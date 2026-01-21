// peel_sender.cpp
// A simple reliable multicast sender over UDP with a TCP-like handshake.
//
// BENCHMARK MODE (Jan 2026 changes)
//   - Start the benchmark timer immediately before sending the first SYN.
//   - Send EXACTLY ONE DATA packet (payload comes from --file or a generated buffer).
//   - Immediately send a STOP signal (we use FIN) after the DATA is reliably ACKed.
//   - Stop the benchmark timer when the FIN has been ACKed by all receivers.
//   - Print the same per-packet debug lines as before, plus a final benchmark summary.
//
// Protocol summary:
// - Multicast group: user-provided (e.g., 239.255.0.1)
// - Port: user-provided (UDP dest port for multicast)
// - Sender binds a local UDP port to receive unicast ACKs from receivers
// - 2-step handshake: Sender multicasts SYN, receivers reply unicast with SYN|ACK
// - Cohort is fixed once expected N receivers have replied
// - Stop-and-wait reliability: each DATA/FIN packet must be ACKed by all receivers before proceeding
// - Header has Internet 16-bit ones'-complement checksum over header only
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o peel_sender_pp peel_sender_pp.cpp
//
// Example (benchmark using a file payload):
//   ./peel_sender \
//     --group 239.255.0.1 --port 5000 \
//     --sender-port 45000 --expected 3 \
//     --file payload.bin --iface 10.169.144.14 --ttl 1 \
//     --rto-ms 250 --retries 20 --chunk 1450
//
// Example (benchmark with generated payload):
//   ./peel_sender \
//     --group 239.255.0.1 --port 5000 \
//     --sender-port 45000 --expected 3 \
//     --payload-bytes 1450 --iface 10.169.144.14 --ttl 1 \
//     --rto-ms 250 --retries 20
//
// Notes:
// - The OS adds IPv4(20) + UDP(8). We add a 22-byte Reliable Multicast header and optional payload.
// - ACKs are unicast back to the sender's bound port.
// - This is a reference implementation intended for lab/LAN conditions.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// ---------------- Protocol header (22 bytes) ----------------
#pragma pack(push, 1)
struct RmHeader {
    uint32_t seq;        // Sequence Number
    uint16_t src_port;   // Sender's UDP port (network order)
    uint16_t flags;      // Bit flags
    uint8_t  retrans_id; // Retransmission attempt id (1..8)
    uint8_t  reserved;   // Must be zero (keeps header length even)
    uint16_t window;     // Window size (for future use)
    uint16_t checksum;   // Internet checksum (header only, checksum field = 0 when computing)
    uint32_t tsval;      // Sender timestamp (ms, monotonic truncated)
    uint32_t tsecr;      // Echoed timestamp from peer (ACKs echo tsval)
};
#pragma pack(pop)
static_assert(sizeof(RmHeader) == 22, "RmHeader must be 22 bytes");

// Flags
enum : uint16_t {
    FLG_SYN   = 0x0001,
    FLG_ACK   = 0x0002,
    FLG_START = 0x0004, // cohort established / start of data
    FLG_DATA  = 0x0008,
    FLG_FIN   = 0x0010,
    FLG_RST   = 0x0020,
};

// Utilities
static uint32_t now_ms() {
    auto now = Clock::now().time_since_epoch();
    return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

static uint16_t checksum16(const void* data, size_t len) {
    // Internet checksum (RFC 1071) over bytes
    uint32_t sum = 0;
    const uint16_t* p = static_cast<const uint16_t*>(data);
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<const uint8_t*>(p);
        sum += last;
    }
    // Fold 32->16
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

static std::string addr_to_string(const sockaddr_in& a) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
    std::ostringstream oss;
    oss << buf << ":" << ntohs(a.sin_port);
    return oss.str();
}

struct PeerKey {
    uint32_t ip;   // network order
    uint16_t port; // network order
    bool operator==(const PeerKey& o) const { return ip == o.ip && port == o.port; }
};

struct PeerKeyHash { size_t operator()(const PeerKey& k) const { return (size_t)k.ip * 1315423911u + k.port; } };

struct Args {
    std::string group = "239.255.0.1"; // multicast group
    uint16_t port = 5000;               // multicast dest port
    uint16_t sender_port = 45000;       // local bind port for ACKs
    int expected = 1;                   // expected receivers
    std::string file;                   // optional payload file
    size_t payload_bytes = 0;           // optional payload size for generated payload (0 => use --chunk)
    std::optional<std::string> iface_ip; // optional egress interface IPv4 (e.g., 192.168.1.50)
    int ttl = 1;                        // multicast TTL
    int rto_ms = 250;                   // retransmission timeout
    int retries = 20;                   // max retries per step
    size_t max_app_payload = 1450;      // default for Ethernet MTU (1472 total - 22 header)
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog << " --group A.B.C.D --port P --sender-port S --expected N [--file path]"
              << " [--payload-bytes BYTES] [--iface X.Y.Z.W] [--ttl T] [--rto-ms MS] [--retries K] [--chunk BYTES]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more){ if (i + more >= argc) { usage(argv[0]); return false; } return true; };
        if (s == "--group" && need(1)) a.group = argv[++i];
        else if (s == "--port" && need(1)) a.port = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--sender-port" && need(1)) a.sender_port = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--expected" && need(1)) a.expected = std::stoi(argv[++i]);
        else if (s == "--file" && need(1)) a.file = argv[++i];
        else if (s == "--payload-bytes" && need(1)) a.payload_bytes = (size_t)std::stoull(argv[++i]);
        else if (s == "--iface" && need(1)) a.iface_ip = argv[++i];
        else if (s == "--ttl" && need(1)) a.ttl = std::stoi(argv[++i]);
        else if (s == "--rto-ms" && need(1)) a.rto_ms = std::stoi(argv[++i]);
        else if (s == "--retries" && need(1)) a.retries = std::stoi(argv[++i]);
        else if (s == "--chunk" && need(1)) a.max_app_payload = (size_t)std::stoul(argv[++i]);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); return false; }
    }
    if (a.expected <= 0) { std::cerr << "--expected must be >= 1\n"; return false; }
    if (a.max_app_payload < 1 || a.max_app_payload > 65507 - sizeof(RmHeader)) {
        std::cerr << "--chunk invalid; must be 1.." << (65507 - sizeof(RmHeader)) << "\n"; return false;
    }
    if (a.payload_bytes > 0 && (a.payload_bytes < 1 || a.payload_bytes > a.max_app_payload)) {
        std::cerr << "--payload-bytes invalid; must be 1..--chunk (" << a.max_app_payload << ")\n";
        return false;
    }
    return true;
}

class PeelSender {
public:
    explicit PeelSender(const Args& args) : A(args) {}
    ~PeelSender() { if (fd >= 0) close(fd); }

    bool init() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return false; }

        // Bind local sender port to receive unicast ACKs
        sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_ANY); local.sin_port = htons(A.sender_port);
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) { perror("bind sender_port"); return false; }

        // Multicast options
        if (A.iface_ip) {
            in_addr ifaceAddr{};
            if (inet_pton(AF_INET, A.iface_ip->c_str(), &ifaceAddr) != 1) {
                std::cerr << "Invalid --iface IP: " << *A.iface_ip << "\n"; return false; }
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaceAddr, sizeof(ifaceAddr)) < 0) {
                perror("setsockopt IP_MULTICAST_IF"); return false; }
        }
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &A.ttl, sizeof(A.ttl)) < 0) {
            perror("setsockopt IP_MULTICAST_TTL"); return false; }
        int loop = 0; // avoid receiving our own multicast on this socket
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
            perror("setsockopt IP_MULTICAST_LOOP"); return false; }

        // Destination group
        memset(&mcast, 0, sizeof(mcast));
        mcast.sin_family = AF_INET; mcast.sin_port = htons(A.port);
        if (inet_pton(AF_INET, A.group.c_str(), &mcast.sin_addr) != 1) {
            std::cerr << "Invalid --group IP" << "\n"; return false; }

        // Socket recv timeout (we'll also layer a manual loop)
        timeval tv{}; tv.tv_sec = A.rto_ms / 1000; tv.tv_usec = (A.rto_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_RCVTIMEO"); return false; }

        std::cerr << "Bound for ACKs on :" << A.sender_port << ", sending to "
                  << A.group << ":" << A.port << ", expected receivers=" << A.expected << "\n";
        return true;
    }

    bool run() {
        // Benchmark timer: starts immediately before the handshake and stops
        // once FIN is ACKed by all receivers.
        std::vector<uint8_t> payload;
        if (!build_payload(payload)) return false;

        auto t0 = Clock::now();
        auto th0 = t0;
        if (!handshake()) return false;
        auto th1 = Clock::now();

        uint32_t seq = 1;
        if (!send_data(seq++, payload)) return false;   // exactly ONE data packet
        auto td1 = Clock::now();

        if (!send_fin(seq++)) return false;             // STOP signal (FIN)
        auto t1 = Clock::now();

        report_benchmark(payload.size(), th0, th1, td1, t1);
        return true;
    }

private:

    struct TxStats {
        uint64_t syn_pkts = 0;
        uint64_t start_pkts = 0;
        uint64_t data_pkts = 0;
        uint64_t fin_pkts = 0;
        uint64_t total_pkts = 0;
        uint64_t total_wire_bytes = 0;   // bytes passed to sendto() (header+payload)
        uint64_t data_payload_bytes = 0; // payload bytes in DATA packets only
    } stats;

    bool build_payload(std::vector<uint8_t>& out) {
        // Payload source priority:
        //   1) --file (read up to --chunk bytes; only the first chunk is used)
        //   2) generated payload with size --payload-bytes (or --chunk if omitted)

        if (!A.file.empty()) {
            std::ifstream f(A.file, std::ios::binary);
            if (!f) {
                std::cerr << "Failed to open file: " << A.file << "\n";
                return false;
            }

            // Determine file size (best-effort). If larger than --chunk, we'll truncate.
            f.seekg(0, std::ios::end);
            std::streamoff sz = f.tellg();
            if (sz < 0) sz = 0;
            f.seekg(0, std::ios::beg);

            size_t want = (size_t)sz;
            if (want == 0) {
                std::cerr << "Payload file is empty: " << A.file << "\n";
                return false;
            }
            if (want > A.max_app_payload) {
                std::cerr << "[bench] NOTE: file is " << want << " bytes, but benchmark sends ONE packet only. "
                          << "Truncating to --chunk=" << A.max_app_payload << " bytes. "
                          << "(Increase --chunk if you truly want a single-packet file)\n";
                want = A.max_app_payload;
            }

            out.resize(want);
            f.read(reinterpret_cast<char*>(out.data()), (std::streamsize)want);
            std::streamsize got = f.gcount();
            if (got <= 0) {
                std::cerr << "Failed to read payload from file: " << A.file << "\n";
                return false;
            }
            out.resize((size_t)got);
            return true;
        }

        size_t n = (A.payload_bytes > 0) ? A.payload_bytes : A.max_app_payload;
        if (n < 1 || n > A.max_app_payload) {
            std::cerr << "Invalid generated payload size " << n << " (must be 1.." << A.max_app_payload << ")\n";
            return false;
        }
        out.resize(n);
        // Deterministic pattern (helps receiver-side validation/debugging)
        for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)('A' + (i % 26));
        return true;
    }

    void report_benchmark(size_t payload_bytes,
                          const Clock::time_point& th0,
                          const Clock::time_point& th1,
                          const Clock::time_point& td1,
                          const Clock::time_point& t1) {

        auto dur_us = [](const Clock::time_point& a, const Clock::time_point& b) -> uint64_t {
            return (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(b - a).count();
        };

        const uint64_t handshake_us = dur_us(th0, th1);
        const uint64_t data_us      = dur_us(th1, td1);
        const uint64_t fin_us       = dur_us(td1, t1);
        const uint64_t total_us     = dur_us(th0, t1);

        const double total_s = (double)total_us / 1e6;
        const double payload_mib = (double)payload_bytes / (1024.0 * 1024.0);
        const double goodput_mibs = (total_s > 0.0) ? (payload_mib / total_s) : 0.0;
        const double goodput_mbps = goodput_mibs * 8.0;

        const double wire_mib = (double)stats.total_wire_bytes / (1024.0 * 1024.0);
        const double wire_mibs = (total_s > 0.0) ? (wire_mib / total_s) : 0.0;
        const double wire_mbps = wire_mibs * 8.0;

        std::cerr << "\n========== BENCHMARK SUMMARY =========="
                  << "\nReceivers (expected/actual): " << A.expected << "/" << cohort.size()
                  << "\nPayload: " << payload_bytes << " bytes (ONE DATA packet)"
                  << "\nTiming: handshake=" << (handshake_us / 1000.0) << " ms"
                  << ", data+ACK=" << (data_us / 1000.0) << " ms"
                  << ", fin+ACK=" << (fin_us / 1000.0) << " ms"
                  << ", TOTAL=" << (total_us / 1000.0) << " ms"
                  << "\nTX packets (including retrans): SYN=" << stats.syn_pkts
                  << ", START=" << stats.start_pkts
                  << ", DATA=" << stats.data_pkts
                  << ", FIN=" << stats.fin_pkts
                  << ", TOTAL=" << stats.total_pkts
                  << "\nTX bytes: wire=" << stats.total_wire_bytes
                  << " bytes, payload(DATA only)=" << stats.data_payload_bytes << " bytes"
                  << "\nGoodput (payload/TOTAL): " << goodput_mibs << " MiB/s (" << goodput_mbps << " Mib/s)"
                  << "\nWire rate (sendto bytes/TOTAL): " << wire_mibs << " MiB/s (" << wire_mbps << " Mib/s)"
                  << "\nRetransmissions: SYN=" << (stats.syn_pkts > 0 ? (stats.syn_pkts - 1) : 0)
                  << ", DATA=" << (stats.data_pkts > 0 ? (stats.data_pkts - 1) : 0)
                  << ", FIN=" << (stats.fin_pkts > 0 ? (stats.fin_pkts - 1) : 0)
                  << "\n======================================\n";
    }

    bool handshake() {
        // High-resolution start time
        auto handshake_start = Clock::now();
        auto elapsed_us = [&]() -> long long {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - handshake_start
            ).count();
        };

        std::unordered_map<PeerKey, sockaddr_in, PeerKeyHash> cohort_map; // by (ip,port) from recvfrom

        constexpr uint8_t kMaxRetransId = 8;
        bool success = false;

        // NOTE: we cap handshake retransmissions by retrans_id (1..8), and we also respect --retries.
        for (int attempt = 0, retrans_id = 1;
             attempt <= A.retries && retrans_id <= kMaxRetransId;
             ++attempt, ++retrans_id) {

            // A retransmission attempt starts a *new* ack-collection epoch.
            // (User requirement: clear current received ACKs when retransmission triggers.)
            if (attempt > 0) cohort_map.clear();

            uint32_t ts = now_ms();
            RmHeader h{}; fill_header(h, /*seq*/0, FLG_SYN, /*wnd*/1, ts, /*tsecr*/0, (uint8_t)retrans_id);
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            serialize_header(h, pkt.data());
            if (!xmit(pkt)) {
                auto us = elapsed_us();
                double ms = us / 1000.0;
                std::cerr << "Handshake failed while sending SYN after "
                          << us << " us (" << ms << " ms)\n";
                return false;
            }

            auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
            while (Clock::now() < deadline) {
                sockaddr_in peer{}; RmHeader rh{};
                if (!recv_header(peer, rh)) break; // timeout or error -> break to trigger retransmit
                if (!verify_header(rh)) continue;
                if ((ntohs(rh.flags) & (FLG_SYN | FLG_ACK)) != (FLG_SYN | FLG_ACK)) continue; // need SYN|ACK
                if (rh.retrans_id != (uint8_t)retrans_id) continue; // ignore stale/early epochs
                if (ntohl(rh.tsecr) != ts) continue; // must echo our ts

                PeerKey k{ peer.sin_addr.s_addr, peer.sin_port };
                if (!cohort_map.count(k)) {
                    cohort_map[k] = peer;
                }
                if ((int)cohort_map.size() >= A.expected) break;
            }

            if ((int)cohort_map.size() >= A.expected) { success = true; break; }
        }

        if (!success || (int)cohort_map.size() < A.expected) {
            auto us = elapsed_us();
            double ms = us / 1000.0;
            std::cerr << "Handshake failed after " << us << " us ("
                      << ms << " ms): got " << cohort_map.size()
                      << "/" << A.expected << " receivers\n";
            return false;
        }

        // Solidify cohort
        cohort.clear(); cohort.reserve(cohort_map.size());
        for (auto& kv : cohort_map) cohort.push_back(kv.second);

        // Inform cohort: START (multicast)
        uint32_t ts = now_ms();
        RmHeader start{}; fill_header(start, /*seq*/0, FLG_START, /*wnd*/1, ts, 0, /*retrans_id*/1);
        std::vector<uint8_t> pkt(sizeof(RmHeader));
        serialize_header(start, pkt.data());
        if (!xmit(pkt)) {
            auto us = elapsed_us();
            double ms = us / 1000.0;
            std::cerr << "Handshake failed while sending START after "
                      << us << " us (" << ms << " ms), cohort size="
                      << cohort.size() << "\n";
            return false;
        }

        auto us = elapsed_us();
        double ms = us / 1000.0;
        std::cerr << "Handshake complete in " << us << " us ("
                  << ms << " ms). Cohort size=" << cohort.size()
                  << ". Sent START.\n";

        return true;
    }

    bool send_data(uint32_t seq, const std::vector<uint8_t>& app) {
        constexpr uint8_t kMaxRetransId = 8;

        // attempt 0 => retrans_id 1, attempt 1 => retrans_id 2, ... up to 8
        for (int attempt = 0, rid = 1;
             attempt <= A.retries && rid <= kMaxRetransId;
             ++attempt, ++rid) {

            uint8_t retrans_id = (uint8_t)rid;

            uint32_t ts = now_ms();
            std::vector<uint8_t> pkt(sizeof(RmHeader) + app.size());
            RmHeader h{}; fill_header(h, seq, FLG_DATA, /*wnd*/1, ts, 0, retrans_id);
            serialize_header(h, pkt.data());
            if (!app.empty()) memcpy(pkt.data() + sizeof(RmHeader), app.data(), app.size());

            if (!xmit(pkt)) return false;

            std::cerr << "DATA seq=" << seq << " len=" << app.size()
                      << " (try " << (attempt+1) << ", retrans_id=" << (int)retrans_id << ")\n";

            // Only count ACKs that match this retrans_id epoch.
            if (wait_all_acks(seq, ts, retrans_id)) return true;

            std::cerr << "  timeout waiting DATA ACKs -> retransmit\n";
        }

        std::cerr << "Failed to deliver DATA seq=" << seq
                  << " after retries/retrans_id limit\n";
        return false;
    }

    bool send_fin(uint32_t seq) {
        constexpr uint8_t kMaxRetransId = 8;

        for (int attempt = 0, rid = 1;
             attempt <= A.retries && rid <= kMaxRetransId;
             ++attempt, ++rid) {

            uint8_t retrans_id = (uint8_t)rid;

            uint32_t ts = now_ms();
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            RmHeader h{}; fill_header(h, seq, FLG_FIN, /*wnd*/0, ts, 0, retrans_id);
            serialize_header(h, pkt.data());

            if (!xmit(pkt)) return false;

            std::cerr << "FIN seq=" << seq
                      << " (try " << (attempt+1) << ", retrans_id=" << (int)retrans_id << ")\n";

            if (wait_all_acks(seq, ts, retrans_id)) {
                std::cerr << "All receivers ACKed FIN. Done.\n";
                return true;
            }

            std::cerr << "  timeout waiting FIN ACKs -> retransmit\n";
        }

        std::cerr << "Failed to deliver FIN after retries/retrans_id limit\n";
        return false;
    }

    bool wait_all_acks(uint32_t seq, uint32_t ts_sent, uint8_t retrans_id_expected) {
        std::unordered_set<uint64_t> got; got.reserve(cohort.size() * 2);
        auto pack_key = [](const sockaddr_in& a){
            return (uint64_t)a.sin_addr.s_addr << 16 | ntohs(a.sin_port);
        };

        auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
        while (Clock::now() < deadline) {
            sockaddr_in peer{}; RmHeader rh{};
            if (!recv_header(peer, rh)) break; // timeout -> break to trigger retransmit by caller
            if (!verify_header(rh)) continue;
            if ((ntohs(rh.flags) & FLG_ACK) == 0) continue;

            // Require ack.seq == our seq and rh.tsecr == ts_sent
            if (ntohl(rh.seq) != seq) continue;
            if (ntohl(rh.tsecr) != ts_sent) continue;

            // Only accept ACKs for the current retransmission epoch.
            if (rh.retrans_id != retrans_id_expected) continue;

            // Check that peer is part of cohort
            bool member = false;
            for (auto& c : cohort) {
                if (c.sin_addr.s_addr == peer.sin_addr.s_addr && c.sin_port == peer.sin_port) {
                    member = true; break;
                }
            }
            if (!member) continue; // ignore unknown

            got.insert(pack_key(peer));
            if (got.size() >= cohort.size()) return true;
        }
        return false;
    }

    bool xmit(const std::vector<uint8_t>& bytes) {
        // Update stats (best-effort parse of header flags).
        if (bytes.size() >= sizeof(RmHeader)) {
            RmHeader h{};
            memcpy(&h, bytes.data(), sizeof(h));
            const uint16_t flags = ntohs(h.flags);
            stats.total_pkts++;
            stats.total_wire_bytes += bytes.size();
            if (flags & FLG_SYN) {
                stats.syn_pkts++;
            } else if (flags & FLG_START) {
                stats.start_pkts++;
            } else if (flags & FLG_DATA) {
                stats.data_pkts++;
                if (bytes.size() > sizeof(RmHeader)) {
                    stats.data_payload_bytes += (bytes.size() - sizeof(RmHeader));
                }
            } else if (flags & FLG_FIN) {
                stats.fin_pkts++;
            }
        }

        ssize_t n = sendto(fd, bytes.data(), bytes.size(), 0, (sockaddr*)&mcast, sizeof(mcast));
        if (n < 0) { perror("sendto"); return false; }
        if ((size_t)n != bytes.size()) {
            std::cerr << "Partial send!? sent=" << n << " expected=" << bytes.size() << "\n"; return false;
        }
        return true;
    }

    bool recv_header(sockaddr_in& from, RmHeader& out) {
        uint8_t buf[sizeof(RmHeader) + 16]; // header only expected; allow tiny extra
        socklen_t alen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&from, &alen);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) return false; // timeout
            perror("recvfrom"); return false;
        }
        if ((size_t)n < sizeof(RmHeader)) return false;
        deserialize_header(buf, out);
        return true;
    }

    void fill_header(RmHeader& h, uint32_t seq, uint16_t flags, uint16_t wnd, uint32_t ts, uint32_t tsecr,
                     uint8_t retrans_id = 1) {
        h.seq = htonl(seq);
        h.src_port = htons(A.sender_port);
        h.flags = htons(flags);
        h.retrans_id = retrans_id;
        h.reserved = 0;
        h.window = htons(wnd);
        h.checksum = 0;
        h.tsval = htonl(ts);
        h.tsecr = htonl(tsecr);
    }

    void serialize_header(RmHeader& h, uint8_t* out) {
        // compute checksum over header with checksum=0
        RmHeader tmp = h;
        tmp.checksum = 0;
        uint16_t sum = checksum16(&tmp, sizeof(tmp));
        h.checksum = sum;
        memcpy(out, &h, sizeof(h));
    }

    void deserialize_header(const uint8_t* in, RmHeader& h) {
        memcpy(&h, in, sizeof(h));
    }

    bool verify_header(const RmHeader& net) {
        // recompute checksum and compare
        RmHeader tmp = net; uint16_t rcv = tmp.checksum; tmp.checksum = 0; uint16_t calc = checksum16(&tmp, sizeof(tmp));
        if (rcv != calc) return false;
        return true;
    }

private:
    Args A;
    int fd = -1;
    sockaddr_in mcast{};
    std::vector<sockaddr_in> cohort; // fixed after handshake
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    PeelSender s(args);
    if (!s.init()) return 2;
    if (!s.run()) return 3;
    return 0;
}
