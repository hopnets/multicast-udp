// peel_sender.cpp
// A simple reliable multicast sender over UDP with a TCP-like handshake.
// - Multicast group: user-provided (e.g., 239.255.0.1)
// - Port: user-provided (UDP dest port for multicast)
// - Sender binds a local UDP port to receive unicast ACKs from receivers
// - TCP-like 2-step handshake: Sender multicasts SYN, receivers reply unicast with SYN|ACK
// - Cohort is fixed once expected N receivers have replied
// - Stop-and-wait reliability: each DATA packet must be ACKed by all receivers before proceeding
// - Header per spec (22 bytes) with Internet 16-bit ones'-complement checksum over header only
//
// Build: g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o peel_sender peel_sender.cpp
//
// NOTE (benchmarking):
// - All reliability logic is unchanged.
// - Prints during DATA transmit / ACK parsing are removed to avoid timing distortion.
// - We time three stages:
//    (a) handshake/setup
//    (b) data transfer (all DATA seqs)
//    (c) fin (FIN send + ACK wait)
// - We also report average transfer time per DATA packet = data_transfer_us / data_packets.

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

[[maybe_unused]] static std::string addr_to_string(const sockaddr_in& a) {
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

struct PeerKeyHash {
    size_t operator()(const PeerKey& k) const { return (size_t)k.ip * 1315423911u + k.port; }
};

struct Args {
    std::string group = "239.255.0.1"; // multicast group
    uint16_t port = 5000;               // multicast dest port
    uint16_t sender_port = 45000;       // local bind port for ACKs
    int expected = 1;                   // expected receivers
    std::string file;                   // optional payload file
    std::optional<std::string> iface_ip; // optional egress interface IPv4 (e.g., 192.168.1.50)
    int ttl = 1;                        // multicast TTL
    int rto_ms = 250;                   // retransmission timeout
    int retries = 20;                   // max retries per step
    size_t max_app_payload = 1450;      // default for Ethernet MTU (1472 total - 22 header)
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog << " --group A.B.C.D --port P --sender-port S --expected N [--file path]"
              << " [--iface X.Y.Z.W] [--ttl T] [--rto-ms MS] [--retries K] [--chunk BYTES]\n";
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
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(A.sender_port);
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) { perror("bind sender_port"); return false; }

        // Multicast options
        if (A.iface_ip) {
            in_addr ifaceAddr{};
            if (inet_pton(AF_INET, A.iface_ip->c_str(), &ifaceAddr) != 1) {
                std::cerr << "Invalid --iface IP: " << *A.iface_ip << "\n";
                return false;
            }
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaceAddr, sizeof(ifaceAddr)) < 0) {
                perror("setsockopt IP_MULTICAST_IF");
                return false;
            }
        }
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &A.ttl, sizeof(A.ttl)) < 0) {
            perror("setsockopt IP_MULTICAST_TTL");
            return false;
        }
        int loop = 0; // avoid receiving our own multicast on this socket
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
            perror("setsockopt IP_MULTICAST_LOOP");
            return false;
        }

        // Destination group
        memset(&mcast, 0, sizeof(mcast));
        mcast.sin_family = AF_INET;
        mcast.sin_port = htons(A.port);
        if (inet_pton(AF_INET, A.group.c_str(), &mcast.sin_addr) != 1) {
            std::cerr << "Invalid --group IP\n";
            return false;
        }

        // Socket recv timeout
        timeval tv{};
        tv.tv_sec = A.rto_ms / 1000;
        tv.tv_usec = (A.rto_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_RCVTIMEO");
            return false;
        }

        std::cerr << "Bound for ACKs on :" << A.sender_port
                  << ", sending to " << A.group << ":" << A.port
                  << ", expected receivers=" << A.expected << "\n";
        return true;
    }

    bool run() {
        // Stage A: Handshake / setup
        auto t_hand0 = Clock::now();
        if (!handshake()) return false;
        auto t_hand1 = Clock::now();
        stats.handshake_us = us_since(t_hand0, t_hand1);

        // Stage B: DATA transfer (all DATA seqs)
        uint32_t next_seq = 1;
        auto t_xfer0 = Clock::now();
        if (!A.file.empty()) {
            if (!send_file_data_only(A.file, next_seq)) return false;
        } else {
            // Demo mode: send 5 small DATA packets and then FIN
            std::vector<std::string> msgs;
            for (int i = 1; i <= 5; ++i) msgs.push_back("hello-" + std::to_string(i));
            for (auto& s : msgs) {
                if (!send_data(next_seq++, std::vector<uint8_t>(s.begin(), s.end()))) return false;
            }
        }
        auto t_xfer1 = Clock::now();
        stats.data_xfer_us = us_since(t_xfer0, t_xfer1);

        // Stage C: FIN
        auto t_fin0 = Clock::now();
        if (!send_fin(next_seq)) return false;
        auto t_fin1 = Clock::now();
        stats.fin_us = us_since(t_fin0, t_fin1);

        print_benchmark_summary();
        return true;
    }

private:
    struct BenchStats {
        long long handshake_us = 0;
        long long data_xfer_us = 0;
        long long fin_us = 0;

        uint64_t data_packets = 0;      // number of successful DATA seqs
        uint64_t data_app_bytes = 0;    // sum(app payload sizes) for DATA seqs
        uint64_t data_tx_bytes = 0;     // bytes actually transmitted for DATA (includes header + retrans)
        uint64_t fin_tx_bytes = 0;      // bytes actually transmitted for FIN (includes header + retrans)

        uint32_t fin_seq = 0;
    };

    static long long us_since(const Clock::time_point& a, const Clock::time_point& b) {
        return std::chrono::duration_cast<std::chrono::microseconds>(b - a).count();
    }

    void print_benchmark_summary() const {
        auto to_ms = [](long long us){ return us / 1000.0; };

        std::cout << "\n=== PeelSender Benchmark Summary ===\n";
        std::cout << "  cohort size: " << cohort.size() << "\n";
        std::cout << "  handshake/setup: " << stats.handshake_us << " us (" << to_ms(stats.handshake_us) << " ms)\n";
        std::cout << "  data transfer:   " << stats.data_xfer_us << " us (" << to_ms(stats.data_xfer_us) << " ms)\n";
        std::cout << "    data packets:  " << stats.data_packets << "\n";
        std::cout << "    app bytes:     " << stats.data_app_bytes << "\n";
        std::cout << "    tx bytes:      " << stats.data_tx_bytes << " (incl. header + retrans)\n";

        double avg_us_per_pkt = 0.0;
        if (stats.data_packets > 0 && stats.data_xfer_us > 0) {
            avg_us_per_pkt = (double)stats.data_xfer_us / (double)stats.data_packets;
        }
        std::cout << "    avg per DATA packet: " << avg_us_per_pkt << " us\n";

        double gbps_app = 0.0;
        if (stats.data_xfer_us > 0 && stats.data_app_bytes > 0) {
            // Gbps = bytes*8 / (us*1000)
            gbps_app = (stats.data_app_bytes * 8.0) / (stats.data_xfer_us * 1000.0);
        }
        double gbps_tx = 0.0;
        if (stats.data_xfer_us > 0 && stats.data_tx_bytes > 0) {
            gbps_tx = (stats.data_tx_bytes * 8.0) / (stats.data_xfer_us * 1000.0);
        }
        std::cout << "    xfer_bw (app): " << gbps_app << " Gbps\n";
        std::cout << "    xfer_bw (tx):  " << gbps_tx  << " Gbps\n";

        std::cout << "  fin:             " << stats.fin_us << " us (" << to_ms(stats.fin_us) << " ms)\n";
        std::cout << "    fin seq:       " << stats.fin_seq << "\n";
        std::cout << "    fin tx bytes:  " << stats.fin_tx_bytes << " (incl. header + retrans)\n";
        std::cout << "===================================\n";
    }

    bool handshake() {
        // High-resolution start time (kept as original behavior)
        auto handshake_start = Clock::now();
        auto elapsed_us = [&]() -> long long {
            return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - handshake_start).count();
        };

        std::unordered_map<PeerKey, sockaddr_in, PeerKeyHash> cohort_map; // by (ip,port) from recvfrom

        constexpr uint8_t kMaxRetransId = 8;
        bool success = false;

        // NOTE: we cap handshake retransmissions by retrans_id (1..8), and we also respect --retries.
        for (int attempt = 0, retrans_id = 1;
             attempt <= A.retries && retrans_id <= kMaxRetransId;
             ++attempt, ++retrans_id) {

            // A retransmission attempt starts a new ack-collection epoch.
            if (attempt > 0) cohort_map.clear();

            uint32_t ts = now_ms();
            RmHeader h{};
            fill_header(h, /*seq*/0, FLG_SYN, /*wnd*/1, ts, /*tsecr*/0, (uint8_t)retrans_id);
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            serialize_header(h, pkt.data());
            if (!xmit(pkt)) {
                auto us = elapsed_us();
                std::cerr << "Handshake failed while sending SYN after " << us << " us (" << (us/1000.0) << " ms)\n";
                return false;
            }

            auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
            while (Clock::now() < deadline) {
                sockaddr_in peer{};
                RmHeader rh{};
                if (!recv_header(peer, rh)) break; // timeout or error -> retransmit
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
            std::cerr << "Handshake failed after " << us << " us (" << (us/1000.0) << " ms): got "
                      << cohort_map.size() << "/" << A.expected << " receivers\n";
            return false;
        }

        // Solidify cohort
        cohort.clear();
        cohort.reserve(cohort_map.size());
        for (auto& kv : cohort_map) cohort.push_back(kv.second);

        // Inform cohort: START (multicast)
        uint32_t ts = now_ms();
        RmHeader start{};
        fill_header(start, /*seq*/0, FLG_START, /*wnd*/1, ts, 0, /*retrans_id*/1);
        std::vector<uint8_t> pkt(sizeof(RmHeader));
        serialize_header(start, pkt.data());
        if (!xmit(pkt)) {
            auto us = elapsed_us();
            std::cerr << "Handshake failed while sending START after " << us << " us (" << (us/1000.0)
                      << " ms), cohort size=" << cohort.size() << "\n";
            return false;
        }

        auto us = elapsed_us();
        std::cerr << "Handshake complete in " << us << " us (" << (us/1000.0) << " ms). Cohort size="
                  << cohort.size() << ". Sent START.\n";

        return true;
    }

    // Send only DATA chunks from file; does NOT send FIN.
    // next_seq is incremented as DATA is sent.
    bool send_file_data_only(const std::string& path, uint32_t& next_seq) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Failed to open file: " << path << "\n"; return false; }

        std::vector<uint8_t> buf(A.max_app_payload);
        while (true) {
            f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
            std::streamsize got = f.gcount();
            if (got <= 0) break;
            std::vector<uint8_t> chunk(buf.begin(), buf.begin() + got);
            if (!send_data(next_seq++, chunk)) return false;
        }
        return true;
    }

    bool send_data(uint32_t seq, const std::vector<uint8_t>& app) {
        constexpr uint8_t kMaxRetransId = 8;

        for (int attempt = 0, rid = 1;
             attempt <= A.retries && rid <= kMaxRetransId;
             ++attempt, ++rid) {

            uint8_t retrans_id = (uint8_t)rid;

            uint32_t ts = now_ms();
            std::vector<uint8_t> pkt(sizeof(RmHeader) + app.size());
            RmHeader h{};
            fill_header(h, seq, FLG_DATA, /*wnd*/1, ts, 0, retrans_id);
            serialize_header(h, pkt.data());
            if (!app.empty()) memcpy(pkt.data() + sizeof(RmHeader), app.data(), app.size());

            if (!xmit(pkt)) return false;
            stats.data_tx_bytes += pkt.size();

            // Only count ACKs that match this retrans_id epoch.
            if (wait_all_acks(seq, ts, retrans_id)) {
                stats.data_packets += 1;
                stats.data_app_bytes += app.size();
                return true;
            }
        }

        std::cerr << "Failed to deliver DATA seq=" << seq << " after retries/retrans_id limit\n";
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
            RmHeader h{};
            fill_header(h, seq, FLG_FIN, /*wnd*/0, ts, 0, retrans_id);
            serialize_header(h, pkt.data());

            if (!xmit(pkt)) return false;
            stats.fin_tx_bytes += pkt.size();

            if (wait_all_acks(seq, ts, retrans_id)) {
                stats.fin_seq = seq;
                std::cerr << "All receivers ACKed FIN. Done.\n";
                return true;
            }
        }

        std::cerr << "Failed to deliver FIN after retries/retrans_id limit\n";
        return false;
    }

    bool wait_all_acks(uint32_t seq, uint32_t ts_sent, uint8_t retrans_id_expected) {
        std::unordered_set<uint64_t> got;
        got.reserve(cohort.size() * 2);
        auto pack_key = [](const sockaddr_in& a){
            return (uint64_t)a.sin_addr.s_addr << 16 | ntohs(a.sin_port);
        };

        auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
        while (Clock::now() < deadline) {
            sockaddr_in peer{};
            RmHeader rh{};
            if (!recv_header(peer, rh)) break; // timeout -> trigger retransmit by caller
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
                    member = true;
                    break;
                }
            }
            if (!member) continue; // ignore unknown

            got.insert(pack_key(peer));
            if (got.size() >= cohort.size()) return true;
        }
        return false;
    }

    bool xmit(const std::vector<uint8_t>& bytes) {
        ssize_t n = sendto(fd, bytes.data(), bytes.size(), 0, (sockaddr*)&mcast, sizeof(mcast));
        if (n < 0) { perror("sendto"); return false; }
        if ((size_t)n != bytes.size()) {
            std::cerr << "Partial send!? sent=" << n << " expected=" << bytes.size() << "\n";
            return false;
        }
        return true;
    }

    bool recv_header(sockaddr_in& from, RmHeader& out) {
        uint8_t buf[sizeof(RmHeader) + 16]; // header only expected; allow tiny extra
        socklen_t alen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&from, &alen);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) return false; // timeout
            perror("recvfrom");
            return false;
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
        RmHeader tmp = net;
        uint16_t rcv = tmp.checksum;
        tmp.checksum = 0;
        uint16_t calc = checksum16(&tmp, sizeof(tmp));
        return (rcv == calc);
    }

private:
    Args A;
    int fd = -1;
    sockaddr_in mcast{};
    std::vector<sockaddr_in> cohort; // fixed after handshake
    BenchStats stats;
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;

    PeelSender s(args);
    if (!s.init()) return 2;
    if (!s.run()) return 3;
    return 0;
}
