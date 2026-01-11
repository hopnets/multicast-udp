// peel_sender_handshake_bench.cpp
// Benchmark-only version of the original sender:
// - Keeps the UDP + TCP-like handshake logic exactly as-is
// - Removes all data/file transmission logic
// - Runs 10 handshakes, sleeps 500ms between runs, prints average duration
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o peel_sender_handshake peel_sender_handshake.cpp
//
// Example:
//   ./peel_sender_handshake_bench \
//     --group 239.255.0.1 --port 5000 \
//     --sender-port 45000 --expected 3 \
//     --iface 10.169.144.14 --ttl 1 \
//     --rto-ms 250 --retries 20

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// ---------------- Protocol header (20 bytes) ----------------
#pragma pack(push, 1)
struct RmHeader {
    uint32_t seq;        // Sequence Number
    uint16_t src_port;   // Sender's UDP port (network order)
    uint16_t flags;      // Bit flags
    uint16_t window;     // Window size (for future use)
    uint16_t checksum;   // Internet checksum (header only, checksum field = 0 when computing)
    uint32_t tsval;      // Sender timestamp (ms, monotonic truncated)
    uint32_t tsecr;      // Echoed timestamp from peer (ACKs echo tsval)
};
#pragma pack(pop)
static_assert(sizeof(RmHeader) == 20, "RmHeader must be 20 bytes");

// Flags
enum : uint16_t {
    FLG_SYN   = 0x0001,
    FLG_ACK   = 0x0002,
    FLG_START = 0x0004, // cohort established / start (handshake complete)
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

struct PeerKeyHash {
    size_t operator()(const PeerKey& k) const {
        return (size_t)k.ip * 1315423911u + k.port;
    }
};

struct Args {
    std::string group = "239.255.0.1";  // multicast group
    uint16_t port = 5000;               // multicast dest port
    uint16_t sender_port = 45000;       // local bind port for replies
    int expected = 1;                   // expected receivers
    std::optional<std::string> iface_ip; // optional egress interface IPv4 (e.g., 192.168.1.50)
    int ttl = 1;                        // multicast TTL
    int rto_ms = 250;                   // receive timeout / retransmission timeout for handshake steps
    int retries = 20;                   // max retries per handshake step
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --group A.B.C.D --port P --sender-port S --expected N"
              << " [--iface X.Y.Z.W] [--ttl T] [--rto-ms MS] [--retries K]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more){ if (i + more >= argc) { usage(argv[0]); return false; } return true; };
        if (s == "--group" && need(1)) a.group = argv[++i];
        else if (s == "--port" && need(1)) a.port = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--sender-port" && need(1)) a.sender_port = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--expected" && need(1)) a.expected = std::stoi(argv[++i]);
        else if (s == "--iface" && need(1)) a.iface_ip = argv[++i];
        else if (s == "--ttl" && need(1)) a.ttl = std::stoi(argv[++i]);
        else if (s == "--rto-ms" && need(1)) a.rto_ms = std::stoi(argv[++i]);
        else if (s == "--retries" && need(1)) a.retries = std::stoi(argv[++i]);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); return false; }
    }
    if (a.expected <= 0) { std::cerr << "--expected must be >= 1\n"; return false; }
    return true;
}

class PeelSender {
public:
    explicit PeelSender(const Args& args) : A(args) {}
    ~PeelSender() { if (fd >= 0) close(fd); }

    bool init() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return false; }

        // Bind local sender port to receive unicast replies
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

        // Socket recv timeout
        timeval tv{}; tv.tv_sec = A.rto_ms / 1000; tv.tv_usec = (A.rto_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_RCVTIMEO"); return false; }

        std::cerr << "Bound for replies on :" << A.sender_port << ", sending to "
                  << A.group << ":" << A.port << ", expected receivers=" << A.expected << "\n";
        return true;
    }

    bool benchmark_handshake(int runs = 100, std::chrono::milliseconds gap = 500ms) {
        std::vector<long long> durations_us;
        durations_us.reserve(runs);

        for (int i = 0; i < runs; ++i) {
            auto t0 = Clock::now();
            if (!handshake()) {
                std::cerr << "Handshake failed on run " << (i + 1) << "/" << runs << "\n";
                return false;
            }
            auto t1 = Clock::now();

            auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            durations_us.push_back(us);

            // Give the remote receiver time to reset/start properly between runs
            std::this_thread::sleep_for(gap);
        }

        long long sum_us = 0;
        for (auto v : durations_us) sum_us += v;

        double avg_us = runs ? (double)sum_us / (double)runs : 0.0;
        double avg_ms = avg_us / 1000.0;

        std::cout << "\n=== Handshake benchmark results ===\n";
        for (int i = 0; i < (int)durations_us.size(); ++i) {
            double ms = durations_us[i] / 1000.0;
            std::cout << "Run " << (i + 1) << ": " << durations_us[i] << " us (" << ms << " ms)\n";
        }
        std::cout << "Average (" << runs << " runs): " << avg_us << " us (" << avg_ms << " ms)\n";
        std::cout << "===================================\n\n";

        return true;
    }

private:
    bool handshake() {
        // High-resolution start time
        auto handshake_start = Clock::now();
        auto elapsed_us = [&]() -> long long {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - handshake_start
            ).count();
        };

        std::unordered_map<PeerKey, sockaddr_in, PeerKeyHash> cohort_map; // by (ip,port) from recvfrom
        int retries = 0;
        while (retries <= A.retries) {
            uint32_t ts = now_ms();
            RmHeader h{}; fill_header(h, /*seq*/0, FLG_SYN, /*wnd*/1, ts, /*tsecr*/0);
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            serialize_header(h, pkt.data());
            if (!xmit(pkt)) {
                auto us = elapsed_us();
                double ms = us / 1000.0;
                std::cerr << "Handshake failed while sending SYN after "
                          << us << " us (" << ms << " ms)\n";
                return false;
            }

            // Verbose logging disabled for timing
            // std::cerr << "SYN -> group (try " << (retries+1)
            //           << "/" << (A.retries+1) << ")\n";

            auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
            while (Clock::now() < deadline) {
                sockaddr_in peer{}; RmHeader rh{};
                if (!recv_header(peer, rh)) break; // timeout or error -> break to maybe retransmit
                if (!verify_header(rh)) continue;
                if ((ntohs(rh.flags) & (FLG_SYN|FLG_ACK)) != (FLG_SYN|FLG_ACK)) continue; // need SYN|ACK
                if (ntohl(rh.tsecr) != ts) continue; // must echo our ts
                PeerKey k{ peer.sin_addr.s_addr, peer.sin_port };
                if (!cohort_map.count(k)) {
                    cohort_map[k] = peer;
                    // std::cerr << "  SYN|ACK from " << addr_to_string(peer)
                    //           << " (" << cohort_map.size() << "/" << A.expected << ")\n";
                }
                if ((int)cohort_map.size() >= A.expected) break;
            }
            if ((int)cohort_map.size() >= A.expected) break; // success
            ++retries;
        }

        if ((int)cohort_map.size() < A.expected) {
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
        RmHeader start{}; fill_header(start, /*seq*/0, FLG_START, /*wnd*/1, ts, 0);
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

    bool xmit(const std::vector<uint8_t>& bytes) {
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

    void fill_header(RmHeader& h, uint32_t seq, uint16_t flags, uint16_t wnd, uint32_t ts, uint32_t tsecr) {
        h.seq = htonl(seq);
        h.src_port = htons(A.sender_port);
        h.flags = htons(flags);
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
    std::vector<sockaddr_in> cohort; // fixed after each handshake
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;

    PeelSender s(args);
    if (!s.init()) return 2;

    // Run 10 handshakes with 500ms gap, print per-run durations + average
    if (!s.benchmark_handshake(100, 500ms)) return 3;

    return 0;
}
