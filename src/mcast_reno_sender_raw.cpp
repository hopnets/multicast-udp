// mcast_reno_sender_raw.cpp
// Multicast reliable sender — sliding-window TCP Reno, AF_PACKET/SOCK_RAW version.
//
// What changed from mcast_reno_sender_udp.cpp (the SOCK_DGRAM version):
//   - AF_PACKET/SOCK_RAW replaces AF_INET/SOCK_DGRAM.  Full Ethernet+IP+UDP
//     frames are built manually via build_udp_frame(), giving byte-level control
//     over every header field including the Ethernet dst MAC.
//   - --iface now takes an interface NAME (e.g. "eth0"), not an IP address.
//     Source IP is auto-derived via ioctl(SIOCGIFADDR).
//   - dst_mac is a public field; callers can call set_custom_dst_mac() between
//     init() and run() to embed custom routing labels in the Ethernet dst MAC.
//   - A kernel BPF filter is attached so only unicast ACKs addressed to our
//     IP:sender_port reach userspace; all other frames are dropped in-kernel.
//   - Requires CAP_NET_RAW (run as root or set capability).
//
// Everything above the socket layer is IDENTICAL to the UDP version:
//   RmHeader, flags, AckSlot, AckWindow, RenoSM, AckAggState, RTT estimator,
//   handshake logic, ack_aggregator_loop, transfer loop, send/retransmit_segment.
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -pedantic -pthread \
//       -o mcast_reno_sender_raw mcast_reno_sender_raw.cpp
//
// Example:
//   sudo ./mcast_reno_sender_raw \
//     --group 239.255.0.1 --port 5000 \
//     --sender-port 45000 --expected 2 \
//     --iface eth0 --ttl 1 --file payload.bin \
//     --rto-ms 250 --retries 20 --dupack-pct 50 --tagg-ms 100

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// ── Wire-format headers (packed, no padding) ──────────────────────────────
#pragma pack(push, 1)

struct EthHdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t etype; // 0x0800 = IPv4 (network order)
};

struct Ip4Hdr {
    uint8_t  ver_ihl;  // 0x45 = version 4, IHL 5 (no options)
    uint8_t  tos;
    uint16_t tot_len;  // network order
    uint16_t id;       // network order
    uint16_t frag_off; // 0x4000 = DF, network order
    uint8_t  ttl;
    uint8_t  proto;    // 17 = UDP
    uint16_t cksum;    // network order
    uint32_t saddr;    // network order
    uint32_t daddr;    // network order
};

struct UdpHdr {
    uint16_t sport; // network order
    uint16_t dport; // network order
    uint16_t len;   // network order
    uint16_t cksum; // 0 = not computed (optional for IPv4)
};

// Reliable Multicast application header — 22 bytes, unchanged from UDP version.
struct RmHeader {
    uint32_t seq;        // sequence number (network order)
    uint16_t src_port;   // sender's listening port (network order)
    uint16_t flags;      // protocol flags (network order)
    uint8_t  retrans_id; // retransmission epoch id (1..8)
    uint8_t  reserved;   // must be zero
    uint16_t window;     // window size hint (network order)
    uint16_t checksum;   // internet checksum over RmHeader only (network order)
    uint32_t tsval;      // sender timestamp ms (network order)
    uint32_t tsecr;      // echoed timestamp (network order)
};

#pragma pack(pop)

static_assert(sizeof(EthHdr)   == 14, "EthHdr must be 14 bytes");
static_assert(sizeof(Ip4Hdr)   == 20, "Ip4Hdr must be 20 bytes");
static_assert(sizeof(UdpHdr)   ==  8, "UdpHdr must be 8 bytes");
static_assert(sizeof(RmHeader) == 22, "RmHeader must be 22 bytes");

// ── Protocol flags ────────────────────────────────────────────────────────
enum : uint16_t {
    FLG_SYN   = 0x0001,
    FLG_ACK   = 0x0002,
    FLG_START = 0x0004,
    FLG_DATA  = 0x0008,
    FLG_FIN   = 0x0010,
    FLG_RST   = 0x0020,
};

// ── Utilities ─────────────────────────────────────────────────────────────

static uint32_t now_ms() {
    auto now = Clock::now().time_since_epoch();
    return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

static uint16_t checksum16(const void* data, size_t len) {
    uint32_t sum = 0;
    const uint16_t* p = static_cast<const uint16_t*>(data);
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) {
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<const uint8_t*>(p);
        sum += last;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

// Derive the standard Ethernet multicast MAC from an IPv4 multicast address
// (RFC 1112): 01:00:5E followed by the low 23 bits of the IP address.
static void mcast_ip_to_mac(uint32_t mcast_ip_n, uint8_t mac[6]) {
    uint32_t ip = ntohl(mcast_ip_n);
    mac[0] = 0x01; mac[1] = 0x00; mac[2] = 0x5E;
    mac[3] = (ip >> 16) & 0x7F; // bit 23 masked off (reserved)
    mac[4] = (ip >>  8) & 0xFF;
    mac[5] = (ip >>  0) & 0xFF;
}

// Hook for custom Ethernet-layer routing: pack 6 arbitrary bytes into dst MAC.
// Call between init() and run().  To restore standard multicast MAC:
//   mcast_ip_to_mac(mcast_ip_n, sender.dst_mac);
[[maybe_unused]]
static void set_custom_dst_mac(uint8_t dst_mac[6], const uint8_t values[6]) {
    memcpy(dst_mac, values, 6);
}

static bool get_iface_index(const std::string& iface, int& idx) {
    idx = (int)if_nametoindex(iface.c_str());
    if (idx == 0) { perror(("if_nametoindex(" + iface + ")").c_str()); return false; }
    return true;
}

static bool get_iface_mac(const std::string& iface, uint8_t mac[6]) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket(get_iface_mac)"); return false; }
    ifreq ifr{};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror(("SIOCGIFHWADDR " + iface).c_str()); close(s); return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(s);
    return true;
}

static bool get_iface_ip(const std::string& iface, uint32_t& ip_n) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket(get_iface_ip)"); return false; }
    ifreq ifr{};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        perror(("SIOCGIFADDR " + iface).c_str()); close(s); return false;
    }
    ip_n = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr;
    close(s);
    return true;
}

static std::string ip_to_str(uint32_t ip_n) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_n, buf, sizeof(buf));
    return buf;
}

// Build a complete Ethernet frame: EthHdr(14)+Ip4Hdr(20)+UdpHdr(8)+payload.
// src_ip_n / dst_ip_n are in network order; ports are in host order.
static size_t build_udp_frame(
    uint8_t*       frame,
    size_t         cap,
    const uint8_t  src_mac[6],
    const uint8_t  dst_mac[6],
    uint32_t       src_ip_n,
    uint32_t       dst_ip_n,
    uint16_t       src_port_h,
    uint16_t       dst_port_h,
    uint8_t        ttl,
    uint16_t       ip_id,
    const uint8_t* payload,
    size_t         payload_len)
{
    const size_t udp_len   = 8 + payload_len;
    const size_t ip_len    = 20 + udp_len;
    const size_t frame_len = 14 + ip_len;
    if (frame_len > cap) return 0;

    auto* eth = reinterpret_cast<EthHdr*>(frame);
    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, src_mac, 6);
    eth->etype = htons(0x0800);

    auto* ip = reinterpret_cast<Ip4Hdr*>(frame + 14);
    ip->ver_ihl  = 0x45;
    ip->tos      = 0;
    ip->tot_len  = htons((uint16_t)ip_len);
    ip->id       = htons(ip_id);
    ip->frag_off = htons(0x4000); // DF
    ip->ttl      = ttl;
    ip->proto    = 17;
    ip->cksum    = 0;
    ip->saddr    = src_ip_n;
    ip->daddr    = dst_ip_n;
    ip->cksum    = checksum16(ip, 20);

    auto* udp = reinterpret_cast<UdpHdr*>(frame + 14 + 20);
    udp->sport = htons(src_port_h);
    udp->dport = htons(dst_port_h);
    udp->len   = htons((uint16_t)udp_len);
    udp->cksum = 0; // optional for IPv4

    if (payload_len > 0)
        memcpy(frame + 14 + 20 + 8, payload, payload_len);

    return frame_len;
}

// Parse a raw Ethernet frame. Accepts EtherType=IPv4, proto=UDP only.
// filter_dst_ip_n=0 → skip IP dst check.  filter_dst_port_h=0 → skip port check.
// Fills: src_ip_n (net order), src_port_h (host order), src_mac (6B), payload_len.
// Returns pointer to UDP payload, or nullptr on mismatch / parse error.
static const uint8_t* parse_udp_frame(
    const uint8_t* frame,
    ssize_t        n,
    uint32_t       filter_dst_ip_n,
    uint16_t       filter_dst_port_h,
    uint32_t&      src_ip_n,
    uint16_t&      src_port_h,
    uint8_t        src_mac[6],
    size_t&        payload_len)
{
    if (n < (ssize_t)(14 + 20 + 8)) return nullptr;

    const auto* eth = reinterpret_cast<const EthHdr*>(frame);
    if (ntohs(eth->etype) != 0x0800) return nullptr;

    const auto* ip = reinterpret_cast<const Ip4Hdr*>(frame + 14);
    if ((ip->ver_ihl >> 4) != 4) return nullptr;
    int ihl = (ip->ver_ihl & 0x0F) << 2;
    if (ihl < 20) return nullptr;
    if (ip->proto != 17) return nullptr;
    if (filter_dst_ip_n && ip->daddr != filter_dst_ip_n) return nullptr;

    uint16_t ip_tot = ntohs(ip->tot_len);
    if ((ssize_t)(14 + ip_tot) > n) return nullptr;
    if ((ssize_t)(14 + ihl + 8) > n) return nullptr;

    const auto* udp = reinterpret_cast<const UdpHdr*>(frame + 14 + ihl);
    if (filter_dst_port_h && ntohs(udp->dport) != filter_dst_port_h) return nullptr;

    uint16_t udp_len_val = ntohs(udp->len);
    if (udp_len_val < 8) return nullptr;

    src_ip_n   = ip->saddr;
    src_port_h = ntohs(udp->sport);
    memcpy(src_mac, eth->src, 6);
    payload_len = udp_len_val - 8;
    return reinterpret_cast<const uint8_t*>(udp) + 8;
}

// Attach a classic BPF filter so the kernel discards any frame that does NOT
// match: IP proto=UDP AND IP dst==filter_dst_ip_n AND UDP dport==filter_dst_port_h.
// Non-matching frames are dropped before a byte reaches userspace.
static bool attach_rx_filter(int fd, uint32_t filter_dst_ip_n, uint16_t filter_dst_port_h) {
    sock_filter f[] = {
        BPF_STMT(BPF_LD |BPF_B|BPF_ABS,  23),                                // A = IP.proto
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  IPPROTO_UDP,             0, 6),     // != UDP  → reject
        BPF_STMT(BPF_LD |BPF_W|BPF_ABS,  30),                                // A = IP.dst
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  ntohl(filter_dst_ip_n),  0, 4),     // != dst  → reject
        BPF_STMT(BPF_LDX|BPF_B|BPF_MSH,  14),                                // X = IHL bytes
        BPF_STMT(BPF_LD |BPF_H|BPF_IND,  16),                                // A = UDP.dport
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  filter_dst_port_h,       0, 1),     // != port → reject
        BPF_STMT(BPF_RET|BPF_K, 0xFFFFFFFF),                                 // accept
        BPF_STMT(BPF_RET|BPF_K, 0),                                           // reject
    };
    sock_fprog prog{ static_cast<unsigned short>(sizeof(f)/sizeof(f[0])), f };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("SO_ATTACH_FILTER (non-fatal)");
        return false;
    }
    return true;
}

// ── PeerKey ───────────────────────────────────────────────────────────────
struct PeerKey {
    uint32_t ip;
    uint16_t port;
    bool operator==(const PeerKey& o) const { return ip == o.ip && port == o.port; }
};
struct PeerKeyHash {
    size_t operator()(const PeerKey& k) const {
        return (size_t)k.ip * 1315423911u + k.port;
    }
};

static uint64_t pack_peer_key(const sockaddr_in& a) {
    return (uint64_t)a.sin_addr.s_addr << 16 | ntohs(a.sin_port);
}

// ── Args ──────────────────────────────────────────────────────────────────
struct Args {
    std::string group       = "239.255.0.1";
    uint16_t    port        = 5000;
    uint16_t    sender_port = 45000;
    int         expected    = 1;
    std::string file;
    std::string iface       = "eth0"; // interface NAME (not IP); source IP auto-derived
    int         ttl         = 1;
    int         rto_ms      = 250;
    int         retries     = 20;
    size_t      max_app_payload = 1450;

    float dupack_pct       = 50.0f;
    int   tagg_ms          = 100;
    bool  rto_reset_on_ack = true;
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --group A.B.C.D --port P --sender-port S --expected N"
              << " --iface IFNAME [--file path] [--ttl T]"
              << " [--rto-ms MS] [--retries K] [--chunk BYTES]"
              << " [--dupack-pct PCT] [--tagg-ms MS] [--rto-reset-on-ack 0|1]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more) {
            if (i + more >= argc) { usage(argv[0]); return false; }
            return true;
        };
        if      (s == "--group"            && need(1)) a.group           = argv[++i];
        else if (s == "--port"             && need(1)) a.port            = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--sender-port"      && need(1)) a.sender_port     = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--expected"         && need(1)) a.expected        = std::stoi(argv[++i]);
        else if (s == "--file"             && need(1)) a.file            = argv[++i];
        else if (s == "--iface"            && need(1)) a.iface           = argv[++i];
        else if (s == "--ttl"              && need(1)) a.ttl             = std::stoi(argv[++i]);
        else if (s == "--rto-ms"           && need(1)) a.rto_ms         = std::stoi(argv[++i]);
        else if (s == "--retries"          && need(1)) a.retries         = std::stoi(argv[++i]);
        else if (s == "--chunk"            && need(1)) a.max_app_payload = (size_t)std::stoul(argv[++i]);
        else if (s == "--dupack-pct"       && need(1)) a.dupack_pct      = std::stof(argv[++i]);
        else if (s == "--tagg-ms"          && need(1)) a.tagg_ms         = std::stoi(argv[++i]);
        else if (s == "--rto-reset-on-ack" && need(1)) a.rto_reset_on_ack = (std::stoi(argv[++i]) != 0);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); return false; }
    }
    if (a.expected <= 0) { std::cerr << "--expected must be >= 1\n"; return false; }
    if (a.dupack_pct <= 0.0f || a.dupack_pct > 100.0f) {
        std::cerr << "--dupack-pct must be in (0, 100]\n"; return false;
    }
    return true;
}

// ═════════════════════════════════════════════════════════════════════════
// COMPONENT 1 — ACK Window (AckSlot + AckWindow)   [identical to UDP version]
// ═════════════════════════════════════════════════════════════════════════

struct AckSlot {
    uint32_t ack_count      = 0;
    bool     first_ack_done = false;

    std::unordered_set<uint64_t> dup_ack_senders;
    uint32_t dup_ack_count     = 0;
    Clock::time_point dupack_window_start{};
    bool     dupack_window_open = false;

    uint8_t  retrans_id    = 1;
    bool     is_retransmit = false;
};

struct AckWindow {
    std::unordered_map<uint32_t, AckSlot> slots;

    void add_slot(uint32_t seq, uint8_t retrans_id = 1) {
        AckSlot s{};
        s.retrans_id = retrans_id;
        slots[seq]   = std::move(s);
    }

    void mark_retransmit(uint32_t seq, uint8_t new_retrans_id) {
        auto it = slots.find(seq);
        if (it == slots.end()) return;
        AckSlot& s          = it->second;
        s.retrans_id        = new_retrans_id;
        s.is_retransmit     = true;
        s.ack_count         = 0;
        s.first_ack_done    = true;  // suppress cwnd growth on retransmit ACKs
        s.dup_ack_count     = 0;
        s.dup_ack_senders.clear();
        s.dupack_window_open = false;
    }

    void erase_below(uint32_t committed_una) {
        for (auto it = slots.begin(); it != slots.end(); )
            it = (it->first < committed_una) ? slots.erase(it) : std::next(it);
    }

    AckSlot* get(uint32_t seq) {
        auto it = slots.find(seq);
        return it != slots.end() ? &it->second : nullptr;
    }
    const AckSlot* get(uint32_t seq) const {
        auto it = slots.find(seq);
        return it != slots.end() ? &it->second : nullptr;
    }
};

// ═════════════════════════════════════════════════════════════════════════
// COMPONENT 2 — Reno State Machine (RenoSM)   [identical to UDP version]
// ═════════════════════════════════════════════════════════════════════════

enum class CCState { SLOW_START, CONG_AVOIDANCE, FAST_RECOVERY };

struct RenoSM {
    double   cwnd           = 1.0;
    double   ssthresh       = 65536.0;
    CCState  state          = CCState::SLOW_START;
    uint32_t recovery_point = 0;

    uint32_t window_size() const {
        return static_cast<uint32_t>(std::max(1.0, cwnd));
    }

    const char* state_str() const {
        switch (state) {
        case CCState::SLOW_START:     return "SS";
        case CCState::CONG_AVOIDANCE: return "CA";
        case CCState::FAST_RECOVERY:  return "FR";
        }
        return "?";
    }

    void on_first_ack(uint32_t count = 1) {
        switch (state) {
        case CCState::SLOW_START:
            cwnd += static_cast<double>(count);
            if (cwnd >= ssthresh) state = CCState::CONG_AVOIDANCE;
            break;
        case CCState::CONG_AVOIDANCE:
            cwnd += static_cast<double>(count) / cwnd;
            break;
        case CCState::FAST_RECOVERY:
            cwnd += static_cast<double>(count);
            break;
        }
    }

    void on_recovery_ack() {
        cwnd  = ssthresh;
        state = CCState::CONG_AVOIDANCE;
    }

    void on_dup_ack_threshold(uint32_t lost_seq) {
        if (state != CCState::FAST_RECOVERY) {
            ssthresh = std::max(cwnd / 2.0, 2.0);
            cwnd     = ssthresh + 3.0;
            state    = CCState::FAST_RECOVERY;
        }
        if (lost_seq > recovery_point)
            recovery_point = lost_seq;
    }

    void on_timeout() {
        ssthresh = std::max(cwnd / 2.0, 2.0);
        cwnd     = 1.0;
        state    = CCState::SLOW_START;
    }

    void on_partial_ack(uint32_t newly_acked) {
        cwnd -= static_cast<double>(newly_acked);
        cwnd += 1.0;
        if (cwnd < 1.0) cwnd = 1.0;
    }
};

static void update_rtt(double& srtt, double& rttvar, int& rto_ms, double sample_ms) {
    if (srtt < 0.0) {
        srtt   = sample_ms;
        rttvar = sample_ms / 2.0;
    } else {
        double err = sample_ms - srtt;
        rttvar = 0.75 * rttvar + 0.25 * std::abs(err);
        srtt   = 0.875 * srtt  + 0.125 * sample_ms;
    }
    int computed = static_cast<int>(srtt + 4.0 * rttvar);
    rto_ms = std::min(std::max(computed, 10), 30000);
}

// ═════════════════════════════════════════════════════════════════════════
// COMPONENT 3 — Shared ACK aggregator state   [identical to UDP version]
// ═════════════════════════════════════════════════════════════════════════

struct AckAggState {
    std::mutex              mtx;
    std::condition_variable cv;

    std::unordered_map<uint64_t, uint32_t> peer_cum_ack;
    std::unordered_map<uint64_t, uint32_t> peer_rwnd;

    AckWindow ack_wnd;
    uint32_t  committed_una = 1;

    uint32_t first_ack_count = 0;

    bool     fast_retransmit_needed = false;
    uint32_t fast_retransmit_seq    = 0;

    uint32_t last_tsecr  = 0;
    bool     tsecr_valid = false;

    uint32_t min_rwnd = 0xFFFF;
};

struct InFlightMeta {
    Clock::time_point sent_at;
    uint32_t          tsval;
    uint8_t           retrans_id = 1;
};

// ═════════════════════════════════════════════════════════════════════════
// McastRenoSender
// ═════════════════════════════════════════════════════════════════════════

class McastRenoSender {
public:
    explicit McastRenoSender(const Args& args) : A(args) {}
    ~McastRenoSender() { if (fd >= 0) close(fd); }

    // dst_mac is public: callers may call set_custom_dst_mac() between init() and run()
    // to embed routing labels in the Ethernet dst MAC field.
    uint8_t dst_mac[6]{};

    // ── init ──────────────────────────────────────────────────────────────
    bool init() {
        // Raw socket: receives all IPv4 frames on the interface.
        fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        if (fd < 0) { perror("socket(AF_PACKET)"); return false; }

        if (!get_iface_index(A.iface, if_idx))   return false;
        if (!get_iface_mac  (A.iface, src_mac))  return false;
        if (!get_iface_ip   (A.iface, src_ip_n)) return false;

        if (inet_pton(AF_INET, A.group.c_str(), &mcast_ip_n) != 1) {
            std::cerr << "Invalid --group: " << A.group << "\n"; return false;
        }

        // Standard multicast dst MAC (01:00:5E:xx:xx:xx).
        // Caller may override via set_custom_dst_mac() for routing labels.
        mcast_ip_to_mac(mcast_ip_n, dst_mac);

        // Bind to the interface so recv() only sees frames from it.
        sockaddr_ll sll{};
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_IP);
        sll.sll_ifindex  = if_idx;
        if (bind(fd, (sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind(AF_PACKET)"); return false;
        }

        // BPF filter: only deliver frames that are unicast UDP addressed to
        // our sender IP and sender_port.  Everything else is dropped in-kernel.
        attach_rx_filter(fd, src_ip_n, A.sender_port);

        // SO_RCVTIMEO drives the per-recv deadline used during handshake and FIN.
        timeval tv{};
        tv.tv_sec  = A.rto_ms / 1000;
        tv.tv_usec = (A.rto_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_RCVTIMEO"); return false;
        }

        std::cerr << "Sender: iface=" << A.iface
                  << " src=" << ip_to_str(src_ip_n) << ":" << A.sender_port
                  << " mcast=" << A.group << ":" << A.port
                  << " expected=" << A.expected
                  << " dupack_pct=" << A.dupack_pct
                  << " tagg_ms=" << A.tagg_ms
                  << " rto_reset_on_ack=" << A.rto_reset_on_ack << "\n";
        return true;
    }

    bool run() {
        if (!handshake()) return false;

        if (!A.file.empty()) {
            if (!load_file(A.file)) return false;
        } else {
            for (int i = 1; i <= 5; ++i) {
                std::string m = "hello-" + std::to_string(i);
                all_segs.emplace_back(m.begin(), m.end());
            }
        }
        uint32_t total = (uint32_t)all_segs.size();
        std::cerr << "Starting transfer: " << total << " segment(s)\n";

        {
            std::lock_guard<std::mutex> lk(agg.mtx);
            for (auto& c : cohort) {
                uint64_t k = pack_peer_key(c);
                agg.peer_cum_ack[k] = 1;
                agg.peer_rwnd[k]    = 0xFFFF;
            }
            agg.committed_una          = 1;
            agg.first_ack_count        = 0;
            agg.fast_retransmit_needed = false;
            agg.tsecr_valid            = false;
            agg.min_rwnd               = 0xFFFF;
        }

        agg_stop.store(false);
        agg_thread = std::thread(&McastRenoSender::ack_aggregator_loop, this);

        bool ok = transfer(total);

        agg_stop.store(true);
        agg.cv.notify_all();
        if (agg_thread.joinable()) agg_thread.join();

        if (!ok) return false;

        std::cerr << "Transfer complete. Sending FIN.\n";
        return send_fin(total + 1);
    }

private:
    // ═════════════════════════════════════════════════════════════════════
    // HANDSHAKE   [logic identical to UDP version; I/O via raw socket]
    // ═════════════════════════════════════════════════════════════════════
    bool handshake() {
        auto handshake_start = Clock::now();
        auto elapsed_us = [&]() -> long long {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - handshake_start).count();
        };

        std::unordered_map<PeerKey, sockaddr_in, PeerKeyHash> cohort_map;
        constexpr uint8_t kMaxRetransId = 8;
        bool success = false;

        for (int attempt = 0, retrans_id = 1;
             attempt <= A.retries && retrans_id <= kMaxRetransId;
             ++attempt, ++retrans_id)
        {
            if (attempt > 0) cohort_map.clear();

            uint32_t ts = now_ms();
            RmHeader h{};
            fill_header(h, 0, FLG_SYN, 1, ts, 0, (uint8_t)retrans_id);
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            serialize_header(h, pkt.data());
            if (!xmit(pkt)) {
                std::cerr << "Handshake failed sending SYN after " << elapsed_us() << " us\n";
                return false;
            }

            auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
            while (Clock::now() < deadline) {
                sockaddr_in peer{}; RmHeader rh{};
                if (!recv_header(peer, rh)) break;
                if (!verify_header(rh)) continue;
                if ((ntohs(rh.flags) & (FLG_SYN | FLG_ACK)) != (FLG_SYN | FLG_ACK)) continue;
                if (rh.retrans_id != (uint8_t)retrans_id) continue;
                if (ntohl(rh.tsecr) != ts) continue;

                PeerKey k{ peer.sin_addr.s_addr, peer.sin_port };
                if (!cohort_map.count(k)) cohort_map[k] = peer;
                if ((int)cohort_map.size() >= A.expected) break;
            }

            if ((int)cohort_map.size() >= A.expected) { success = true; break; }
        }

        if (!success || (int)cohort_map.size() < A.expected) {
            std::cerr << "Handshake failed after " << elapsed_us() << " us: got "
                      << cohort_map.size() << "/" << A.expected << " receivers\n";
            return false;
        }

        cohort.clear(); cohort.reserve(cohort_map.size());
        for (auto& kv : cohort_map) cohort.push_back(kv.second);

        uint32_t ts = now_ms();
        RmHeader start{};
        fill_header(start, 0, FLG_START, 1, ts, 0, 1);
        std::vector<uint8_t> pkt(sizeof(RmHeader));
        serialize_header(start, pkt.data());
        if (!xmit(pkt)) {
            std::cerr << "Handshake failed sending START after " << elapsed_us() << " us\n";
            return false;
        }

        std::cerr << "Handshake complete in " << elapsed_us() << " us ("
                  << (elapsed_us() / 1000.0) << " ms). Cohort=" << cohort.size()
                  << ". Sent START.\n";
        return true;
    }

    // ═════════════════════════════════════════════════════════════════════
    // FIN TEARDOWN   [identical to UDP version]
    // ═════════════════════════════════════════════════════════════════════
    bool send_fin(uint32_t seq) {
        constexpr uint8_t kMaxRetransId = 8;
        for (int attempt = 0, rid = 1;
             attempt <= A.retries && rid <= kMaxRetransId;
             ++attempt, ++rid)
        {
            uint8_t retrans_id = (uint8_t)rid;
            uint32_t ts = now_ms();
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            RmHeader h{};
            fill_header(h, seq, FLG_FIN, 0, ts, 0, retrans_id);
            serialize_header(h, pkt.data());
            if (!xmit(pkt)) return false;

            std::cerr << "FIN seq=" << seq
                      << " (try " << (attempt + 1)
                      << " retrans_id=" << (int)retrans_id << ")\n";

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
        std::unordered_set<uint64_t> got;
        got.reserve(cohort.size() * 2);
        auto pack_key = [](const sockaddr_in& a) {
            return (uint64_t)a.sin_addr.s_addr << 16 | ntohs(a.sin_port);
        };

        auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
        while (Clock::now() < deadline) {
            sockaddr_in peer{}; RmHeader rh{};
            if (!recv_header(peer, rh)) break;
            if (!verify_header(rh)) continue;
            if ((ntohs(rh.flags) & FLG_ACK) == 0) continue;
            if (ntohl(rh.seq) != seq) continue;
            if (ntohl(rh.tsecr) != ts_sent) continue;
            if (rh.retrans_id != retrans_id_expected) continue;

            bool member = false;
            for (auto& c : cohort)
                if (c.sin_addr.s_addr == peer.sin_addr.s_addr &&
                    c.sin_port        == peer.sin_port) { member = true; break; }
            if (!member) continue;

            got.insert(pack_key(peer));
            if (got.size() >= cohort.size()) return true;
        }
        return false;
    }

    // ═════════════════════════════════════════════════════════════════════
    // COMPONENT 3 — ACK AGGREGATOR THREAD   [identical to UDP version]
    // ═════════════════════════════════════════════════════════════════════
    void ack_aggregator_loop() {
        constexpr int kPollMs = 10;

        const size_t fr_threshold = std::max(size_t(1),
            (size_t)std::ceil((double)cohort.size() * ((double)A.dupack_pct / 100.0)));

        while (!agg_stop.load()) {
            sockaddr_in from{};
            RmHeader    rh{};
            if (!recv_header_timed(from, rh, kPollMs)) continue;

            if (!verify_header(rh)) continue;
            if ((ntohs(rh.flags) & FLG_ACK) == 0) continue;
            if (!is_cohort_member(from)) continue;

            uint64_t peer_key = pack_peer_key(from);
            uint32_t cum_ack  = ntohl(rh.seq);
            uint32_t tsecr    = ntohl(rh.tsecr);
            uint8_t  pkt_rid  = rh.retrans_id;

            std::lock_guard<std::mutex> lk(agg.mtx);

            auto pit = agg.peer_cum_ack.find(peer_key);
            if (pit == agg.peer_cum_ack.end()) continue;
            uint32_t peer_prev = pit->second;

            // ── Flow control: per-peer rwnd, recompute global min ────────
            {
                uint16_t adv_wnd = ntohs(rh.window);
                if (adv_wnd > 0) {
                    agg.peer_rwnd[peer_key] = (uint32_t)adv_wnd;
                    uint32_t new_min = 0xFFFFu;
                    for (auto& [k, w] : agg.peer_rwnd)
                        if (w < new_min) new_min = w;
                    if (new_min != agg.min_rwnd) {
                        agg.min_rwnd = new_min;
                        agg.cv.notify_all();
                    }
                }
            }

            if (cum_ack > peer_prev) {
                // ── Req 3: retrans_id filter (forward-progress path) ─────
                if (cum_ack > 0) {
                    const AckSlot* chk = agg.ack_wnd.get(cum_ack - 1);
                    if (chk && pkt_rid < chk->retrans_id) continue; // stale epoch
                }

                // ── Req 1: credit ack_count; detect first-ACK events ─────
                uint32_t local_first_acks = 0;
                for (uint32_t s = peer_prev; s < cum_ack; ++s) {
                    AckSlot* slot = agg.ack_wnd.get(s);
                    if (!slot) continue;
                    slot->ack_count++;
                    if (!slot->first_ack_done) {
                        slot->first_ack_done = true;
                        local_first_acks++;
                        agg.first_ack_count++;
                    }
                }

                pit->second = cum_ack;

                // ── Req 2: advance committed_una ─────────────────────────
                uint32_t new_committed = agg.committed_una;
                while (true) {
                    const AckSlot* s = agg.ack_wnd.get(new_committed);
                    if (!s || s->ack_count < (uint32_t)cohort.size()) break;
                    new_committed++;
                }
                bool advanced = (new_committed > agg.committed_una);
                if (advanced) agg.committed_una = new_committed;

                // ── RTT sample — Karn's algorithm ────────────────────────
                const AckSlot* last_slot = agg.ack_wnd.get(cum_ack - 1);
                if (last_slot && !last_slot->is_retransmit && tsecr != 0) {
                    agg.last_tsecr  = tsecr;
                    agg.tsecr_valid = true;
                }

                if (local_first_acks > 0 || advanced)
                    agg.cv.notify_all();

            } else {
                // ── Duplicate ACK ─────────────────────────────────────────
                AckSlot* slot = agg.ack_wnd.get(peer_prev);
                if (!slot) continue;

                // ── Req 3: retrans_id filter (dup-ACK path) ───────────────
                if (pkt_rid < slot->retrans_id) continue;

                // ── Req 7: T_agg aggregation timer ───────────────────────
                auto now_tp = Clock::now();
                if (!slot->dupack_window_open) {
                    slot->dupack_window_open  = true;
                    slot->dupack_window_start = now_tp;
                } else {
                    auto elapsed_ms =
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            now_tp - slot->dupack_window_start).count();
                    if (elapsed_ms > (long long)A.tagg_ms) {
                        slot->dup_ack_senders.clear();
                        slot->dup_ack_count       = 0;
                        slot->dupack_window_start = now_tp;
                    }
                }

                // ── Req 5: record unique sender; check x% threshold ───────
                if (slot->dup_ack_senders.insert(peer_key).second) {
                    slot->dup_ack_count = (uint32_t)slot->dup_ack_senders.size();
                    if (slot->dup_ack_count >= fr_threshold &&
                        !agg.fast_retransmit_needed &&
                        !slot->is_retransmit) {
                        agg.fast_retransmit_needed = true;
                        agg.fast_retransmit_seq    = peer_prev;
                        agg.cv.notify_all();
                    }
                }
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // SLIDING-WINDOW TRANSFER   [identical to UDP version]
    // ═════════════════════════════════════════════════════════════════════
    bool transfer(uint32_t total) {
        snd_nxt = 1;
        uint32_t prev_committed  = 1;
        int      consec_timeouts = 0;

        double srtt   = -1.0;
        double rttvar =  0.0;
        int    rto_ms = A.rto_ms;

        RenoSM reno;
        uint32_t last_known_min_rwnd = 0xFFFF;

        while (true) {
            {
                std::lock_guard<std::mutex> lk(agg.mtx);
                if (agg.committed_una > total) break;
            }

            uint32_t committed;
            {
                std::lock_guard<std::mutex> lk(agg.mtx);
                committed = agg.committed_una;
            }

            uint32_t eff_wnd = std::min(reno.window_size(), last_known_min_rwnd);
            while (snd_nxt <= total && snd_nxt < committed + eff_wnd) {
                {
                    std::lock_guard<std::mutex> lk(agg.mtx);
                    agg.ack_wnd.add_slot(snd_nxt, 1);
                }
                if (!send_segment(snd_nxt)) return false;
                snd_nxt++;
            }

            if (in_flight.empty()) break;

            auto& oldest   = in_flight.begin()->second;
            auto  expiry   = oldest.sent_at + std::chrono::milliseconds(rto_ms);
            auto  wait_dur = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 expiry - Clock::now());
            if (wait_dur.count() < 0) wait_dur = std::chrono::milliseconds(0);

            uint32_t first_ack_events    = 0;
            bool     fast_retransmit     = false;
            uint32_t fast_retransmit_seq = 0;
            uint32_t tsecr_sample        = 0;
            bool     have_tsecr          = false;

            std::unique_lock<std::mutex> lk(agg.mtx);
            bool woke_up = agg.cv.wait_for(lk, wait_dur, [&] {
                return agg.committed_una   > prev_committed ||
                       agg.first_ack_count > 0             ||
                       agg.fast_retransmit_needed           ||
                       agg.min_rwnd != last_known_min_rwnd;
            });
            uint32_t new_committed    = agg.committed_una;
            uint32_t current_min_rwnd = agg.min_rwnd;

            if (agg.first_ack_count > 0) {
                first_ack_events    = agg.first_ack_count;
                agg.first_ack_count = 0;
            }
            if (agg.fast_retransmit_needed) {
                fast_retransmit            = true;
                fast_retransmit_seq        = agg.fast_retransmit_seq;
                agg.fast_retransmit_needed = false;
            }
            if (agg.tsecr_valid) {
                tsecr_sample    = agg.last_tsecr;
                have_tsecr      = true;
                agg.tsecr_valid = false;
            }
            lk.unlock();

            last_known_min_rwnd = current_min_rwnd;

            if (have_tsecr && tsecr_sample != 0) {
                uint32_t now = now_ms();
                if (now >= tsecr_sample) {
                    update_rtt(srtt, rttvar, rto_ms,
                               static_cast<double>(now - tsecr_sample));
                    std::cerr << "  RTT sample=" << (now - tsecr_sample)
                              << " ms srtt=" << (int)srtt
                              << " rto=" << rto_ms << " ms\n";
                }
            }

            if (first_ack_events > 0) {
                reno.on_first_ack(first_ack_events);
                std::cerr << "  FIRST_ACK ×" << first_ack_events
                          << " cwnd=" << reno.cwnd
                          << " state=" << reno.state_str() << "\n";
            }

            if (woke_up && new_committed > prev_committed) {
                consec_timeouts = 0;

                for (auto it = in_flight.begin();
                     it != in_flight.end() && it->first < new_committed; )
                    it = in_flight.erase(it);
                {
                    std::lock_guard<std::mutex> lk2(agg.mtx);
                    agg.ack_wnd.erase_below(new_committed);
                }

                uint32_t old_committed = prev_committed;
                prev_committed = new_committed;

                if (A.rto_reset_on_ack) {
                    rto_ms = (srtt > 0.0)
                             ? std::min(std::max((int)(srtt + 4.0 * rttvar), 10), 30000)
                             : A.rto_ms;
                }

                if (reno.state == CCState::FAST_RECOVERY &&
                    new_committed > reno.recovery_point) {
                    reno.on_recovery_ack();
                    std::cerr << "  EXIT FR committed=" << new_committed
                              << " cwnd=" << reno.cwnd
                              << " state=" << reno.state_str() << "\n";
                } else if (reno.state == CCState::FAST_RECOVERY) {
                    uint32_t newly_acked = new_committed - old_committed;
                    reno.on_partial_ack(newly_acked);
                    std::cerr << "  PARTIAL_ACK committed=" << new_committed
                              << " newly_acked=" << newly_acked
                              << " retransmit seq=" << new_committed
                              << " cwnd=" << reno.cwnd << "\n";
                    if (!retransmit_segment(new_committed)) return false;
                    auto ifit = in_flight.find(new_committed);
                    if (ifit != in_flight.end()) {
                        std::lock_guard<std::mutex> lk2(agg.mtx);
                        agg.ack_wnd.mark_retransmit(new_committed,
                                                    ifit->second.retrans_id);
                    }
                } else {
                    std::cerr << "  COMMIT committed=" << new_committed
                              << " cwnd=" << reno.cwnd
                              << " state=" << reno.state_str() << "\n";
                }
            }

            if (fast_retransmit) {
                if (in_flight.count(fast_retransmit_seq)) {
                    reno.on_dup_ack_threshold(fast_retransmit_seq);
                    std::cerr << "  FAST_RETRANSMIT seq=" << fast_retransmit_seq
                              << " cwnd=" << reno.cwnd
                              << " ssthresh=" << reno.ssthresh
                              << " state=" << reno.state_str() << "\n";
                    if (!retransmit_segment(fast_retransmit_seq)) return false;
                    auto ifit = in_flight.find(fast_retransmit_seq);
                    if (ifit != in_flight.end()) {
                        std::lock_guard<std::mutex> lk2(agg.mtx);
                        agg.ack_wnd.mark_retransmit(fast_retransmit_seq,
                                                    ifit->second.retrans_id);
                    }
                } else {
                    std::cerr << "  FAST_RETRANSMIT seq=" << fast_retransmit_seq
                              << " already committed — skipping FR entry\n";
                }
            }

            if (!woke_up) {
                consec_timeouts++;
                if (consec_timeouts > A.retries) {
                    std::cerr << "Too many consecutive timeouts. Aborting.\n";
                    return false;
                }
                reno.on_timeout();
                rto_ms = std::min(rto_ms * 2, 30000);

                std::cerr << "  RTO timeout committed=" << prev_committed
                          << " cwnd=" << reno.cwnd
                          << " new_rto=" << rto_ms << " ms\n";

                if (!retransmit_segment(prev_committed)) return false;
                auto ifit = in_flight.find(prev_committed);
                if (ifit != in_flight.end()) {
                    std::lock_guard<std::mutex> lk2(agg.mtx);
                    agg.ack_wnd.mark_retransmit(prev_committed,
                                                ifit->second.retrans_id);
                }
            }
        }
        return true;
    }

    bool send_segment(uint32_t seq) {
        const auto& payload = all_segs[seq - 1];

        uint32_t ts = now_ms();
        std::vector<uint8_t> pkt(sizeof(RmHeader) + payload.size());
        RmHeader h{};
        fill_header(h, seq, FLG_DATA, 1, ts, 0, 1);
        serialize_header(h, pkt.data());
        memcpy(pkt.data() + sizeof(RmHeader), payload.data(), payload.size());

        if (!xmit(pkt)) return false;

        InFlightMeta meta{};
        meta.sent_at    = Clock::now();
        meta.tsval      = ts;
        meta.retrans_id = 1;
        in_flight[seq]  = meta;

        std::cerr << "  -> DATA seq=" << seq
                  << " len=" << payload.size()
                  << " snd_nxt=" << snd_nxt
                  << " in_flight=" << in_flight.size() << "\n";
        return true;
    }

    bool retransmit_segment(uint32_t seq) {
        auto it = in_flight.find(seq);
        if (it == in_flight.end()) return true;
        InFlightMeta& meta = it->second;

        uint8_t new_rid = static_cast<uint8_t>(
            std::min(static_cast<int>(meta.retrans_id) + 1, 8));
        meta.retrans_id = new_rid;

        const auto& payload = all_segs[seq - 1];
        uint32_t ts = now_ms();
        std::vector<uint8_t> pkt(sizeof(RmHeader) + payload.size());
        RmHeader h{};
        fill_header(h, seq, FLG_DATA, 1, ts, 0, new_rid);
        serialize_header(h, pkt.data());
        memcpy(pkt.data() + sizeof(RmHeader), payload.data(), payload.size());

        if (!xmit(pkt)) return false;

        meta.sent_at = Clock::now();
        meta.tsval   = ts;

        std::cerr << "  -> RETRANSMIT seq=" << seq
                  << " retrans_id=" << (int)new_rid
                  << " len=" << payload.size() << "\n";
        return true;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    bool load_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Failed to open file: " << path << "\n"; return false; }
        std::vector<uint8_t> buf(A.max_app_payload);
        while (true) {
            f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
            std::streamsize got = f.gcount();
            if (got <= 0) break;
            all_segs.emplace_back(buf.begin(), buf.begin() + got);
        }
        return true;
    }

    bool is_cohort_member(const sockaddr_in& from) const {
        for (auto& c : cohort)
            if (c.sin_addr.s_addr == from.sin_addr.s_addr &&
                c.sin_port        == from.sin_port) return true;
        return false;
    }

    bool recv_header_timed(sockaddr_in& from, RmHeader& out, int timeout_ms) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv{};
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (select(fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) return false;
        return recv_header(from, out);
    }

    // ═════════════════════════════════════════════════════════════════════
    // LOW-LEVEL I/O — RAW SOCKET (changed from UDP version)
    // ═════════════════════════════════════════════════════════════════════

    // Build and transmit a multicast frame: EthHdr+Ip4Hdr+UdpHdr+payload.
    // dst MAC is dst_mac (standard multicast or custom routing label).
    bool xmit(const std::vector<uint8_t>& payload) {
        std::vector<uint8_t> frame(14 + 20 + 8 + payload.size());
        size_t flen = build_udp_frame(
            frame.data(), frame.size(),
            src_mac, dst_mac,
            src_ip_n, mcast_ip_n,
            A.sender_port, A.port,
            (uint8_t)A.ttl,
            ip_id_++,
            payload.data(), payload.size());

        if (flen == 0) { std::cerr << "build_udp_frame: buffer too small\n"; return false; }

        sockaddr_ll sll{};
        sll.sll_family  = AF_PACKET;
        sll.sll_ifindex = if_idx;
        sll.sll_halen   = 6;
        memcpy(sll.sll_addr, dst_mac, 6);

        ssize_t n = sendto(fd, frame.data(), flen, 0, (sockaddr*)&sll, sizeof(sll));
        if (n < 0) { perror("sendto(raw)"); return false; }
        if ((size_t)n != flen) {
            std::cerr << "Partial send: " << n << "/" << flen << "\n"; return false;
        }
        return true;
    }

    // Receive one raw frame; parse and filter for unicast ACKs to our IP:sender_port.
    // Fills |from| with {src_ip (net order), src_port (net order)} and |out| with RmHeader.
    bool recv_header(sockaddr_in& from, RmHeader& out) {
        uint8_t frame[2048];
        ssize_t n = recv(fd, frame, sizeof(frame), 0);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) return false; // SO_RCVTIMEO
            perror("recv(raw)"); return false;
        }

        uint32_t src_ip; uint16_t src_port; uint8_t smac[6]; size_t plen;
        const uint8_t* payload = parse_udp_frame(
            frame, n,
            src_ip_n,       // ACKs must be addressed to our unicast IP
            A.sender_port,  // and to our sender port
            src_ip, src_port, smac, plen);

        if (!payload || plen < sizeof(RmHeader)) return false;

        memcpy(&out, payload, sizeof(RmHeader));
        from.sin_family      = AF_INET;
        from.sin_addr.s_addr = src_ip;
        from.sin_port        = htons(src_port); // store in network order (matches recvfrom)
        return true;
    }

    // ── Header helpers (identical to UDP version) ─────────────────────────

    void fill_header(RmHeader& h, uint32_t seq, uint16_t flags, uint16_t wnd,
                     uint32_t ts, uint32_t tsecr, uint8_t retrans_id = 1) {
        h.seq        = htonl(seq);
        h.src_port   = htons(A.sender_port);
        h.flags      = htons(flags);
        h.retrans_id = retrans_id;
        h.reserved   = 0;
        h.window     = htons(wnd);
        h.checksum   = 0;
        h.tsval      = htonl(ts);
        h.tsecr      = htonl(tsecr);
    }

    void serialize_header(RmHeader& h, uint8_t* out) {
        RmHeader tmp = h; tmp.checksum = 0;
        h.checksum = checksum16(&tmp, sizeof(tmp));
        memcpy(out, &h, sizeof(h));
    }

    bool verify_header(const RmHeader& net) {
        RmHeader tmp = net; uint16_t rcv = tmp.checksum;
        tmp.checksum = 0;
        return rcv == checksum16(&tmp, sizeof(tmp));
    }

    // ── State ─────────────────────────────────────────────────────────────
    Args A;
    int  fd = -1;

    // Raw socket state (new vs UDP version)
    int      if_idx    = 0;
    uint8_t  src_mac[6]{};
    uint32_t src_ip_n  = 0;
    uint32_t mcast_ip_n = 0;
    uint16_t ip_id_    = 0; // rolling IP Identification counter

    // Transport state
    std::vector<sockaddr_in>           cohort;
    uint32_t                           snd_nxt  = 1;
    std::map<uint32_t, InFlightMeta>   in_flight;
    std::vector<std::vector<uint8_t>>  all_segs;

    AckAggState       agg;
    std::atomic<bool> agg_stop{false};
    std::thread       agg_thread;
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    McastRenoSender s(args);
    if (!s.init()) return 2;
    // Optional: set custom routing labels in dst MAC before run(), e.g.:
    //   uint8_t labels[6] = {0x01, zone, rack, slot, port, 0x00};
    //   set_custom_dst_mac(s.dst_mac, labels);
    if (!s.run()) return 3;
    return 0;
}
