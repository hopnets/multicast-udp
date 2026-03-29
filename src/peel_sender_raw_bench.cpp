// peel_sender.cpp
// Reliable multicast sender — AF_PACKET raw socket version.
//
// Changes from the UDP version:
//   - AF_PACKET/SOCK_RAW used instead of SOCK_DGRAM; full Ethernet+IP+UDP
//     headers are built manually, giving byte-level control of every field.
//   - --iface now takes an interface NAME (e.g. "eth0"), not an IP address.
//     The sender's source IP is derived automatically from the interface.
//   - set_custom_dst_mac() is provided as the hook for
//     custom Ethernet-layer routing: the 6 dst-MAC bytes can carry arbitrary
//     8-bit routing labels instead of a real MAC address.
//   - Transport (stop-and-wait) is isolated in send_data() / send_fin() /
//     wait_all_acks() so it can be swapped for sliding-window or any other
//     scheme without touching socket / frame-building code.
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -o peel_sender peel_sender.cpp
//
// Example:
//   sudo ./peel_sender --group 239.255.0.1 --port 5000 --sender-port 45000 --expected 2  --iface eth0 --ttl 1 --file payload.bin --rto-ms 250 --retries 20
//
// Notes:
//   - Requires CAP_NET_RAW (run as root or set capability).
//   - Max application payload per packet defaults to 1450 bytes
//     (1500 MTU - 14 ETH - 20 IP - 8 UDP - 22 RmHeader - slack = 1436; we
//     keep 1450 as a safe default matching the UDP version).

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// ── Wire-format headers (packed, no padding) ─────────────────────────────
#pragma pack(push, 1)

struct EthHdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t etype; // 0x0800 = IPv4 (network order)
};

struct Ip4Hdr {
    uint8_t  ver_ihl;  // 0x45 → version=4, IHL=5 (no options)
    uint8_t  tos;
    uint16_t tot_len;  // IP header + payload (network order)
    uint16_t id;       // identification (network order)
    uint16_t frag_off; // 0x4000 = DF (network order)
    uint8_t  ttl;
    uint8_t  proto;    // 17 = UDP
    uint16_t cksum;    // header checksum (network order)
    uint32_t saddr;    // source IP (network order)
    uint32_t daddr;    // destination IP (network order)
};

struct UdpHdr {
    uint16_t sport; // source port (network order)
    uint16_t dport; // destination port (network order)
    uint16_t len;   // UDP header + payload length (network order)
    uint16_t cksum; // 0 = not computed (optional for IPv4)
};

// Reliable Multicast header — 22 bytes, unchanged from UDP version.
struct RmHeader {
    uint32_t seq;        // sequence number (network order)
    uint16_t src_port;   // sender's listening port (network order)
    uint16_t flags;      // protocol flags (network order)
    uint8_t  retrans_id; // retransmission epoch id (1..8)
    uint8_t  reserved;   // must be zero
    uint16_t window;     // window size hint (network order)
    uint16_t checksum;   // Internet checksum over header only (network order)
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

// ── Utility functions ─────────────────────────────────────────────────────

static uint32_t now_ms() {
    return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
               Clock::now().time_since_epoch()).count();
}

// Internet checksum (RFC 1071) over arbitrary bytes.
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

// ─────────────────────────────────────────────────────────────────────────────
// set_custom_dst_mac  —  hook for custom Ethernet-layer routing  (UNUSED for now)
//
// Standard Ethernet dst MAC addresses are 48-bit hardware identifiers.
// This function repurposes those 6 bytes to carry 6 arbitrary 8-bit routing
// labels (zone, rack, slot, port, ...) that your custom forwarding plane can
// inspect and act on.  The values array is copied verbatim into dst_mac; no
// validation or masking is performed.
//
// Typical usage (caller sets labels before calling sender.run()):
//
//   uint8_t labels[6] = { cidr_hop1, cidr_hop2, cidr_hop3, 0x00, 0x00, 0x00 };
//   set_custom_dst_mac(sender.dst_mac, labels);
//   sender.run();
//
// To restore standard multicast MAC behaviour:
//   mcast_ip_to_mac(mcast_ip_n, sender.dst_mac);
// ─────────────────────────────────────────────────────────────────────────────
[[maybe_unused]]
static void set_custom_dst_mac(uint8_t dst_mac[6], const uint8_t values[6]) {
    memcpy(dst_mac, values, 6);
}

// Get the kernel interface index for a named interface (e.g. "eth0").
static bool get_iface_index(const std::string& iface, int& idx) {
    idx = (int)if_nametoindex(iface.c_str());
    if (idx == 0) { perror(("if_nametoindex(" + iface + ")").c_str()); return false; }
    return true;
}

// Get the hardware (Ethernet) MAC address of a named interface.
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

// Get the primary IPv4 address of a named interface (network order).
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

// Build a complete Ethernet frame: EthHdr(14) + Ip4Hdr(20) + UdpHdr(8) + payload.
// All port and IP arguments are in HOST byte order except src_ip_n / dst_ip_n
// which are already in network order (as stored in sockaddr_in.sin_addr.s_addr).
// Returns the total frame length, or 0 if cap is too small.
static size_t build_udp_frame(
    uint8_t*       frame,
    size_t         cap,
    const uint8_t  src_mac[6],
    const uint8_t  dst_mac[6],
    uint32_t       src_ip_n,
    uint32_t       dst_ip_n,
    uint16_t       src_port_h,   // host order
    uint16_t       dst_port_h,   // host order
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
    ip->proto    = 17; // UDP
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

// Parse a raw Ethernet frame.
// Accepts only: EtherType=IPv4, proto=UDP.
// Optional filters: dst_ip (pass 0 to skip), dst_port (pass 0 to skip).
// On match fills: src_ip_n (network order), src_port_h (host order),
//                 src_mac (6 bytes), payload_len.
// Returns pointer to start of UDP payload, or nullptr on mismatch / error.
static const uint8_t* parse_udp_frame(
    const uint8_t* frame,
    ssize_t        n,
    uint32_t       filter_dst_ip_n,   // 0 = don't filter
    uint16_t       filter_dst_port_h, // 0 = don't filter (host order)
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

static std::string ip_to_str(uint32_t ip_n) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_n, buf, sizeof(buf));
    return buf;
}

// Attach a classic BPF filter (SO_ATTACH_FILTER) that makes the kernel drop
// every received frame that does NOT match:
//   IP protocol == UDP  AND  IP dst == filter_dst_ip_n  AND  UDP dst port == filter_dst_port_h
//
// The filter runs entirely inside the kernel — non-matching frames are
// discarded before a single byte is copied into userspace, so your recv()
// call only wakes up for packets that are actually relevant.
//
// Byte offsets (AF_PACKET frames include the Ethernet header):
//   23  = ETH(14) + IP.protocol offset(9)
//   30  = ETH(14) + IP.daddr offset(16)
//   36  = ETH(14) + IP(20) + UDP.dport offset(2)
//
// BPF loads multi-byte fields using get_unaligned_be* (network → host order),
// so compare constants must be in HOST byte order:
//   IP address  → ntohl(ip_n)
//   UDP port    → port_h  (already host order)
//   Protocol    → plain integer (single byte, no endianness)
//
// Works correctly regardless of IHL (IP options): the UDP header offset is
// computed dynamically using BPF_MSH + BPF_IND rather than a fixed offset.
static bool attach_rx_filter(int fd, uint32_t filter_dst_ip_n, uint16_t filter_dst_port_h) {
    // BPF loads multi-byte fields using get_unaligned_be* (network → host order),
    // so compare constants must be in HOST byte order:
    //   IP address  → ntohl(ip_n)
    //   UDP port    → port_h  (already host order)
    //   Protocol    → plain integer (single byte, no endianness)
    //
    // Fixed offsets (AF_PACKET frames include the 14-byte Ethernet header):
    //   14 = start of IP header (ver_ihl byte, used by BPF_MSH to extract IHL)
    //   23 = ETH(14) + IP.protocol(9)       — always fixed, before any options
    //   30 = ETH(14) + IP.daddr(16)         — always fixed, before any options
    //
    // Variable offset — UDP header position depends on IHL:
    //   BPF_LDX|BPF_B|BPF_MSH at offset 14:
    //     X = (packet[14] & 0x0F) << 2      — IP header length in bytes
    //     e.g. IHL=5 → X=20,  IHL=6 → X=24
    //   BPF_LD|BPF_H|BPF_IND at offset 16:
    //     A = packet[X + 16]                — X=IHL bytes, +14 ETH, +2 UDP dport
    //     e.g. IHL=5 → packet[36], IHL=6 → packet[40]   (always correct)

    sock_filter f[] = {
        /*[0]*/ BPF_STMT(BPF_LD |BPF_B|BPF_ABS,  23),                                 // A = IP.proto
        /*[1]*/ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  IPPROTO_UDP,            0, 6),       // != UDP  → [8] reject
        /*[2]*/ BPF_STMT(BPF_LD |BPF_W|BPF_ABS,  30),                                 // A = IP.dst (host order)
        /*[3]*/ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  ntohl(filter_dst_ip_n), 0, 4),       // != dst  → [8] reject
        /*[4]*/ BPF_STMT(BPF_LDX|BPF_B|BPF_MSH,  14),                                 // X = IHL in bytes
        /*[5]*/ BPF_STMT(BPF_LD |BPF_H|BPF_IND,  16),                                 // A = packet[X+16] = UDP.dport
        /*[6]*/ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  filter_dst_port_h,      0, 1),       // != port → [8] reject
        /*[7]*/ BPF_STMT(BPF_RET|BPF_K, 0xFFFFFFFF),                                  // accept all bytes
        /*[8]*/ BPF_STMT(BPF_RET|BPF_K, 0),                                            // reject (drop)
    };
    sock_fprog prog{ static_cast<unsigned short>(sizeof(f)/sizeof(f[0])), f };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("SO_ATTACH_FILTER (non-fatal)");
        return false; // non-fatal: recv still works, just sees all packets on the interface
    }
    return true;
}

// ── Arguments ─────────────────────────────────────────────────────────────
struct Args {
    std::string group       = "239.255.0.1"; // multicast group IP
    uint16_t    port        = 5000;           // multicast UDP dst port
    uint16_t    sender_port = 45000;          // sender's UDP src port (ACKs come here)
    int         expected    = 1;              // expected number of receivers
    std::string file;                         // optional payload file
    std::string iface       = "eth0";         // egress interface NAME (not IP)
    int         ttl         = 1;              // IP TTL for multicast frames
    int         rto_ms      = 250;            // retransmission timeout (ms)
    int         retries     = 20;             // max retransmit attempts per step
    size_t      max_app_payload = 1450;       // max application bytes per DATA packet
};

static void usage(const char* prog) {
    std::cerr
        << "Usage: " << prog
        << " --group A.B.C.D --port P --sender-port S --expected N"
        << " --iface IFNAME [--file path] [--ttl T]"
        << " [--rto-ms MS] [--retries K] [--chunk BYTES]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        // Helper: consume next token or abort
        auto need = [&](const char* opt) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << opt << " requires a value\n";
                usage(argv[0]);
                return nullptr;
            }
            return argv[++i];
        };
        const char* v = nullptr;
        if      (s == "--group"      ) { if (!(v = need(s.c_str()))) return false; a.group           = v; }
        else if (s == "--port"       ) { if (!(v = need(s.c_str()))) return false; a.port            = (uint16_t)std::stoi(v); }
        else if (s == "--sender-port") { if (!(v = need(s.c_str()))) return false; a.sender_port     = (uint16_t)std::stoi(v); }
        else if (s == "--expected"   ) { if (!(v = need(s.c_str()))) return false; a.expected        = std::stoi(v); }
        else if (s == "--file"       ) { if (!(v = need(s.c_str()))) return false; a.file            = v; }
        else if (s == "--iface"      ) { if (!(v = need(s.c_str()))) return false; a.iface           = v; }
        else if (s == "--ttl"        ) { if (!(v = need(s.c_str()))) return false; a.ttl             = std::stoi(v); }
        else if (s == "--rto-ms"     ) { if (!(v = need(s.c_str()))) return false; a.rto_ms          = std::stoi(v); }
        else if (s == "--retries"    ) { if (!(v = need(s.c_str()))) return false; a.retries         = std::stoi(v); }
        else if (s == "--chunk"      ) { if (!(v = need(s.c_str()))) return false; a.max_app_payload = (size_t)std::stoul(v); }
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown argument: " << s << "\n"; usage(argv[0]); return false; }
    }
    if (a.expected <= 0) {
        std::cerr << "--expected must be >= 1\n"; return false;
    }
    constexpr size_t kMaxPayload = 65535 - 20 - 8 - sizeof(RmHeader);
    if (a.max_app_payload < 1 || a.max_app_payload > kMaxPayload) {
        std::cerr << "--chunk invalid; must be 1.." << kMaxPayload << "\n"; return false;
    }
    return true;
}

// ── Per-receiver identity (IP + port) ────────────────────────────────────
struct PeerKey {
    uint32_t ip;   // network order
    uint16_t port; // host order
    bool operator==(const PeerKey& o) const { return ip == o.ip && port == o.port; }
};
struct PeerKeyHash {
    size_t operator()(const PeerKey& k) const {
        return (size_t)k.ip * 1315423911u ^ k.port;
    }
};

// ── PeelSender ────────────────────────────────────────────────────────────
class PeelSender {
public:
    explicit PeelSender(const Args& a) : A(a) {}
    ~PeelSender() { if (fd >= 0) close(fd); }

    // dst_mac is public so callers can apply set_custom_dst_mac() before run().
    uint8_t dst_mac[6]{};

    bool init() {
        // Raw socket receiving all IPv4 frames on the interface.
        fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        if (fd < 0) { perror("socket(AF_PACKET)"); return false; }

        if (!get_iface_index(A.iface, if_idx))    return false;
        if (!get_iface_mac  (A.iface, src_mac))   return false;
        if (!get_iface_ip   (A.iface, src_ip_n))  return false;

        if (inet_pton(AF_INET, A.group.c_str(), &mcast_ip_n) != 1) {
            std::cerr << "Invalid --group: " << A.group << "\n"; return false;
        }

        // Compute standard multicast dst MAC; caller may override via dst_mac.
        mcast_ip_to_mac(mcast_ip_n, dst_mac);

        // Bind to interface so we only receive frames from it.
        sockaddr_ll sll{};
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_IP);
        sll.sll_ifindex  = if_idx;
        if (bind(fd, (sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind(AF_PACKET)"); return false;
        }

        // Kernel BPF filter: only deliver frames that are unicast UDP to our
        // sender port. Everything else is dropped in-kernel before reaching us.
        attach_rx_filter(fd, src_ip_n, A.sender_port);

        // SO_RCVTIMEO drives the ACK-collection deadline.
        timeval tv{};
        tv.tv_sec  = A.rto_ms / 1000;
        tv.tv_usec = (A.rto_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_RCVTIMEO"); return false;
        }

        std::cerr << "Sender: iface=" << A.iface
                  << " src=" << ip_to_str(src_ip_n) << ":" << A.sender_port
                  << " mcast=" << A.group << ":" << A.port
                  << " expected=" << A.expected << "\n";
        return true;
    }

    bool run() {
        if (!handshake()) return false;
        if (!A.file.empty()) return send_file(A.file);

        // Demo: 5 small messages then FIN.
        uint32_t seq = 1;
        for (int i = 1; i <= 5; ++i) {
            std::string msg = "hello-" + std::to_string(i);
            if (!send_data(seq++, std::vector<uint8_t>(msg.begin(), msg.end())))
                return false;
        }
        return send_fin(seq++);
    }

    bool benchmark_raw(const int runs = 100, const int packets_to_send_per_iteration = 1000, std::chrono::milliseconds gap = 500ms) {
        std::vector<int> handshake_durations = {};
        std::vector<int> data_ack_durations = {};
        std::vector<int> fin_ack_durations = {};


        for (int i = 0; i < runs; i++) {
            // init vars

            ip_id_ = 0;
            cohort.clear();

            auto t0 = Clock::now();
            if (!handshake()) return false;
            auto t1 = Clock::now();
            uint64_t us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            handshake_durations.push_back(us);

            // Demo: 5 small messages then FIN.
            uint32_t seq = 1;
            auto t2 = Clock::now();
            for (int i = 1; i <= packets_to_send_per_iteration; ++i) {
                std::string msg = "hello-" + std::to_string(i);
                if (!send_data(seq++, std::vector<uint8_t>(msg.begin(), msg.end())))
                    return false;
            }
            auto t3 = Clock::now();
            us = std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count();
            auto us_over_packet_count = us/packets_to_send_per_iteration;
            data_ack_durations.push_back(us_over_packet_count);

            auto t4 = Clock::now();
            auto ret_code = send_fin(seq++);
            auto t5 = Clock::now();
            if (ret_code == false) {
                return false;
            }
            us = std::chrono::duration_cast<std::chrono::microseconds>(t5 - t4).count();
            fin_ack_durations.push_back(us);
        }
        uint64_t avg_handshake = 0;
        uint64_t avg_data_ack = 0;
        uint64_t avg_fin_ack = 0;
        for (int i = 0; i < runs; i++) {
            avg_handshake += handshake_durations[i];
            avg_data_ack += data_ack_durations[i];
            avg_fin_ack += fin_ack_durations[i];
        }
        avg_handshake = avg_handshake / runs;
        avg_data_ack = avg_data_ack / runs;
        avg_fin_ack = avg_fin_ack / runs;
        printf("----------------------------------------\n");
        printf("BENCHMARK COMPLETE:\n");
        printf("average handshake time (us): %lu\n", avg_handshake);
        printf("average data + ack time (us): %lu\n", avg_data_ack);
        printf("average fin + ack time (us): %lu\n", avg_fin_ack);
        printf("----------------------------------------\n\n");
    }

private:
    // ── Handshake ─────────────────────────────────────────────────────────
    bool handshake() {
        auto t0 = Clock::now();
        auto elapsed_us = [&]() {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                       Clock::now() - t0).count();
        };

        std::unordered_map<PeerKey, sockaddr_in, PeerKeyHash> cohort_map;
        constexpr int kMaxRid = 8;
        bool success = false;

        for (int attempt = 0, rid = 1;
             attempt <= A.retries && rid <= kMaxRid;
             ++attempt, ++rid)
        {
            if (attempt > 0) cohort_map.clear();

            uint32_t ts = now_ms();
            RmHeader h{};
            fill_header(h, 0, FLG_SYN, 1, ts, 0, (uint8_t)rid);
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            serialize_header(h, pkt.data());

            if (!xmit(pkt)) {
                std::cerr << "handshake: xmit SYN failed at " << elapsed_us() << " us\n";
                return false;
            }

            auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
            while (Clock::now() < deadline) {
                sockaddr_in peer{}; RmHeader rh{};
                if (!recv_header(peer, rh)) break; // timeout
                if (!verify_header(rh)) continue;
                uint16_t fl = ntohs(rh.flags);
                if ((fl & (FLG_SYN | FLG_ACK)) != (FLG_SYN | FLG_ACK)) continue;
                if (rh.retrans_id != (uint8_t)rid) continue;
                if (ntohl(rh.tsecr) != ts) continue;

                PeerKey k{ peer.sin_addr.s_addr, ntohs(peer.sin_port) };
                cohort_map.emplace(k, peer);
                if ((int)cohort_map.size() >= A.expected) break;
            }
            if ((int)cohort_map.size() >= A.expected) { success = true; break; }
        }

        if (!success) {
            std::cerr << "Handshake failed at " << elapsed_us() << " us: "
                      << cohort_map.size() << "/" << A.expected << " receivers\n";
            return false;
        }

        cohort.clear();
        cohort.reserve(cohort_map.size());
        for (auto& kv : cohort_map) cohort.push_back(kv.second);

        // Notify cohort with START.
        uint32_t ts = now_ms();
        RmHeader st{};
        fill_header(st, 0, FLG_START, 1, ts, 0, 1);
        std::vector<uint8_t> pkt(sizeof(RmHeader));
        serialize_header(st, pkt.data());
        if (!xmit(pkt)) { std::cerr << "handshake: xmit START failed\n"; return false; }

        std::cerr << "Handshake done in " << elapsed_us() << " us, cohort="
                  << cohort.size() << ". Sent START.\n";
        return true;
    }

    // ── File sender ───────────────────────────────────────────────────────
    bool send_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Cannot open file: " << path << "\n"; return false; }
        uint32_t seq = 1;
        std::vector<uint8_t> buf(A.max_app_payload);
        while (true) {
            f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
            std::streamsize got = f.gcount();
            if (got <= 0) break;
            if (!send_data(seq++, std::vector<uint8_t>(buf.begin(), buf.begin() + got)))
                return false;
        }
        return send_fin(seq++);
    }

    // ── Transport: stop-and-wait ──────────────────────────────────────────
    //
    // EXTENSION POINT: to replace stop-and-wait with a sliding-window or
    // other transport, rewrite send_data(), send_fin(), and wait_all_acks().
    // The socket layer (xmit, recv_header) and all header helpers remain
    // untouched.

    bool send_data(uint32_t seq, const std::vector<uint8_t>& app) {
        constexpr int kMaxRid = 8;
        for (int attempt = 0, rid = 1;
             attempt <= A.retries && rid <= kMaxRid;
             ++attempt, ++rid)
        {
            uint32_t ts = now_ms();
            std::vector<uint8_t> pkt(sizeof(RmHeader) + app.size());
            RmHeader h{};
            fill_header(h, seq, FLG_DATA, 1, ts, 0, (uint8_t)rid);
            serialize_header(h, pkt.data());
            if (!app.empty())
                memcpy(pkt.data() + sizeof(RmHeader), app.data(), app.size());

            if (!xmit(pkt)) return false;
            std::cerr << "DATA seq=" << seq << " len=" << app.size()
                      << " (try " << (attempt+1) << ", rid=" << rid << ")\n";

            if (wait_all_acks(seq, ts, (uint8_t)rid)) return true;
            std::cerr << "  timeout -> retransmit\n";
        }
        std::cerr << "Failed to deliver DATA seq=" << seq << "\n";
        return false;
    }

    bool send_fin(uint32_t seq) {
        constexpr int kMaxRid = 8;
        for (int attempt = 0, rid = 1;
             attempt <= A.retries && rid <= kMaxRid;
             ++attempt, ++rid)
        {
            uint32_t ts = now_ms();
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            RmHeader h{};
            fill_header(h, seq, FLG_FIN, 0, ts, 0, (uint8_t)rid);
            serialize_header(h, pkt.data());

            if (!xmit(pkt)) return false;
            std::cerr << "FIN seq=" << seq << " (try " << (attempt+1) << ")\n";

            if (wait_all_acks(seq, ts, (uint8_t)rid)) {
                std::cerr << "All receivers ACKed FIN. Done.\n";
                return true;
            }
            std::cerr << "  timeout -> retransmit FIN\n";
        }
        std::cerr << "Failed to deliver FIN\n";
        return false;
    }

    bool wait_all_acks(uint32_t seq, uint32_t ts_sent, uint8_t rid_expected) {
        std::unordered_set<uint64_t> got;
        got.reserve(cohort.size() * 2);

        // Pack (ip_network, port_host) into a unique 64-bit key.
        auto pack_key = [](const sockaddr_in& a) -> uint64_t {
            return ((uint64_t)(uint32_t)a.sin_addr.s_addr << 16) | ntohs(a.sin_port);
        };

        auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
        while (Clock::now() < deadline) {
            sockaddr_in peer{}; RmHeader rh{};
            if (!recv_header(peer, rh)) break;
            if (!verify_header(rh)) continue;
            if ((ntohs(rh.flags) & FLG_ACK) == 0) continue;
            if (ntohl(rh.seq)   != seq)       continue;
            if (ntohl(rh.tsecr) != ts_sent)   continue;
            if (rh.retrans_id   != rid_expected) continue;

            // Verify peer is in cohort.
            bool member = false;
            for (auto& c : cohort) {
                if (c.sin_addr.s_addr == peer.sin_addr.s_addr &&
                    c.sin_port        == peer.sin_port) {
                    member = true; break;
                }
            }
            if (!member) continue;

            got.insert(pack_key(peer));
            if (got.size() >= cohort.size()) return true;
        }
        return false;
    }

    // ── Socket I/O ────────────────────────────────────────────────────────

    // Build and transmit a multicast frame containing payload (RmHeader + app data).
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

    // Receive one raw frame; parse and filter for unicast ACKs addressed to us.
    // Fills |from| with (sender_ip, sender_port) and |out| with the RmHeader.
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
        from.sin_port        = htons(src_port); // store in network order
        return true;
    }

    // ── Header helpers ────────────────────────────────────────────────────

    void fill_header(RmHeader& h, uint32_t seq, uint16_t flags,
                     uint16_t wnd, uint32_t ts, uint32_t tsecr,
                     uint8_t rid = 1)
    {
        h.seq        = htonl(seq);
        h.src_port   = htons(A.sender_port);
        h.flags      = htons(flags);
        h.retrans_id = rid;
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
        RmHeader tmp = net;
        uint16_t rcv = tmp.checksum;
        tmp.checksum = 0;
        return rcv == checksum16(&tmp, sizeof(tmp));
    }

    // ── State ─────────────────────────────────────────────────────────────
    Args     A;
    int      fd      = -1;
    int      if_idx  = 0;
    uint8_t  src_mac[6]{};
    uint32_t src_ip_n   = 0;
    uint32_t mcast_ip_n = 0;
    uint16_t ip_id_     = 0; // rolling IP Identification counter

    std::vector<sockaddr_in> cohort; // fixed after handshake
};

// ── main ──────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    PeelSender s(args);
    if (!s.init()) return 2;
    // Optional: override dst MAC with custom routing labels here, e.g.:
    //   uint8_t labels[6] = {0x01, zone, rack, slot, port, 0x00};
    //   set_custom_dst_mac(s.dst_mac, labels);
    if (!s.run()) return 3;
    return 0;
}
