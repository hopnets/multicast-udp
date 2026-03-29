// peel_receiver.cpp
// Reliable multicast receiver — AF_PACKET raw socket version.
//
// Changes from the UDP version:
//   - AF_PACKET/SOCK_RAW used instead of SOCK_DGRAM; full Ethernet frames are
//     received and parsed; ACKs are sent as raw unicast Ethernet frames.
//   - --iface now takes an interface NAME (e.g. "eth0"), not an IP address.
//     The receiver's source IP is derived automatically from the interface.
//   - The NIC joins the standard multicast MAC via PACKET_ADD_MEMBERSHIP.
//     No IGMP is used: the sender embeds custom routing labels in dst MAC;
//     the last-hop switch rewrites dst MAC to the real multicast MAC before
//     delivery, so the NIC sees a normal multicast frame. IGMP (which signals
//     IP multicast routers) is irrelevant because this design replaces that
//     router-level forwarding entirely.
//   - Sender MAC and IP are learned from the Ethernet/IP headers of the first
//     received SYN, and used to address unicast ACK frames.
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -o peel_receiver peel_receiver.cpp
//
// Example:
//   sudo ./peel_receiver --group 239.255.0.1 --port 5000 --iface eth0 [--out received.bin] [--rcvbuf BYTES]
//
// Notes:
//   - Requires CAP_NET_RAW (run as root or set capability).
//   - Stop-and-wait assumption (same as UDP version): only seq == delivered+1
//     is accepted; out-of-order is ignored to force retransmit.

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
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// ── Wire-format headers (packed) ─────────────────────────────────────────
#pragma pack(push, 1)

struct EthHdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t etype;
};

struct Ip4Hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t cksum;
    uint32_t saddr;
    uint32_t daddr;
};

struct UdpHdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t cksum;
};

struct RmHeader {
    uint32_t seq;
    uint16_t src_port;
    uint16_t flags;
    uint8_t  retrans_id;
    uint8_t  reserved;
    uint16_t window;
    uint16_t checksum;
    uint32_t tsval;
    uint32_t tsecr;
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
    return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
               Clock::now().time_since_epoch()).count();
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

static void mcast_ip_to_mac(uint32_t mcast_ip_n, uint8_t mac[6]) {
    uint32_t ip = ntohl(mcast_ip_n);
    mac[0] = 0x01; mac[1] = 0x00; mac[2] = 0x5E;
    mac[3] = (ip >> 16) & 0x7F;
    mac[4] = (ip >>  8) & 0xFF;
    mac[5] = (ip >>  0) & 0xFF;
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

// Build a complete Ethernet frame: EthHdr(14) + Ip4Hdr(20) + UdpHdr(8) + payload.
// src_ip_n / dst_ip_n are already in network order.
// src_port_h / dst_port_h are in HOST order.
// Returns total frame length, or 0 on error.
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
    ip->frag_off = htons(0x4000);
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
    udp->cksum = 0;

    if (payload_len > 0)
        memcpy(frame + 14 + 20 + 8, payload, payload_len);

    return frame_len;
}

// Parse a raw Ethernet frame.
// Accepts only EtherType=IPv4, proto=UDP frames.
// filter_dst_ip_n=0 → skip IP dst check. filter_dst_port_h=0 → skip port check.
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
    std::string group  = "239.255.0.1";
    uint16_t    port   = 5000;
    std::string iface  = "eth0";     // interface NAME (not IP)
    std::string out_path;
    int         rcvbuf = 4 * 1024 * 1024;
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --group A.B.C.D --port P --iface IFNAME"
              << " [--out file] [--rcvbuf BYTES]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](const char* opt) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << opt << " requires a value\n";
                usage(argv[0]);
                return nullptr;
            }
            return argv[++i];
        };
        const char* v = nullptr;
        if      (s == "--group" ) { if (!(v = need(s.c_str()))) return false; a.group    = v; }
        else if (s == "--port"  ) { if (!(v = need(s.c_str()))) return false; a.port     = (uint16_t)std::stoi(v); }
        else if (s == "--iface" ) { if (!(v = need(s.c_str()))) return false; a.iface    = v; }
        else if (s == "--out"   ) { if (!(v = need(s.c_str()))) return false; a.out_path = v; }
        else if (s == "--rcvbuf") { if (!(v = need(s.c_str()))) return false; a.rcvbuf   = std::stoi(v); }
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown argument: " << s << "\n"; usage(argv[0]); return false; }
    }
    return true;
}

// ── PeelReceiver ──────────────────────────────────────────────────────────
class PeelReceiver {
public:
    explicit PeelReceiver(const Args& a) : A(a) {}
    ~PeelReceiver() {
        if (fd >= 0)      close(fd);
        if (ofs.is_open()) ofs.close();
    }

    bool init() {
        // Raw packet socket receiving all IPv4 frames on the interface.
        fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        if (fd < 0) { perror("socket(AF_PACKET)"); return false; }

        if (!get_iface_index(A.iface, if_idx))   return false;
        if (!get_iface_mac  (A.iface, src_mac))  return false;
        if (!get_iface_ip   (A.iface, src_ip_n)) return false;

        if (inet_pton(AF_INET, A.group.c_str(), &mcast_ip_n) != 1) {
            std::cerr << "Invalid --group: " << A.group << "\n"; return false;
        }

        // Optional receive buffer enlargement.
        if (A.rcvbuf > 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &A.rcvbuf, sizeof(A.rcvbuf));

        // Bind to the interface.
        sockaddr_ll sll{};
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_IP);
        sll.sll_ifindex  = if_idx;
        if (bind(fd, (sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind(AF_PACKET)"); return false;
        }

        // Kernel BPF filter: only deliver frames that are multicast UDP to our
        // group and port. Everything else is dropped in-kernel before reaching us.
        attach_rx_filter(fd, mcast_ip_n, A.port);

        // --- NIC frame acceptance (link-layer multicast membership) ---
        //
        // The sender puts custom routing labels in the Ethernet dst MAC field.
        // Intermediate switches forward using those labels; the LAST-HOP switch
        // rewrites dst MAC back to the standard IPv4 multicast MAC
        // (01:00:5E:xx:xx:xx) before delivering to receiver hosts.
        //
        // Therefore, frames arriving at this NIC carry the standard multicast MAC,
        // and PACKET_ADD_MEMBERSHIP (PACKET_MR_MULTICAST) is the right tool:
        // it registers the multicast MAC with the NIC hardware filter so those
        // frames are accepted without putting the whole NIC into promiscuous mode.
        //
        // IGMP is NOT used: IGMP signals IP multicast *routers*, but this design
        // replaces router-level multicast forwarding entirely with the custom
        // switch logic above.  The last-hop switch delivers to our link directly;
        // no IP multicast router needs to be informed.
        uint8_t mcast_mac[6];
        mcast_ip_to_mac(mcast_ip_n, mcast_mac);
        packet_mreq mr{};
        mr.mr_ifindex = if_idx;
        mr.mr_type    = PACKET_MR_MULTICAST;
        mr.mr_alen    = 6;
        memcpy(mr.mr_address, mcast_mac, 6);
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
            perror("PACKET_ADD_MEMBERSHIP (non-fatal)"); // non-fatal; recv still works

        if (!A.out_path.empty()) {
            ofs.open(A.out_path, std::ios::binary | std::ios::trunc);
            if (!ofs) {
                std::cerr << "Cannot open output file: " << A.out_path << "\n";
                return false;
            }
        }

        std::cerr << "Receiver: iface=" << A.iface
                  << " src_ip=" << ip_to_str(src_ip_n)
                  << " group=" << A.group << ":" << A.port
                  << (A.out_path.empty() ? " (stdout)" : (" -> " + A.out_path))
                  << "\n";
        return true;
    }

    bool run() {
        bool     started     = false;
        uint32_t delivered   = 0;   // last in-order seq delivered
        uint64_t total_bytes = 0;

        std::vector<uint8_t> frame(65536);

        while (true) {
            ssize_t n = recv(fd, frame.data(), frame.size(), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("recv(raw)"); return false;
            }

            // Parse and filter: only accept UDP frames for our multicast group:port.
            uint32_t src_ip; uint16_t src_port; uint8_t smac[6]; size_t plen;
            const uint8_t* payload = parse_udp_frame(
                frame.data(), n,
                mcast_ip_n, A.port,
                src_ip, src_port, smac, plen);

            if (!payload || plen < sizeof(RmHeader)) continue;

            RmHeader h{};
            memcpy(&h, payload, sizeof(RmHeader));
            if (!verify_header(h)) continue;

            // Learn sender's MAC and IP from first received frame.
            // This is used to address unicast ACKs back to the sender.
            if (sender_ip_n == 0) {
                sender_ip_n = src_ip;
                memcpy(sender_mac, smac, 6);
            }

            uint16_t flags      = ntohs(h.flags);
            uint32_t seq        = ntohl(h.seq);
            uint32_t tsval      = ntohl(h.tsval);
            uint16_t ack_port   = ntohs(h.src_port); // sender's ACK-listening port
            uint8_t  retrans_id = h.retrans_id;

            if (flags & FLG_SYN) {
                send_ack(src_ip, smac, ack_port, 0, FLG_SYN | FLG_ACK, tsval, retrans_id);
                continue;
            }

            if (flags & FLG_START) {
                started = true;
                std::cerr << "START received. Entering data phase.\n";
                continue;
            }

            if (!started && (flags & (FLG_DATA | FLG_FIN))) {
                // Be robust: ACK but don't deliver.
                send_ack(src_ip, smac, ack_port, seq, FLG_ACK, tsval, retrans_id);
                std::cerr << "DATA/FIN before START; ACKed but not delivered.\n";
                if (flags & FLG_FIN) {
                    std::cerr << "FIN before START; exiting.\n";
                    return true;
                }
                continue;
            }

            if (flags & FLG_DATA) {
                if (seq == delivered + 1) {
                    size_t app_len = plen - sizeof(RmHeader);
                    if (app_len > 0) {
                        const uint8_t* app = payload + sizeof(RmHeader);
                        if (ofs.is_open())
                            ofs.write(reinterpret_cast<const char*>(app), (std::streamsize)app_len);
                        total_bytes += app_len;
                    }
                    delivered = seq;
                    send_ack(src_ip, smac, ack_port, seq, FLG_ACK, tsval, retrans_id);
                    std::cerr << "DATA seq=" << seq << " len=" << (plen - sizeof(RmHeader))
                              << " delivered, total=" << total_bytes << "\n";
                } else if (seq == delivered) {
                    // Duplicate; re-ACK so sender doesn't time out.
                    send_ack(src_ip, smac, ack_port, seq, FLG_ACK, tsval, retrans_id);
                    std::cerr << "Duplicate DATA seq=" << seq << " -> re-ACK\n";
                } else {
                    // Out-of-order (seq > delivered+1): ignore to trigger retransmit.
                    std::cerr << "Out-of-order DATA seq=" << seq
                              << " (expected " << (delivered+1) << ") -> ignored\n";
                }
                continue;
            }

            if (flags & FLG_FIN) {
                send_ack(src_ip, smac, ack_port, seq, FLG_ACK, tsval, retrans_id);
                std::cerr << "FIN seq=" << seq << " ACKed. Total=" << total_bytes << " bytes\n";
                return true;
            }
        }
        return true;
    }

private:
    // ── Header helpers ────────────────────────────────────────────────────

    bool verify_header(const RmHeader& net) {
        RmHeader tmp = net;
        uint16_t rcv = tmp.checksum;
        tmp.checksum = 0;
        return rcv == checksum16(&tmp, sizeof(tmp));
    }

    // Send a raw unicast ACK frame to the sender.
    //   dst_ip_n  — sender's IP (network order, learned from received frame)
    //   dst_mac   — sender's Ethernet MAC (learned from received frame)
    //   dst_port  — sender's ACK-listening port (host order, from RmHeader.src_port)
    void send_ack(uint32_t      dst_ip_n,
                  const uint8_t dst_mac_p[6],
                  uint16_t      dst_port_h,
                  uint32_t      seq,
                  uint16_t      flags,
                  uint32_t      tsecr_in,
                  uint8_t       rid)
    {
        RmHeader a{};
        a.seq        = htonl(seq);
        a.src_port   = htons(A.port);  // receiver uses the multicast port as its src port
        a.flags      = htons(flags);
        a.retrans_id = rid;
        a.reserved   = 0;
        a.window     = htons(1);
        a.checksum   = 0;
        a.tsval      = htonl(now_ms());
        a.tsecr      = htonl(tsecr_in);
        RmHeader tmp = a; tmp.checksum = 0;
        a.checksum = checksum16(&tmp, sizeof(tmp));

        const size_t kFrameCap = 14 + 20 + 8 + sizeof(RmHeader);
        uint8_t frame[kFrameCap];
        size_t flen = build_udp_frame(
            frame, sizeof(frame),
            src_mac,    dst_mac_p,
            src_ip_n,   dst_ip_n,
            A.port,     dst_port_h,  // ACK: src=our port, dst=sender's ACK port
            64,                       // TTL for unicast
            ack_ip_id_++,
            reinterpret_cast<const uint8_t*>(&a), sizeof(a));

        if (flen == 0) { std::cerr << "send_ack: build_udp_frame failed\n"; return; }

        sockaddr_ll sll{};
        sll.sll_family  = AF_PACKET;
        sll.sll_ifindex = if_idx;
        sll.sll_halen   = 6;
        memcpy(sll.sll_addr, dst_mac_p, 6);

        ssize_t n = sendto(fd, frame, flen, 0, (sockaddr*)&sll, sizeof(sll));
        if (n < 0) perror("sendto ACK(raw)");
    }

    // ── State ─────────────────────────────────────────────────────────────
    Args     A;
    int      fd     = -1;
    int      if_idx = 0;
    uint8_t  src_mac[6]{};
    uint32_t src_ip_n   = 0;
    uint32_t mcast_ip_n = 0;
    uint16_t ack_ip_id_ = 0; // rolling IP Identification for ACK frames

    // Sender info learned from received packets; used to address ACKs.
    uint8_t  sender_mac[6]{};
    uint32_t sender_ip_n = 0;

    std::ofstream ofs;
};

// ── main ──────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    PeelReceiver r(args);
    if (!r.init()) return 2;
    while (true) {
        if (!r.run())  return 3;
    }
}