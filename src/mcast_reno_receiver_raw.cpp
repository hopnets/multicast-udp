// mcast_reno_receiver_raw.cpp
// Multicast reliable receiver — sliding-window skeleton, AF_PACKET/SOCK_RAW version.
//
// What changed from mcast_reno_receiver_udp.cpp (the SOCK_DGRAM version):
//   - AF_PACKET/SOCK_RAW replaces AF_INET/SOCK_DGRAM.  Full Ethernet frames are
//     received and parsed; ACKs are sent as raw unicast Ethernet frames built
//     via build_udp_frame().
//   - --iface now takes an interface NAME (e.g. "eth0"), not an IP address.
//     Source IP is auto-derived via ioctl(SIOCGIFADDR).
//   - SO_REUSEADDR and IP_ADD_MEMBERSHIP are replaced by PACKET_ADD_MEMBERSHIP
//     (link-layer multicast group join) and bind(sockaddr_ll).
//   - A kernel BPF filter is attached so only multicast UDP frames addressed to
//     our group:port reach userspace.
//   - send_ack() now builds a full Ethernet frame (EthHdr+Ip4Hdr+UdpHdr+RmHeader)
//     and uses sendto with sockaddr_ll.  The sender's MAC and IP are learned from
//     the Ethernet/IP headers of the first received SYN frame.
//   - Requires CAP_NET_RAW (run as root or set capability).
//
// Everything in the sliding-window data path is IDENTICAL to the UDP version:
//   OooBufEntry, in-order delivery, OOO buffering, cumulative ACK logic,
//   last_inorder_retrans_id, window advertisement, --ack-drop-rate injection.
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -pedantic \
//       -o mcast_reno_receiver_raw mcast_reno_receiver_raw.cpp
//
// Example:
//   sudo ./mcast_reno_receiver_raw \
//     --group 239.255.0.1 --port 5000 --iface eth0 \
//     --out received.bin --ooo-buf 64

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
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
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;    // 17 = UDP
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

// Reliable Multicast application header — 22 bytes, unchanged.
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

// ── Protocol flags ─────────────────────────────────────────────────────────
enum : uint16_t {
    FLG_SYN   = 0x0001,
    FLG_ACK   = 0x0002,
    FLG_START = 0x0004,
    FLG_DATA  = 0x0008,
    FLG_FIN   = 0x0010,
    FLG_RST   = 0x0020,
};

// ── Utilities ──────────────────────────────────────────────────────────────

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

static std::string ip_to_str(uint32_t ip_n) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_n, buf, sizeof(buf));
    return buf;
}

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

// BPF filter: accept only IP/UDP frames where dst IP == filter_dst_ip_n
// AND UDP dst port == filter_dst_port_h.
static bool attach_rx_filter(int fd, uint32_t filter_dst_ip_n, uint16_t filter_dst_port_h) {
    sock_filter f[] = {
        BPF_STMT(BPF_LD |BPF_B|BPF_ABS,  23),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  IPPROTO_UDP,             0, 6),
        BPF_STMT(BPF_LD |BPF_W|BPF_ABS,  30),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  ntohl(filter_dst_ip_n),  0, 4),
        BPF_STMT(BPF_LDX|BPF_B|BPF_MSH,  14),
        BPF_STMT(BPF_LD |BPF_H|BPF_IND,  16),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,  filter_dst_port_h,       0, 1),
        BPF_STMT(BPF_RET|BPF_K, 0xFFFFFFFF),
        BPF_STMT(BPF_RET|BPF_K, 0),
    };
    sock_fprog prog{ static_cast<unsigned short>(sizeof(f)/sizeof(f[0])), f };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("SO_ATTACH_FILTER (non-fatal)");
        return false;
    }
    return true;
}

// ── Args ───────────────────────────────────────────────────────────────────
struct Args {
    std::string group   = "239.255.0.1";
    uint16_t    port    = 5000;
    std::string iface   = "eth0"; // interface NAME (not IP); source IP auto-derived
    std::string out_path;
    int         rcvbuf  = 4 * 1024 * 1024;
    uint32_t    ooo_buf = 64;
    float ack_drop_rate = 0.0f;
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --group A.B.C.D --port P --iface IFNAME"
              << " [--out file] [--rcvbuf BYTES] [--ooo-buf N] [--ack-drop-rate P]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more) {
            if (i + more >= argc) { usage(argv[0]); return false; }
            return true;
        };
        if      (s == "--group"        && need(1)) a.group         = argv[++i];
        else if (s == "--port"         && need(1)) a.port          = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--iface"        && need(1)) a.iface         = argv[++i];
        else if (s == "--out"          && need(1)) a.out_path      = argv[++i];
        else if (s == "--rcvbuf"       && need(1)) a.rcvbuf        = std::stoi(argv[++i]);
        else if (s == "--ooo-buf"      && need(1)) a.ooo_buf       = (uint32_t)std::stoul(argv[++i]);
        else if (s == "--ack-drop-rate"&& need(1)) a.ack_drop_rate = std::stof(argv[++i]);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); return false; }
    }
    return true;
}

// ── OOO buffer entry (identical to UDP version) ────────────────────────────
struct OooBufEntry {
    std::vector<uint8_t> payload;
    uint32_t             tsval;
    uint8_t              retrans_id;
};

// ── McastRenoReceiver ──────────────────────────────────────────────────────
class McastRenoReceiver {
public:
    explicit McastRenoReceiver(const Args& args) : A(args) {}
    ~McastRenoReceiver() { if (fd >= 0) close(fd); if (ofs.is_open()) ofs.close(); }

    // ── init (changed: raw socket, PACKET_ADD_MEMBERSHIP, BPF filter) ────
    bool init() {
        fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        if (fd < 0) { perror("socket(AF_PACKET)"); return false; }

        if (!get_iface_index(A.iface, if_idx))   return false;
        if (!get_iface_mac  (A.iface, src_mac))  return false;
        if (!get_iface_ip   (A.iface, src_ip_n)) return false;

        if (inet_pton(AF_INET, A.group.c_str(), &mcast_ip_n) != 1) {
            std::cerr << "Invalid --group: " << A.group << "\n"; return false;
        }

        if (A.rcvbuf > 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &A.rcvbuf, sizeof(A.rcvbuf));

        sockaddr_ll sll{};
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_IP);
        sll.sll_ifindex  = if_idx;
        if (bind(fd, (sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind(AF_PACKET)"); return false;
        }

        // BPF filter: only deliver multicast UDP frames for our group:port.
        attach_rx_filter(fd, mcast_ip_n, A.port);

        // Register the standard multicast MAC with the NIC so the hardware
        // filter accepts those frames without putting the NIC in promiscuous mode.
        // (IGMP is not needed: we don't use IP multicast routing.)
        uint8_t mcast_mac[6];
        mcast_ip_to_mac(mcast_ip_n, mcast_mac);
        packet_mreq mr{};
        mr.mr_ifindex = if_idx;
        mr.mr_type    = PACKET_MR_MULTICAST;
        mr.mr_alen    = 6;
        memcpy(mr.mr_address, mcast_mac, 6);
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
            perror("PACKET_ADD_MEMBERSHIP (non-fatal)");

        if (!A.out_path.empty()) {
            ofs.open(A.out_path, std::ios::binary | std::ios::trunc);
            if (!ofs) {
                std::cerr << "Failed to open --out file: " << A.out_path << "\n";
                return false;
            }
        }

        std::cerr << "Listening: iface=" << A.iface
                  << " src=" << ip_to_str(src_ip_n)
                  << " group=" << A.group << ":" << A.port
                  << (A.out_path.empty() ? " (no file output)" : (" -> " + A.out_path))
                  << "\n";
        return true;
    }

    bool run() {
        bool started = false;
        srand(static_cast<unsigned>(time(nullptr)));

        uint32_t rcv_nxt    = 0;
        uint64_t total_bytes = 0;

        std::map<uint32_t, OooBufEntry> ooo_buf;
        uint8_t last_inorder_retrans_id = 1;

        std::vector<uint8_t> frame(65536);

        while (true) {
            // ── Receive one raw Ethernet frame ────────────────────────────
            ssize_t n = recv(fd, frame.data(), frame.size(), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("recv(raw)"); return false;
            }

            // Parse: accept only UDP frames for our multicast group:port.
            // src_ip and src_mac identify the sender for this frame.
            uint32_t src_ip; uint16_t src_port_h; uint8_t src_mac_f[6]; size_t plen;
            const uint8_t* payload = parse_udp_frame(
                frame.data(), n,
                mcast_ip_n, A.port,
                src_ip, src_port_h, src_mac_f, plen);

            if (!payload || plen < sizeof(RmHeader)) continue;

            RmHeader h{};
            memcpy(&h, payload, sizeof(h));
            if (!verify_header(h)) continue;

            uint16_t flags           = ntohs(h.flags);
            uint32_t seq             = ntohl(h.seq);
            uint32_t tsval           = ntohl(h.tsval);
            uint16_t sender_ack_port = ntohs(h.src_port); // sender's ACK-listening port

            uint8_t  retrans_id      = h.retrans_id;

            // ── SYN ───────────────────────────────────────────────────────
            if (flags & FLG_SYN) {
                uint16_t adv_wnd = (uint16_t)std::min(A.ooo_buf, (uint32_t)0xFFFFu);
                send_ack(src_ip, src_mac_f, sender_ack_port,
                         0, FLG_SYN | FLG_ACK, tsval, retrans_id, adv_wnd);
                continue;
            }

            // ── START ─────────────────────────────────────────────────────
            if (flags & FLG_START) {
                started = true;
                rcv_nxt = 1;
                std::cerr << "START received. Entering data phase.\n";
                continue;
            }

            // ── Implicit START ────────────────────────────────────────────
            if (!started && (flags & (FLG_DATA | FLG_FIN))) {
                started = true;
                rcv_nxt = 1;
                std::cerr << "DATA/FIN arrived before START — "
                             "inferring START was lost; entering data phase implicitly.\n";
            }

            // ── DATA ──────────────────────────────────────────────────────
            if (flags & FLG_DATA) {
                size_t app_len = plen - sizeof(RmHeader);
                uint16_t adv_wnd = advertised_window(ooo_buf.size());

                if (seq == rcv_nxt) {
                    // In-order segment
                    if (app_len > 0) {
                        write_payload(payload + sizeof(RmHeader), app_len);
                        total_bytes += app_len;
                    }
                    last_inorder_retrans_id = retrans_id;
                    rcv_nxt++;

                    uint32_t ack_tsval      = tsval;
                    uint8_t  ack_retrans_id = retrans_id;

                    // Drain contiguous OOO segments now deliverable.
                    while (!ooo_buf.empty()) {
                        auto it = ooo_buf.begin();
                        if (it->first != rcv_nxt) break;
                        write_payload(it->second.payload.data(), it->second.payload.size());
                        total_bytes += it->second.payload.size();
                        ack_tsval               = it->second.tsval;
                        ack_retrans_id          = it->second.retrans_id;
                        last_inorder_retrans_id = it->second.retrans_id;
                        ooo_buf.erase(it);
                        rcv_nxt++;
                    }

                    adv_wnd = advertised_window(ooo_buf.size());
                    send_ack(src_ip, src_mac_f, sender_ack_port,
                             rcv_nxt, FLG_ACK, ack_tsval, ack_retrans_id, adv_wnd);

                    std::cerr << "DATA seq=" << seq
                              << " len=" << app_len
                              << " -> in-order, rcv_nxt=" << rcv_nxt
                              << " total=" << total_bytes << " B"
                              << " adv_wnd=" << adv_wnd << "\n";

                } else if (seq > rcv_nxt) {
                    // Out-of-order segment: buffer if space; send dup-ACK.
                    if (ooo_buf.size() < A.ooo_buf && !ooo_buf.count(seq)) {
                        ooo_buf[seq] = OooBufEntry{
                            std::vector<uint8_t>(
                                payload + sizeof(RmHeader),
                                payload + sizeof(RmHeader) + app_len),
                            tsval,
                            retrans_id
                        };
                        std::cerr << "DATA seq=" << seq
                                  << " out-of-order (expected " << rcv_nxt
                                  << ") -> buffered [ooo=" << ooo_buf.size() << "]\n";
                    } else {
                        std::cerr << "DATA seq=" << seq
                                  << " out-of-order -> buffer full or duplicate, dropped\n";
                    }

                    // Dup-ACK: echo last_inorder_retrans_id (epoch of the lost slot,
                    // not the OOO packet's epoch, so the sender's filter is correct).
                    adv_wnd = advertised_window(ooo_buf.size());
                    send_ack(src_ip, src_mac_f, sender_ack_port,
                             rcv_nxt, FLG_ACK, tsval,
                             last_inorder_retrans_id, adv_wnd);

                } else {
                    // Already-delivered duplicate: re-ACK with last_inorder_retrans_id.
                    send_ack(src_ip, src_mac_f, sender_ack_port,
                             rcv_nxt, FLG_ACK, tsval,
                             last_inorder_retrans_id, adv_wnd);
                    std::cerr << "DATA seq=" << seq
                              << " already delivered -> re-ACK rcv_nxt=" << rcv_nxt << "\n";
                }
                continue;
            }

            // ── FIN ───────────────────────────────────────────────────────
            // Echo fin_seq (NOT rcv_nxt) so the sender's wait_all_acks() matches.
            if (flags & FLG_FIN) {
                for (auto& [s, entry] : ooo_buf) {
                    write_payload(entry.payload.data(), entry.payload.size());
                    total_bytes += entry.payload.size();
                }
                ooo_buf.clear();

                send_ack(src_ip, src_mac_f, sender_ack_port,
                         seq, FLG_ACK, tsval, retrans_id, /*adv_wnd*/1);

                std::cerr << "FIN seq=" << seq
                          << " -> ACKed. Total received=" << total_bytes << " bytes\n";
                return true;
            }
        }
        return true;
    }

private:
    // ── Header helpers (identical to UDP version) ──────────────────────────

    bool verify_header(const RmHeader& net) {
        RmHeader tmp = net; uint16_t r = tmp.checksum;
        tmp.checksum = 0;
        return r == checksum16(&tmp, sizeof(tmp));
    }

    // ── send_ack (changed: builds raw Ethernet frame) ─────────────────────
    //   dst_ip_n    — sender IP (network order), from received frame's IP header
    //   dst_mac_p   — sender MAC (6 bytes), from received frame's Ethernet header
    //   dst_port_h  — sender's ACK port (host order), from RmHeader.src_port
    //   seq         — ACK sequence number
    //   flags       — e.g. FLG_ACK, FLG_SYN|FLG_ACK
    //   tsecr_in    — sender tsval to echo back
    //   retrans_id_in — retrans epoch to echo
    //   adv_wnd     — advertised receive window in segments
    void send_ack(uint32_t       dst_ip_n,
                  const uint8_t  dst_mac_p[6],
                  uint16_t       dst_port_h,
                  uint32_t       seq,
                  uint16_t       flags,
                  uint32_t       tsecr_in,
                  uint8_t        retrans_id_in,
                  uint16_t       adv_wnd)
    {
        RmHeader a{};
        a.seq        = htonl(seq);
        a.src_port   = htons(A.port);   // receiver uses the multicast port as its src port
        a.flags      = htons(flags);
        a.retrans_id = retrans_id_in;
        a.reserved   = 0;
        a.window     = htons(adv_wnd);
        a.checksum   = 0;
        a.tsval      = htonl(now_ms());
        a.tsecr      = htonl(tsecr_in);
        RmHeader tmp = a; tmp.checksum = 0;
        a.checksum = checksum16(&tmp, sizeof(tmp));

        // ACK drop injection for fault testing (forward-progress ACKs only).
        bool is_data_ack = (flags == FLG_ACK);
        bool is_forward_prog = is_data_ack && (seq > last_acked_seq);
        if (is_forward_prog && A.ack_drop_rate > 0.0f) {
            float r = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
            if (r < A.ack_drop_rate) {
                std::cerr << "  [DROP] ACK seq=" << seq
                          << " retrans_id=" << (int)retrans_id_in << "\n";
                return;
            }
        }
        if (is_data_ack) last_acked_seq = std::max(last_acked_seq, seq);

        // Build and send the raw unicast ACK frame.
        const size_t kFrameCap = 14 + 20 + 8 + sizeof(RmHeader);
        uint8_t frame_buf[kFrameCap];
        size_t flen = build_udp_frame(
            frame_buf, sizeof(frame_buf),
            src_mac,    dst_mac_p,
            src_ip_n,   dst_ip_n,
            A.port,     dst_port_h, // ACK: src=our port, dst=sender's ACK port
            64,                      // TTL for unicast
            ack_ip_id_++,
            reinterpret_cast<const uint8_t*>(&a), sizeof(a));

        if (flen == 0) { std::cerr << "send_ack: build_udp_frame failed\n"; return; }

        sockaddr_ll sll{};
        sll.sll_family  = AF_PACKET;
        sll.sll_ifindex = if_idx;
        sll.sll_halen   = 6;
        memcpy(sll.sll_addr, dst_mac_p, 6);

        ssize_t n = sendto(fd, frame_buf, flen, 0, (sockaddr*)&sll, sizeof(sll));
        if (n < 0) perror("sendto ACK(raw)");
    }

    uint16_t advertised_window(size_t ooo_used) const {
        if (ooo_used >= A.ooo_buf) return 1;
        return (uint16_t)(A.ooo_buf - ooo_used);
    }

    void write_payload(const uint8_t* data, size_t len) {
        if (len > 0 && ofs.is_open())
            ofs.write(reinterpret_cast<const char*>(data), (std::streamsize)len);
    }

    // ── State ──────────────────────────────────────────────────────────────
    Args A;
    int  fd = -1;

    // Raw socket state (new vs UDP version)
    int      if_idx     = 0;
    uint8_t  src_mac[6]{};
    uint32_t src_ip_n   = 0;
    uint32_t mcast_ip_n = 0;
    uint16_t ack_ip_id_ = 0; // rolling IP Identification for ACK frames

    // ACK drop tracking (identical to UDP version)
    uint32_t last_acked_seq = 0;

    std::ofstream ofs;
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    McastRenoReceiver r(args);
    if (!r.init()) return 2;
    if (!r.run()) return 3;
    return 0;
}
