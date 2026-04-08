// mcast_reno_receiver.cpp
// Multicast reliable receiver — sliding-window skeleton.
//
// What is IDENTICAL to peel_receiver.cpp:
//   - RmHeader, flags, utilities
//   - init()     : socket, SO_REUSEADDR, SO_RCVBUF, multicast group join
//   - Handshake  : SYN -> send SYN|ACK, wait for START
//   - FIN        : ACK the FIN with rh.seq = fin_seq (compatible with sender's
//                  wait_all_acks), then exit
//   - verify_header(), local_port()
//
// What is CHANGED (data phase only):
//   - ACK semantics: ACK.seq = rcv_nxt (cumulative "next expected") instead of
//                    echoing the specific DATA seq.  The sender's aggregator reads
//                    this as the receiver's forward progress.
//   - Out-of-order handling: segments with seq > rcv_nxt are buffered (not
//                    silently dropped as in the stop-and-wait version).
//                    A duplicate ACK (rcv_nxt unchanged) is sent immediately,
//                    which feeds the aggregator's dup-ACK detection.
//   - Window advertisement: ACK.window carries advertised_window(ooo_used) so
//                    the sender has a basic flow-control signal.
//   - retrans_id echo: DATA ACKs echo the retrans_id from the incoming DATA
//                    packet so the sender can apply Karn's algorithm.
//   - Implicit START: if a DATA or FIN packet arrives before the START frame,
//                    the receiver infers START was lost and enters data phase.
//
// NOTE on FIN ACK format:
//   FIN ACKs use the old echo style: ACK.seq = fin_seq (NOT cumulative).
//   This is intentional so the sender's unmodified wait_all_acks() still works.
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o mcast_reno_receiver mcast_reno_receiver.cpp
//
// Example:
//   ./mcast_reno_receiver --group 239.255.0.1 --port 5000 --out received.bin \
//                         --iface 10.169.144.14 --ooo-buf 64

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// ─── Protocol header (22 bytes) — identical to peel_receiver ─────────────────
#pragma pack(push, 1)
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
static_assert(sizeof(RmHeader) == 22, "RmHeader must be 22 bytes");

enum : uint16_t {
    FLG_SYN   = 0x0001,
    FLG_ACK   = 0x0002,
    FLG_START = 0x0004,
    FLG_DATA  = 0x0008,
    FLG_FIN   = 0x0010,
    FLG_RST   = 0x0020,
};

// ─── Utilities — identical to peel_receiver ───────────────────────────────────
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

static std::string addr_to_string(const sockaddr_in& a) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
    char out[128];
    snprintf(out, sizeof(out), "%s:%u", buf, ntohs(a.sin_port));
    return std::string(out);
}

// ─── Args — identical to peel_receiver, plus --ooo-buf ───────────────────────
struct Args {
    std::string group   = "239.255.0.1";
    uint16_t    port    = 5000;
    std::optional<std::string> iface_ip;
    std::string out_path;
    int         rcvbuf  = 4 * 1024 * 1024;
    // Max number of out-of-order segments to buffer.
    // Advertised as the receive window to the sender.
    uint32_t    ooo_buf = 64;
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --group A.B.C.D --port P [--iface X.Y.Z.W]"
              << " [--out file] [--rcvbuf BYTES] [--ooo-buf N]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more) {
            if (i + more >= argc) { usage(argv[0]); return false; }
            return true;
        };
        if      (s == "--group"   && need(1)) a.group    = argv[++i];
        else if (s == "--port"    && need(1)) a.port     = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--iface"   && need(1)) a.iface_ip = argv[++i];
        else if (s == "--out"     && need(1)) a.out_path = argv[++i];
        else if (s == "--rcvbuf"  && need(1)) a.rcvbuf   = std::stoi(argv[++i]);
        else if (s == "--ooo-buf" && need(1)) a.ooo_buf  = (uint32_t)std::stoul(argv[++i]);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); return false; }
    }
    return true;
}

// ─── Out-of-order buffer entry ────────────────────────────────────────────────
// Stores the application payload together with the timing/epoch fields from the
// DATA packet so that the cumulative ACK sent after an OOO drain can echo the
// tsval and retrans_id of the LAST delivered segment rather than those of the
// initial in-order trigger packet.  This is required for:
//   • Karn's algorithm (tsecr must reflect the last packet that advanced rcv_nxt).
//   • Sender's retrans_id epoch filter (retrans_id echoed in ACK must match the
//     current epoch of the slot at rcv_nxt-1, not an unrelated OOO packet).
struct OooBufEntry {
    std::vector<uint8_t> payload;
    uint32_t             tsval;
    uint8_t              retrans_id;
};

// ─── McastRenoReceiver ────────────────────────────────────────────────────────
class McastRenoReceiver {
public:
    explicit McastRenoReceiver(const Args& args) : A(args) {}
    ~McastRenoReceiver() { if (fd >= 0) close(fd); if (ofs.is_open()) ofs.close(); }

    // ── init — identical to PeelReceiver::init() ─────────────────────────────
    bool init() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return false; }

        int yes = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            perror("setsockopt SO_REUSEADDR"); return false;
        }
        if (A.rcvbuf > 0 &&
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &A.rcvbuf, sizeof(A.rcvbuf)) < 0) {
            perror("setsockopt SO_RCVBUF"); /* non-fatal */
        }

        sockaddr_in local{};
        local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(A.port);
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) {
            perror("bind"); return false;
        }

        ip_mreq mreq{};
        if (inet_pton(AF_INET, A.group.c_str(), &mreq.imr_multiaddr) != 1) {
            std::cerr << "Invalid --group IP\n"; return false;
        }
        if (A.iface_ip) {
            if (inet_pton(AF_INET, A.iface_ip->c_str(), &mreq.imr_interface) != 1) {
                std::cerr << "Invalid --iface IP\n"; return false;
            }
        } else {
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        }
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            perror("setsockopt IP_ADD_MEMBERSHIP"); return false;
        }

        if (!A.out_path.empty()) {
            ofs.open(A.out_path, std::ios::binary | std::ios::trunc);
            if (!ofs) {
                std::cerr << "Failed to open --out file: " << A.out_path << "\n";
                return false;
            }
        }

        std::cerr << "Listening on group " << A.group << ":" << A.port
                  << (A.iface_ip ? (" via iface " + *A.iface_ip) : "")
                  << (A.out_path.empty() ? " (no file output)" : (" -> " + A.out_path))
                  << "\n";
        return true;
    }

    bool run() {
        // ════════════════════════════════════════════════════════════════════
        // HANDSHAKE — identical to PeelReceiver::run() handshake section.
        // Respond to SYN with SYN|ACK, then wait for START before data phase.
        // ════════════════════════════════════════════════════════════════════
        bool started = false;

        // rcv_nxt: the next segment seq we expect.
        // Starts at 0 (not yet in data phase); set to 1 on START (or implicit start).
        uint32_t rcv_nxt    = 0;
        uint64_t total_bytes = 0;

        // Out-of-order buffer: seq -> OooBufEntry {payload, tsval, retrans_id}.
        // Holds segments received ahead of rcv_nxt, up to A.ooo_buf entries.
        std::map<uint32_t, OooBufEntry> ooo_buf;

        // retrans_id of the most recently in-order-delivered segment.
        // Used in dup-ACKs and re-delivery ACKs so the sender's epoch filter
        // can correctly discard stale dup-ACKs after a retransmission.
        // Initialised to 1 (first epoch) before any data arrives.
        uint8_t last_inorder_retrans_id = 1;

        std::vector<uint8_t> buf(65536);

        auto deliberately_introducing_unreliability = true;

        while (true) {
            sockaddr_in peer{}; socklen_t alen = sizeof(peer);
            ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0,
                                 (sockaddr*)&peer, &alen);
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("recvfrom"); return false;
            }
            if ((size_t)n < sizeof(RmHeader)) continue;

            RmHeader h{};
            memcpy(&h, buf.data(), sizeof(h));
            if (!verify_header(h)) continue;

            uint16_t flags           = ntohs(h.flags);
            uint32_t seq             = ntohl(h.seq);
            uint32_t tsval           = ntohl(h.tsval);
            uint16_t sender_port_hdr = ntohs(h.src_port);
            uint8_t  retrans_id      = h.retrans_id;

            if (deliberately_introducing_unreliability && (std::rand() % 4)) {
                printf("skipping packet with sequence number %d", seq);
                continue; // ignore the incoming packet
            }

            // ACK destination: sender IP from packet, sender's bound port from header.
            sockaddr_in ack_to{};
            ack_to.sin_family   = AF_INET;
            ack_to.sin_addr     = peer.sin_addr;
            ack_to.sin_port     = htons(sender_port_hdr);

            // ════════════════════════════════════════════════════════════════
            // SYN — identical to peel_receiver
            // ════════════════════════════════════════════════════════════════
            if (flags & FLG_SYN) {
                // Advertise the full ooo buffer as the initial window.
                uint16_t adv_wnd = (uint16_t)std::min(A.ooo_buf, (uint32_t)0xFFFFu);
                send_ack(ack_to, /*seq*/0, FLG_SYN | FLG_ACK, tsval, retrans_id, adv_wnd);
                continue;
            }

            // ════════════════════════════════════════════════════════════════
            // START — identical to peel_receiver
            // ════════════════════════════════════════════════════════════════
            if (flags & FLG_START) {
                started  = true;
                rcv_nxt  = 1; // first expected DATA seq
                std::cerr << "START received. Entering data phase.\n";
                continue;
            }

            // ════════════════════════════════════════════════════════════════
            // Implicit START: DATA or FIN arrived before we saw a START frame.
            // The sender's START multicast was likely lost in transit.
            // Enter data phase now and fall through to the normal handler below.
            // ════════════════════════════════════════════════════════════════
            if (!started && (flags & (FLG_DATA | FLG_FIN))) {
                started = true;
                rcv_nxt = 1; // assume first expected seq is 1
                std::cerr << "DATA/FIN arrived before START — "
                             "inferring START was lost; entering data phase implicitly.\n";
                // Fall through to DATA / FIN handler below (no continue here).
            }

            // ════════════════════════════════════════════════════════════════
            // DATA — CHANGED: sliding-window with cumulative ACKs and OOO buffer
            // ════════════════════════════════════════════════════════════════
            if (flags & FLG_DATA) {
                size_t app_len = (size_t)n - sizeof(RmHeader);

                // Compute the advertised window for this ACK up front.
                uint16_t adv_wnd = advertised_window(ooo_buf.size());

                if (seq == rcv_nxt) {
                    // ── In-order segment ──────────────────────────────────────
                    if (app_len > 0) {
                        write_payload(buf.data() + sizeof(RmHeader), app_len);
                        total_bytes += app_len;
                    }
                    // Track the last in-order delivered packet's epoch so that
                    // dup-ACKs and re-delivery ACKs echo the correct retrans_id.
                    // (R2) The dup-ACK retrans_id filter in the sender's aggregator
                    // compares against slot[peer_prev].retrans_id, which is the
                    // epoch of the LOST packet.  Echoing the OOO packet's
                    // retrans_id mixes up unrelated epochs.  The last in-order
                    // packet's retrans_id is the closest proxy for the loss boundary.
                    last_inorder_retrans_id = retrans_id;
                    rcv_nxt++;

                    // (R1) Track ack_tsval / ack_retrans_id as we drain so the
                    // cumulative ACK reflects the LAST delivered segment, not just
                    // the initial trigger packet.  This matters for Karn's algorithm:
                    // tsecr must match the tsval of the packet at rcv_nxt-1.
                    uint32_t ack_tsval      = tsval;
                    uint8_t  ack_retrans_id = retrans_id;

                    // Drain any contiguous out-of-order segments now deliverable.
                    while (!ooo_buf.empty()) {
                        auto it = ooo_buf.begin();
                        if (it->first != rcv_nxt) break;
                        write_payload(it->second.payload.data(), it->second.payload.size());
                        total_bytes += it->second.payload.size();
                        // Update ACK echo fields to the last drained entry.
                        ack_tsval               = it->second.tsval;
                        ack_retrans_id          = it->second.retrans_id;
                        last_inorder_retrans_id = it->second.retrans_id;
                        ooo_buf.erase(it);
                        rcv_nxt++;
                    }

                    // Recompute after drain (ooo_buf may have shrunk).
                    adv_wnd = advertised_window(ooo_buf.size());

                    // Cumulative ACK: echo tsval/retrans_id of the LAST delivered
                    // packet (trigger or last OOO drain entry).
                    send_ack(ack_to, rcv_nxt, FLG_ACK, ack_tsval, ack_retrans_id, adv_wnd);

                    std::cerr << "DATA seq=" << seq
                              << " len=" << app_len
                              << " -> in-order, rcv_nxt=" << rcv_nxt
                              << " total=" << total_bytes << " B"
                              << " adv_wnd=" << adv_wnd << "\n";

                } else if (seq > rcv_nxt) {
                    // ── Out-of-order segment ──────────────────────────────────
                    if (ooo_buf.size() < A.ooo_buf && !ooo_buf.count(seq)) {
                        // Buffer payload together with timing/epoch fields (R1).
                        ooo_buf[seq] = OooBufEntry{
                            std::vector<uint8_t>(
                                buf.begin() + sizeof(RmHeader),
                                buf.begin() + sizeof(RmHeader) + app_len),
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

                    // Duplicate ACK: rcv_nxt unchanged.
                    // (R2) Echo last_inorder_retrans_id (epoch of the packet just
                    // before the gap) rather than the OOO packet's retrans_id.
                    // The sender's dup-ACK epoch filter checks slot[peer_prev],
                    // which corresponds to the lost packet near rcv_nxt, not the
                    // OOO packet's epoch.
                    adv_wnd = advertised_window(ooo_buf.size());
                    send_ack(ack_to, rcv_nxt, FLG_ACK, tsval,
                             last_inorder_retrans_id, adv_wnd);

                } else {
                    // ── Already-delivered duplicate ───────────────────────────
                    // Re-ACK with current rcv_nxt.
                    // (R2) Echo last_inorder_retrans_id: the re-delivered packet's
                    // retrans_id may be from an old epoch, causing the sender's
                    // aggregator to discard the ACK as stale.
                    send_ack(ack_to, rcv_nxt, FLG_ACK, tsval,
                             last_inorder_retrans_id, adv_wnd);
                    std::cerr << "DATA seq=" << seq
                              << " already delivered -> re-ACK rcv_nxt=" << rcv_nxt << "\n";
                }
                continue;
            }

            // ════════════════════════════════════════════════════════════════
            // FIN — identical to peel_receiver
            // ACK.seq = fin_seq (echo style, NOT cumulative) so the sender's
            // unmodified wait_all_acks() can match it.
            // ════════════════════════════════════════════════════════════════
            if (flags & FLG_FIN) {
                // Flush any remaining OOO data before closing.
                for (auto& [s, entry] : ooo_buf) {
                    write_payload(entry.payload.data(), entry.payload.size());
                    total_bytes += entry.payload.size();
                }
                ooo_buf.clear();

                // Echo fin_seq (NOT rcv_nxt) to stay compatible with wait_all_acks.
                // Window field is irrelevant at teardown; send 1.
                send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id, /*adv_wnd*/1);

                std::cerr << "FIN seq=" << seq
                          << " -> ACKed. Total received=" << total_bytes << " bytes\n";
                return true;
            }
        }
        return true;
    }

private:
    // ─── Helpers — identical to peel_receiver ────────────────────────────────

    bool verify_header(const RmHeader& net) {
        RmHeader tmp = net; uint16_t r = tmp.checksum;
        tmp.checksum = 0;
        return r == checksum16(&tmp, sizeof(tmp));
    }

    // send_ack — adv_wnd is placed in h.window for receiver flow control.
    // For DATA ACKs: retrans_id_in echoes the retrans_id from the incoming DATA
    //   packet so the sender can apply Karn's algorithm.
    // For FIN ACKs: retrans_id_in echoes the FIN's retrans_id (as before).
    // For SYN|ACK: retrans_id_in echoes the SYN's retrans_id (as before).
    void send_ack(const sockaddr_in& to, uint32_t seq, uint16_t flags,
                  uint32_t tsecr_in, uint8_t retrans_id_in, uint16_t adv_wnd) {
        RmHeader a{};
        a.seq        = htonl(seq);
        a.src_port   = htons(local_port());
        a.flags      = htons(flags);
        a.retrans_id = retrans_id_in;
        a.reserved   = 0;
        a.window     = htons(adv_wnd); // advertised receive window
        a.checksum   = 0;
        a.tsval      = htonl(now_ms());
        a.tsecr      = htonl(tsecr_in);

        RmHeader tmp = a; tmp.checksum = 0;
        a.checksum = checksum16(&tmp, sizeof(tmp));

        ssize_t n = sendto(fd, &a, sizeof(a), 0,
                           (const sockaddr*)&to, sizeof(to));
        if (n < 0) perror("sendto ACK");
    }

    // Remaining space in the ooo buffer, expressed as a segment count.
    // Always returns at least 1 to prevent the sender from stalling.
    uint16_t advertised_window(size_t ooo_used) const {
        if (ooo_used >= A.ooo_buf) return 1; // always allow at least 1
        return (uint16_t)(A.ooo_buf - ooo_used);
    }

    void write_payload(const uint8_t* data, size_t len) {
        if (len > 0 && ofs.is_open())
            ofs.write(reinterpret_cast<const char*>(data), (std::streamsize)len);
    }

    uint16_t local_port() const {
        sockaddr_in sa{}; socklen_t sl = sizeof(sa);
        if (getsockname(fd, (sockaddr*)&sa, &sl) == 0) return ntohs(sa.sin_port);
        return 0;
    }

private:
    Args          A;
    int           fd = -1;
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
