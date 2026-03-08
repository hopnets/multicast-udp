// Userspace TCP Reno unicast receiver over UDP.
//
// Behavior:
//   1. Binds to --port and waits for a SYN from the sender.
//   2. Replies with SYN|ACK (echoing sender's tsval), waits for the ACK to
//      complete the 3-way handshake.
//   3. Receives DATA segments.  In-order segments are delivered to --out file
//      (or discarded if no file given).  Out-of-order segments are buffered and
//      delivered as soon as the gap is filled.
//   4. Sends a cumulative ACK after every received segment (no delayed ACKs),
//      advertising the receive window in every ACK.
//   5. On receiving FIN, flushes any buffered data, sends ACK, and exits.
//
// ACKs are unicast to the sender's IP (from packet source) and the port found
// in the header's src_port field.
//
// Header: same 24-byte RenoHeader as reno_sender.cpp.
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o reno_receiver reno_receiver.cpp
//
// Example:
//   ./reno_receiver --port 5100 --out received.bin --rwnd 64

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// ─── Protocol header (24 bytes) ──────────────────────────────────────────────
#pragma pack(push, 1)
struct RenoHeader {
    uint32_t seq;       // Sequence number (chunk-level, network order)
    uint32_t ack_num;   // Cumulative acknowledgment number (network order)
    uint16_t src_port;  // Sender's bound port for reverse-path ACKs (network order)
    uint16_t flags;     // Bit flags (network order)
    uint16_t window;    // Advertised receive window in segments (network order)
    uint16_t checksum;  // Internet checksum over header (field = 0 when computing)
    uint32_t tsval;     // Sender timestamp in ms, monotonic (network order)
    uint32_t tsecr;     // Echoed timestamp from peer (network order)
};
#pragma pack(pop)
static_assert(sizeof(RenoHeader) == 24, "RenoHeader must be 24 bytes");

enum : uint16_t {
    FLG_SYN  = 0x0001,
    FLG_ACK  = 0x0002,
    FLG_DATA = 0x0008,
    FLG_FIN  = 0x0010,
    FLG_RST  = 0x0020,
};

// ─── Utilities ───────────────────────────────────────────────────────────────
static uint32_t now_ms() {
    auto now = Clock::now().time_since_epoch();
    return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

static uint16_t checksum16(const void* data, size_t len) {
    // Internet checksum (RFC 1071)
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

static std::string addr_str(const sockaddr_in& a) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
    char out[64];
    snprintf(out, sizeof(out), "%s:%u", buf, ntohs(a.sin_port));
    return std::string(out);
}

// ─── Args ─────────────────────────────────────────────────────────────────────
struct Args {
    uint16_t    port     = 5100;             // UDP listen port
    std::string out_path;                    // optional output file
    int         rcvbuf   = 4 * 1024 * 1024; // SO_RCVBUF size
    uint16_t    rwnd     = 64;               // advertised receive window (segments)
    int         rto_ms   = 500;              // handshake SYN|ACK retransmit timeout
    int         retries  = 20;               // max handshake retries
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --port P [--out file] [--rcvbuf BYTES]"
              << " [--rwnd N] [--rto-ms MS] [--retries K]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more) {
            if (i + more >= argc) { usage(argv[0]); return false; }
            return true;
        };
        if      (s == "--port"    && need(1)) a.port     = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--out"     && need(1)) a.out_path = argv[++i];
        else if (s == "--rcvbuf"  && need(1)) a.rcvbuf   = std::stoi(argv[++i]);
        else if (s == "--rwnd"    && need(1)) a.rwnd     = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--rto-ms"  && need(1)) a.rto_ms   = std::stoi(argv[++i]);
        else if (s == "--retries" && need(1)) a.retries  = std::stoi(argv[++i]);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown argument: " << s << "\n"; usage(argv[0]); return false; }
    }
    return true;
}

// ─── RenoReceiver ─────────────────────────────────────────────────────────────
class RenoReceiver {
public:
    explicit RenoReceiver(const Args& args) : A(args) {}
    ~RenoReceiver() {
        if (fd >= 0) close(fd);
        if (ofs.is_open()) ofs.close();
    }

    bool init() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return false; }

        int yes = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            perror("setsockopt SO_REUSEADDR"); return false;
        }
        if (A.rcvbuf > 0) {
            if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &A.rcvbuf, sizeof(A.rcvbuf)) < 0)
                perror("setsockopt SO_RCVBUF"); // non-fatal
        }

        sockaddr_in local{};
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port        = htons(A.port);
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) {
            perror("bind"); return false;
        }

        if (!A.out_path.empty()) {
            ofs.open(A.out_path, std::ios::binary | std::ios::trunc);
            if (!ofs) {
                std::cerr << "Failed to open --out file: " << A.out_path << "\n";
                return false;
            }
        }

        std::cerr << "Listening on port " << A.port
                  << (A.out_path.empty() ? " (no file output)" : (" -> " + A.out_path))
                  << "\n";
        return true;
    }

    bool run() {
        if (!handshake()) return false;
        return recv_loop();
    }

private:
    // ─── 3-way handshake (passive open) ──────────────────────────────────────
    // Waits for SYN, sends SYN|ACK, waits for ACK.
    bool handshake() {
        std::cerr << "Waiting for SYN...\n";

        // Phase 1: wait for SYN, send SYN|ACK
        uint32_t syn_tsval = 0;
        bool got_syn = false;
        while (!got_syn) {
            std::vector<uint8_t> buf(sizeof(RenoHeader) + 16);
            sockaddr_in from{};
            socklen_t alen = sizeof(from);

            ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0,
                                 (sockaddr*)&from, &alen);
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("recvfrom SYN"); return false;
            }
            if ((size_t)n < sizeof(RenoHeader)) continue;

            RenoHeader rh{};
            memcpy(&rh, buf.data(), sizeof(rh));
            if (!verify_header(rh)) continue;

            uint16_t flags = ntohs(rh.flags);
            if (!(flags & FLG_SYN)) continue;

            // Record sender address: IP from packet, port from header's src_port
            sender.sin_family      = AF_INET;
            sender.sin_addr        = from.sin_addr;
            sender.sin_port        = rh.src_port; // already in network order

            syn_tsval = ntohl(rh.tsval);
            got_syn   = true;
            std::cerr << "SYN received from " << addr_str(from)
                      << " (ACKs -> :" << ntohs(sender.sin_port) << ")\n";
        }

        // Phase 2: send SYN|ACK and wait for ACK, retry if needed
        for (int attempt = 0; attempt <= A.retries; ++attempt) {
            uint32_t ts = now_ms();
            RenoHeader sa{};
            fill_ack(sa, /*seq*/0, /*ack_num*/1, FLG_SYN | FLG_ACK,
                     A.rwnd, ts, syn_tsval);
            send_pkt(sa, nullptr, 0);

            std::cerr << "SYN|ACK sent (attempt " << (attempt + 1) << ")\n";

            // Wait for ACK completing the handshake
            auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
            while (Clock::now() < deadline) {
                std::vector<uint8_t> buf(sizeof(RenoHeader) + 16);
                sockaddr_in from{};
                socklen_t alen = sizeof(from);

                // Short timeout so we can check deadline in the outer while
                struct timeval tv{};
                tv.tv_usec = 10000; // 10ms poll
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0,
                                     (sockaddr*)&from, &alen);
                // Remove timeout for data phase
                struct timeval notv{};
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));

                if (n < 0) {
                    if (errno == EWOULDBLOCK || errno == EAGAIN) continue;
                    if (errno == EINTR) continue;
                    perror("recvfrom handshake ACK"); return false;
                }
                if ((size_t)n < sizeof(RenoHeader)) continue;

                RenoHeader rh{};
                memcpy(&rh, buf.data(), sizeof(rh));
                if (!verify_header(rh)) continue;

                uint16_t flags = ntohs(rh.flags);

                // Sender may retransmit SYN while our SYN|ACK is in flight
                if (flags & FLG_SYN) {
                    std::cerr << "  SYN retransmit from sender, re-sending SYN|ACK\n";
                    uint32_t ts2 = now_ms();
                    RenoHeader sa2{};
                    fill_ack(sa2, 0, 1, FLG_SYN | FLG_ACK, A.rwnd, ts2,
                             ntohl(rh.tsval));
                    send_pkt(sa2, nullptr, 0);
                    continue;
                }

                if (!(flags & FLG_ACK)) continue;
                if (from.sin_addr.s_addr != sender.sin_addr.s_addr) continue;

                // Handshake complete
                std::cerr << "ACK received. Handshake complete. "
                          << "Entering data phase.\n";
                return true;
            }
            std::cerr << "  no ACK -> re-sending SYN|ACK\n";
        }

        std::cerr << "Handshake failed: no ACK after retries\n";
        return false;
    }

    // ─── Data receive loop ────────────────────────────────────────────────────
    // rcv_nxt: next expected sequence number (starts at 1 after handshake).
    // ooo_buf: out-of-order buffer for segments received ahead of rcv_nxt.
    //
    // ACK strategy: send ACK ack_num=rcv_nxt after every packet (no delay).
    //   - In-order DATA  : advance rcv_nxt, drain ooo_buf, then ACK new rcv_nxt.
    //   - Out-of-order   : buffer, send duplicate ACK (rcv_nxt unchanged).
    //   - Duplicate DATA : send ACK again (rcv_nxt unchanged).
    //   - FIN            : flush ooo_buf, send ACK ack_num=fin_seq+1, exit.
    bool recv_loop() {
        uint32_t rcv_nxt    = 1;    // next expected data seq
        uint64_t total_bytes = 0;
        std::map<uint32_t, std::vector<uint8_t>> ooo_buf; // out-of-order buffer
        uint32_t last_tsval = 0;    // most recent tsval seen (echoed in ACKs)

        std::vector<uint8_t> buf(65536);
        while (true) {
            sockaddr_in from{};
            socklen_t alen = sizeof(from);

            ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0,
                                 (sockaddr*)&from, &alen);
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("recvfrom data"); return false;
            }
            if ((size_t)n < sizeof(RenoHeader)) continue;

            // Only accept packets from the established sender
            if (from.sin_addr.s_addr != sender.sin_addr.s_addr) continue;

            RenoHeader rh{};
            memcpy(&rh, buf.data(), sizeof(rh));
            if (!verify_header(rh)) continue;

            uint16_t flags = ntohs(rh.flags);
            uint32_t seq   = ntohl(rh.seq);
            uint32_t tsval = ntohl(rh.tsval);

            // ACK destination: sender IP (already known) + src_port from header
            sockaddr_in ack_to{};
            ack_to.sin_family = AF_INET;
            ack_to.sin_addr   = sender.sin_addr;
            ack_to.sin_port   = rh.src_port; // network order

            if (flags & FLG_DATA) {
                last_tsval = tsval;

                if (seq == rcv_nxt) {
                    // In-order segment: deliver and drain ooo buffer
                    size_t app_len = (size_t)n - sizeof(RenoHeader);
                    if (app_len > 0) {
                        write_data(buf.data() + sizeof(RenoHeader), app_len);
                        total_bytes += app_len;
                    }
                    rcv_nxt++;

                    // Drain contiguous out-of-order segments
                    while (!ooo_buf.empty()) {
                        auto it = ooo_buf.begin();
                        if (it->first != rcv_nxt) break;
                        write_data(it->second.data(), it->second.size());
                        total_bytes += it->second.size();
                        ooo_buf.erase(it);
                        rcv_nxt++;
                    }

                    // Compute effective rwnd accounting for buffered segments
                    uint16_t adv_wnd = advertised_window(ooo_buf.size());
                    send_ack(ack_to, rcv_nxt, tsval, adv_wnd);

                    std::cerr << "DATA seq=" << seq
                              << " len=" << ((size_t)n - sizeof(RenoHeader))
                              << " -> delivered, rcv_nxt=" << rcv_nxt
                              << " total=" << total_bytes << " bytes\n";

                } else if (seq > rcv_nxt) {
                    // Out-of-order: buffer and send duplicate ACK
                    if (!ooo_buf.count(seq)) {
                        size_t app_len = (size_t)n - sizeof(RenoHeader);
                        ooo_buf[seq] = std::vector<uint8_t>(
                            buf.begin() + sizeof(RenoHeader),
                            buf.begin() + sizeof(RenoHeader) + app_len);
                        std::cerr << "DATA seq=" << seq
                                  << " out-of-order (expected " << rcv_nxt
                                  << ") -> buffered, dup-ACK " << rcv_nxt << "\n";
                    } else {
                        std::cerr << "DATA seq=" << seq
                                  << " out-of-order duplicate -> dup-ACK "
                                  << rcv_nxt << "\n";
                    }
                    uint16_t adv_wnd = advertised_window(ooo_buf.size());
                    send_ack(ack_to, rcv_nxt, tsval, adv_wnd);

                } else {
                    // seq < rcv_nxt: already delivered duplicate
                    std::cerr << "DATA seq=" << seq
                              << " duplicate (already delivered) -> re-ACK "
                              << rcv_nxt << "\n";
                    uint16_t adv_wnd = advertised_window(ooo_buf.size());
                    send_ack(ack_to, rcv_nxt, tsval, adv_wnd);
                }
                continue;
            }

            if (flags & FLG_FIN) {
                // Flush any remaining out-of-order data before closing
                // (best-effort: gaps left by lost packets won't be filled)
                for (auto& kv : ooo_buf) {
                    write_data(kv.second.data(), kv.second.size());
                    total_bytes += kv.second.size();
                }
                ooo_buf.clear();

                // ACK the FIN: ack_num = fin_seq + 1
                uint16_t adv_wnd = A.rwnd;
                send_ack(ack_to, seq + 1, tsval, adv_wnd);

                std::cerr << "FIN seq=" << seq
                          << " -> ACKed. Total received=" << total_bytes
                          << " bytes\n";
                return true;
            }
        }
        return true;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    // Compute advertised window, shrinking it by buffered out-of-order segments
    uint16_t advertised_window(size_t ooo_count) const {
        int avail = (int)A.rwnd - (int)ooo_count;
        if (avail < 1) avail = 1;
        return (uint16_t)avail;
    }

    void write_data(const uint8_t* data, size_t len) {
        if (len > 0 && ofs.is_open())
            ofs.write(reinterpret_cast<const char*>(data), (std::streamsize)len);
    }

    // Send a pure ACK to `to` with cumulative ack_num and echoed tsecr.
    void send_ack(const sockaddr_in& to, uint32_t ack_num,
                  uint32_t tsecr, uint16_t wnd) {
        RenoHeader a{};
        fill_ack(a, /*seq*/0, ack_num, FLG_ACK, wnd, now_ms(), tsecr);
        send_pkt(to, a, nullptr, 0);
    }

    void fill_ack(RenoHeader& h, uint32_t seq, uint32_t ack_num,
                  uint16_t flags, uint16_t wnd,
                  uint32_t tsval, uint32_t tsecr) const {
        h.seq      = htonl(seq);
        h.ack_num  = htonl(ack_num);
        h.src_port = htons(A.port);  // receiver's own port (informative)
        h.flags    = htons(flags);
        h.window   = htons(wnd);
        h.checksum = 0;
        h.tsval    = htonl(tsval);
        h.tsecr    = htonl(tsecr);
    }

    void send_pkt(const sockaddr_in& to, RenoHeader& h, const uint8_t* payload, size_t plen) {
        // Compute checksum over header with checksum=0
        RenoHeader tmp = h;
        tmp.checksum = 0;
        h.checksum   = checksum16(&tmp, sizeof(tmp));

        std::vector<uint8_t> pkt(sizeof(RenoHeader) + plen);
        memcpy(pkt.data(), &h, sizeof(h));
        if (plen > 0) memcpy(pkt.data() + sizeof(h), payload, plen);

        ssize_t n = sendto(fd, pkt.data(), pkt.size(), 0,
                           (sockaddr*)&to, sizeof(to));
        if (n < 0) perror("sendto ACK");
    }

    bool verify_header(const RenoHeader& net) const {
        RenoHeader tmp = net;
        uint16_t rcv  = tmp.checksum;
        tmp.checksum  = 0;
        return rcv == checksum16(&tmp, sizeof(tmp));
    }

private:
    Args        A;
    int         fd = -1;
    sockaddr_in sender{};   // established sender address (set during handshake)
    std::ofstream ofs;
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    RenoReceiver r(args);
    if (!r.init()) return 2;
    if (!r.run()) return 3;
    return 0;
}
