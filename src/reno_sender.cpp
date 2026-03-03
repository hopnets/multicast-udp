// Userspace TCP Reno unicast sender over UDP.
//
// Protocol:
//   1. 3-way handshake : SYN -> SYN|ACK -> ACK
//   2. Sliding-window data transfer with TCP Reno congestion control
//      - Slow start, congestion avoidance, fast retransmit / fast recovery
//      - RTT estimation: Jacobson/Karels algorithm with Karn's fix
//      - RTO exponential backoff on loss
//   3. FIN -> ACK teardown
//
// Header: 24-byte RenoHeader (seq, ack_num, src_port, flags, window, checksum, tsval, tsecr)
//
// Sequence numbering (chunk-level, like segments):
//   - SYN     : seq = 0  (ISN)
//   - Data    : seq = 1, 2, ... N
//   - FIN     : seq = N + 1
//   - ACK num : next expected seq (cumulative)
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o reno_sender reno_sender.cpp
//
// Example:
//   ./reno_sender --host 10.0.0.2 --port 5100 --sender-port 45100 \
//                 --file payload.bin --rto-ms 200 --chunk 1450

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
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

// ─── Args ─────────────────────────────────────────────────────────────────────
struct Args {
    std::string host        = "127.0.0.1";
    uint16_t    port        = 5100;         // receiver listen port
    uint16_t    sender_port = 45100;        // local bind port for sending / receiving ACKs
    std::string file;                       // optional payload file
    int         rto_ms      = 200;          // initial RTO in ms
    int         retries     = 20;           // max consecutive timeouts before giving up
    size_t      max_chunk   = 1450;         // max application payload bytes per segment
    uint16_t    rwnd        = 64;           // advertised receive window we send in our headers
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --host IP --port P --sender-port S"
              << " [--file path] [--rto-ms MS] [--retries K]"
              << " [--chunk BYTES] [--rwnd N]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more) {
            if (i + more >= argc) { usage(argv[0]); return false; }
            return true;
        };
        if      (s == "--host"        && need(1)) a.host        = argv[++i];
        else if (s == "--port"        && need(1)) a.port        = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--sender-port" && need(1)) a.sender_port = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--file"        && need(1)) a.file        = argv[++i];
        else if (s == "--rto-ms"      && need(1)) a.rto_ms      = std::stoi(argv[++i]);
        else if (s == "--retries"     && need(1)) a.retries     = std::stoi(argv[++i]);
        else if (s == "--chunk"       && need(1)) a.max_chunk   = (size_t)std::stoul(argv[++i]);
        else if (s == "--rwnd"        && need(1)) a.rwnd        = (uint16_t)std::stoi(argv[++i]);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown argument: " << s << "\n"; usage(argv[0]); return false; }
    }
    if (a.max_chunk < 1 || a.max_chunk > 65507 - sizeof(RenoHeader)) {
        std::cerr << "--chunk must be 1.." << (65507 - sizeof(RenoHeader)) << "\n";
        return false;
    }
    return true;
}

// ─── In-flight segment record ─────────────────────────────────────────────────
struct SegInfo {
    uint32_t             seq;
    std::vector<uint8_t> payload;          // application bytes (empty for FIN)
    uint16_t             flags;            // FLG_DATA or FLG_FIN
    Clock::time_point    sent_at;          // time of most recent transmission
    uint32_t             tsval;            // timestamp at last transmission (Karn's)
    bool                 is_retransmit = false;
};

// ─── Congestion control state ─────────────────────────────────────────────────
enum class CCState { SLOW_START, CONG_AVOIDANCE, FAST_RECOVERY };

static const char* cc_name(CCState s) {
    switch (s) {
        case CCState::SLOW_START:     return "SS";
        case CCState::CONG_AVOIDANCE: return "CA";
        case CCState::FAST_RECOVERY:  return "FR";
    }
    return "?";
}

// ─── RenoSender ───────────────────────────────────────────────────────────────
class RenoSender {
public:
    explicit RenoSender(const Args& args) : A(args), rto_ms(args.rto_ms) {}
    ~RenoSender() { if (fd >= 0) close(fd); }

    bool init() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return false; }

        sockaddr_in local{};
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port        = htons(A.sender_port);
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) {
            perror("bind sender_port"); return false;
        }

        memset(&peer, 0, sizeof(peer));
        peer.sin_family = AF_INET;
        peer.sin_port   = htons(A.port);
        if (inet_pton(AF_INET, A.host.c_str(), &peer.sin_addr) != 1) {
            std::cerr << "Invalid --host IP: " << A.host << "\n"; return false;
        }

        std::cerr << "Bound on :" << A.sender_port
                  << ", connecting to " << A.host << ":" << A.port << "\n";
        return true;
    }

    bool run() {
        if (!handshake()) return false;

        if (!A.file.empty()) {
            if (!load_file(A.file)) return false;
        } else {
            // Demo mode: 5 small messages
            for (int i = 1; i <= 5; ++i) {
                std::string msg = "hello-" + std::to_string(i);
                all_segs.emplace_back(msg.begin(), msg.end());
            }
        }

        std::cerr << "Starting transfer: " << all_segs.size() << " segment(s), "
                  << total_bytes() << " bytes\n";

        if (!transfer()) return false;

        std::cerr << "Transfer complete. Sending FIN.\n";
        return teardown();
    }

private:
    // ─── Handshake (SYN -> SYN|ACK -> ACK) ──────────────────────────────────
    bool handshake() {
        auto hs_start = Clock::now();
        auto elapsed_us = [&]() -> long long {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - hs_start).count();
        };

        for (int attempt = 0; attempt <= A.retries; ++attempt) {
            uint32_t ts = now_ms();
            RenoHeader h{};
            fill_header(h, /*seq*/0, /*ack_num*/0, FLG_SYN, A.rwnd, ts, /*tsecr*/0);
            if (!send_hdr(h, nullptr, 0)) return false;

            std::cerr << "SYN sent (attempt " << (attempt + 1) << ")\n";

            auto deadline = Clock::now() + std::chrono::milliseconds(rto_ms);
            while (Clock::now() < deadline) {
                uint8_t buf[sizeof(RenoHeader) + 16];
                sockaddr_in from{};
                ssize_t n = 0;
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - Clock::now());
                int r = recv_timed(buf, sizeof(buf), from, n, rem);
                if (r <= 0) break;
                if ((size_t)n < sizeof(RenoHeader)) continue;

                RenoHeader rh{};
                memcpy(&rh, buf, sizeof(rh));
                if (!verify_header(rh)) continue;

                uint16_t flags = ntohs(rh.flags);
                if ((flags & (FLG_SYN | FLG_ACK)) != (FLG_SYN | FLG_ACK)) continue;
                if (ntohl(rh.tsecr) != ts) continue; // must echo our SYN tsval

                // Valid SYN|ACK received
                peer_rwnd = ntohs(rh.window);
                if (peer_rwnd < 1) peer_rwnd = 1;

                // Bootstrap RTT estimate from handshake
                int sample = (int)(now_ms() - ts);
                update_rtt(sample);

                auto us = elapsed_us();
                std::cerr << "SYN|ACK received in " << us << " us ("
                          << (us / 1000.0) << " ms). peer_rwnd=" << peer_rwnd
                          << " rto=" << rto_ms << " ms\n";

                // Complete 3-way handshake
                uint32_t ack_ts = now_ms();
                RenoHeader ack{};
                fill_header(ack, /*seq*/1, /*ack_num*/1, FLG_ACK, A.rwnd,
                            ack_ts, ntohl(rh.tsval));
                if (!send_hdr(ack, nullptr, 0)) return false;

                std::cerr << "ACK sent. Handshake complete in "
                          << elapsed_us() << " us.\n";
                return true;
            }

            std::cerr << "  no SYN|ACK -> retrying (rto=" << rto_ms << " ms)\n";
            rto_ms = std::min(rto_ms * 2, kMaxRtoMs);
        }

        std::cerr << "Handshake failed after " << elapsed_us() << " us\n";
        return false;
    }

    // ─── Load file into segment vector ───────────────────────────────────────
    bool load_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Cannot open file: " << path << "\n"; return false; }
        std::vector<uint8_t> buf(A.max_chunk);
        while (true) {
            f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
            std::streamsize got = f.gcount();
            if (got <= 0) break;
            all_segs.emplace_back(buf.begin(), buf.begin() + got);
        }
        return true;
    }

    size_t total_bytes() const {
        size_t n = 0;
        for (auto& s : all_segs) n += s.size();
        return n;
    }

    // ─── Sliding-window transfer with TCP Reno ────────────────────────────────
    // Data segments use seq = 1 .. all_segs.size().
    // snd_una  = oldest unACKed segment seq (starts at 1 after handshake).
    // snd_nxt  = next segment seq to send.
    // Loop exits when snd_una > total (all data ACKed).
    bool transfer() {
        uint32_t total = (uint32_t)all_segs.size();
        snd_una = 1;
        snd_nxt = 1;
        int consec_timeouts = 0;

        while (snd_una <= total) {
            // Fill the send window with new segments
            uint32_t eff = eff_wnd();
            while (snd_nxt <= total && (uint32_t)in_flight.size() < eff) {
                if (!send_new(snd_nxt)) return false;
                snd_nxt++;
                eff = eff_wnd(); // cwnd may have just become a stricter limit
            }

            if (in_flight.empty()) break; // safety: shouldn't reach if snd_una <= total

            // Compute time until the oldest in-flight segment expires
            auto& oldest  = in_flight.begin()->second;
            auto  expiry  = oldest.sent_at + std::chrono::milliseconds(rto_ms);
            auto  wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                expiry - Clock::now());
            if (wait_ms.count() < 0) wait_ms = std::chrono::milliseconds(0);

            uint8_t   buf[sizeof(RenoHeader) + 65536];
            sockaddr_in from{};
            ssize_t   n  = 0;
            int       r  = recv_timed(buf, sizeof(buf), from, n, wait_ms);

            if (r < 0) return false; // socket error

            if (r == 0) {
                // RTO timeout
                consec_timeouts++;
                if (consec_timeouts > A.retries) {
                    std::cerr << "Transfer failed: " << A.retries
                              << " consecutive timeouts\n";
                    return false;
                }
                if (!on_timeout()) return false;
                continue;
            }

            // Received a packet - validate it
            if ((size_t)n < sizeof(RenoHeader)) continue;
            RenoHeader rh{};
            memcpy(&rh, buf, sizeof(rh));
            if (!verify_header(rh)) continue;
            uint16_t flags = ntohs(rh.flags);
            if ((flags & FLG_ACK) == 0) continue;
            if (from.sin_addr.s_addr != peer.sin_addr.s_addr) continue;

            on_ack(rh);
            consec_timeouts = 0;
        }
        return true;
    }

    // ─── FIN + ACK teardown ───────────────────────────────────────────────────
    bool teardown() {
        uint32_t fin_seq = (uint32_t)all_segs.size() + 1;

        for (int attempt = 0; attempt <= A.retries; ++attempt) {
            uint32_t ts = now_ms();
            RenoHeader h{};
            fill_header(h, fin_seq, /*ack_num*/0, FLG_FIN, 0, ts, /*tsecr*/0);
            if (!send_hdr(h, nullptr, 0)) return false;

            std::cerr << "FIN seq=" << fin_seq
                      << " (attempt " << (attempt + 1) << ")\n";

            auto deadline = Clock::now() + std::chrono::milliseconds(rto_ms);
            while (Clock::now() < deadline) {
                uint8_t buf[sizeof(RenoHeader) + 16];
                sockaddr_in from{};
                ssize_t n = 0;
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - Clock::now());
                int r = recv_timed(buf, sizeof(buf), from, n, rem);
                if (r <= 0) break;
                if ((size_t)n < sizeof(RenoHeader)) continue;

                RenoHeader rh{};
                memcpy(&rh, buf, sizeof(rh));
                if (!verify_header(rh)) continue;
                uint16_t flags = ntohs(rh.flags);
                if ((flags & FLG_ACK) == 0) continue;
                if (ntohl(rh.ack_num) != fin_seq + 1) continue;

                std::cerr << "FIN ACKed. Connection closed.\n";
                return true;
            }

            std::cerr << "  timeout waiting FIN ACK -> retransmit\n";
            rto_ms = std::min(rto_ms * 2, kMaxRtoMs);
        }

        std::cerr << "FIN not ACKed after retries\n";
        return false;
    }

    // ─── Congestion control: process incoming ACK ─────────────────────────────
    void on_ack(const RenoHeader& rh) {
        uint32_t ack = ntohl(rh.ack_num);

        if (ack < snd_una) return; // old ACK, ignore

        if (ack == snd_una) {
            // Duplicate ACK
            dup_ack_count++;
            std::cerr << "  dup-ACK ack=" << ack
                      << " count=" << dup_ack_count
                      << " cwnd=" << cwnd
                      << " [" << cc_name(cc_state) << "]\n";

            if (cc_state == CCState::FAST_RECOVERY) {
                // Each dup-ACK in FR allows one more new segment out
                cwnd += 1.0;
            } else if (dup_ack_count == 3) {
                // Fast retransmit trigger
                ssthresh = std::max(cwnd / 2.0, 2.0);
                cwnd     = ssthresh + 3.0;
                cc_state = CCState::FAST_RECOVERY;
                std::cerr << "  FAST RETRANSMIT seq=" << snd_una
                          << " ssthresh=" << ssthresh
                          << " cwnd=" << cwnd << "\n";
                retransmit(snd_una);
            }
            return;
        }

        // New ACK (ack > snd_una)
        dup_ack_count = 0;

        // Karn's algorithm: only update RTT if none of the ACKed segments were
        // retransmitted.  Use tsecr as the send-time base for the sample.
        bool any_retransmit = false;
        for (auto& kv : in_flight) {
            if (kv.first < ack && kv.second.is_retransmit) {
                any_retransmit = true;
                break;
            }
        }
        uint32_t tsecr = ntohl(rh.tsecr);
        if (!any_retransmit && tsecr != 0) {
            int sample_ms = (int)(now_ms() - tsecr);
            if (sample_ms >= 0 && sample_ms < kMaxRtoMs)
                update_rtt(sample_ms);
        }

        // Remove all ACKed segments from in_flight, advance snd_una
        auto it = in_flight.begin();
        while (it != in_flight.end() && it->first < ack)
            it = in_flight.erase(it);
        snd_una = ack;

        // Update congestion window
        if (cc_state == CCState::SLOW_START) {
            cwnd += 1.0;
            if (cwnd >= ssthresh) cc_state = CCState::CONG_AVOIDANCE;
        } else if (cc_state == CCState::CONG_AVOIDANCE) {
            cwnd += 1.0 / cwnd; // linear: +1 segment per RTT
        } else if (cc_state == CCState::FAST_RECOVERY) {
            cwnd     = ssthresh; // deflate on new ACK exiting recovery
            cc_state = CCState::CONG_AVOIDANCE;
        }

        // Honour peer's advertised window
        uint16_t adv = ntohs(rh.window);
        if (adv > 0) peer_rwnd = adv;

        std::cerr << "  ACK ack=" << ack
                  << " in_flight=" << in_flight.size()
                  << " cwnd=" << cwnd
                  << " ssthresh=" << ssthresh
                  << " rto=" << rto_ms
                  << " [" << cc_name(cc_state) << "]\n";
    }

    // ─── Congestion control: RTO timeout ─────────────────────────────────────
    bool on_timeout() {
        std::cerr << "  RTO timeout snd_una=" << snd_una
                  << " cwnd=" << cwnd << " -> slow start\n";
        ssthresh        = std::max(cwnd / 2.0, 2.0);
        cwnd            = 1.0;
        cc_state        = CCState::SLOW_START;
        dup_ack_count   = 0;
        rto_ms          = std::min(rto_ms * 2, kMaxRtoMs);
        return retransmit(snd_una);
    }

    // ─── RTT estimation (Jacobson/Karels, RFC 6298) ───────────────────────────
    void update_rtt(int sample_ms) {
        if (sample_ms < 0) sample_ms = 0;
        if (!rtt_init) {
            srtt_ms  = (double)sample_ms;
            rttvar_ms = (double)sample_ms / 2.0;
            rtt_init = true;
        } else {
            double diff = std::abs(srtt_ms - (double)sample_ms);
            rttvar_ms   = 0.75 * rttvar_ms + 0.25 * diff;
            srtt_ms     = 0.875 * srtt_ms  + 0.125 * (double)sample_ms;
        }
        rto_ms = std::max(kMinRtoMs,
                          (int)std::ceil(srtt_ms + 4.0 * rttvar_ms));
        rto_ms = std::min(rto_ms, kMaxRtoMs);
    }

    // ─── Effective send window (min of cwnd and peer's rwnd) ─────────────────
    uint32_t eff_wnd() const {
        double w = std::min(cwnd, (double)peer_rwnd);
        return (uint32_t)std::max(1.0, w);
    }

    // ─── Send a new data segment ──────────────────────────────────────────────
    bool send_new(uint32_t seq) {
        SegInfo seg{};
        seg.seq           = seq;
        seg.payload       = all_segs[seq - 1]; // seq is 1-indexed
        seg.flags         = FLG_DATA;
        seg.is_retransmit = false;
        seg.tsval         = now_ms();
        seg.sent_at       = Clock::now();

        RenoHeader h{};
        fill_header(h, seq, /*ack_num*/0, FLG_DATA, A.rwnd, seg.tsval, /*tsecr*/0);
        if (!send_hdr(h, seg.payload.data(), seg.payload.size())) return false;

        in_flight[seq] = std::move(seg);

        std::cerr << "  -> DATA seq=" << seq
                  << " len=" << in_flight[seq].payload.size()
                  << " cwnd=" << cwnd
                  << " in_flight=" << in_flight.size() << "\n";
        return true;
    }

    // ─── Retransmit an in-flight segment ─────────────────────────────────────
    bool retransmit(uint32_t seq) {
        auto it = in_flight.find(seq);
        if (it == in_flight.end()) return true; // nothing to retransmit
        SegInfo& seg      = it->second;
        seg.is_retransmit = true;
        seg.tsval         = now_ms();
        seg.sent_at       = Clock::now();

        RenoHeader h{};
        fill_header(h, seq, /*ack_num*/0, seg.flags, A.rwnd, seg.tsval, /*tsecr*/0);
        if (!send_hdr(h, seg.payload.data(), seg.payload.size())) return false;

        std::cerr << "  -> RETRANSMIT seq=" << seq
                  << " len=" << seg.payload.size() << "\n";
        return true;
    }

    // ─── Header helpers ───────────────────────────────────────────────────────
    void fill_header(RenoHeader& h, uint32_t seq, uint32_t ack_num,
                     uint16_t flags, uint16_t wnd,
                     uint32_t tsval, uint32_t tsecr) const {
        h.seq      = htonl(seq);
        h.ack_num  = htonl(ack_num);
        h.src_port = htons(A.sender_port);
        h.flags    = htons(flags);
        h.window   = htons(wnd);
        h.checksum = 0;
        h.tsval    = htonl(tsval);
        h.tsecr    = htonl(tsecr);
    }

    bool send_hdr(RenoHeader& h, const uint8_t* payload, size_t plen) {
        RenoHeader tmp = h;
        tmp.checksum = 0;
        h.checksum = checksum16(&tmp, sizeof(tmp));

        std::vector<uint8_t> pkt(sizeof(RenoHeader) + plen);
        memcpy(pkt.data(), &h, sizeof(h));
        if (plen > 0) memcpy(pkt.data() + sizeof(h), payload, plen);

        ssize_t n = sendto(fd, pkt.data(), pkt.size(), 0,
                           (sockaddr*)&peer, sizeof(peer));
        if (n < 0) { perror("sendto"); return false; }
        if ((size_t)n != pkt.size()) {
            std::cerr << "Partial send: sent=" << n
                      << " expected=" << pkt.size() << "\n";
            return false;
        }
        return true;
    }

    bool verify_header(const RenoHeader& net) const {
        RenoHeader tmp = net;
        uint16_t rcv  = tmp.checksum;
        tmp.checksum  = 0;
        return rcv == checksum16(&tmp, sizeof(tmp));
    }

    // recv_timed: returns 1=packet received, 0=timeout, -1=error
    int recv_timed(uint8_t* buf, size_t buflen, sockaddr_in& from,
                   ssize_t& n, std::chrono::milliseconds timeout) const {
        if (timeout.count() < 0)
            timeout = std::chrono::milliseconds(0);

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv{};
        tv.tv_sec  = (long)(timeout.count() / 1000);
        tv.tv_usec = (long)((timeout.count() % 1000) * 1000);

        int r = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (r < 0) {
            if (errno == EINTR) return 0;
            perror("select");
            return -1;
        }
        if (r == 0) return 0;

        socklen_t alen = sizeof(from);
        n = recvfrom(fd, buf, buflen, 0, (sockaddr*)&from, &alen);
        if (n < 0) { perror("recvfrom"); return -1; }
        return 1;
    }

private:
    // Config
    Args         A;
    int          fd  = -1;
    sockaddr_in  peer{};

    // Connection state
    uint16_t     peer_rwnd = 1;
    uint32_t     snd_una   = 1;
    uint32_t     snd_nxt   = 1;
    std::map<uint32_t, SegInfo> in_flight; // keyed by seq, ordered by seq

    // All data to send (pre-loaded)
    std::vector<std::vector<uint8_t>> all_segs;

    // Congestion control
    double  cwnd          = 1.0;
    double  ssthresh      = 64.0;
    CCState cc_state      = CCState::SLOW_START;
    int     dup_ack_count = 0;

    // RTT / RTO
    double srtt_ms    = 0.0;
    double rttvar_ms  = 0.0;
    int    rto_ms;          // initialised from Args in constructor
    bool   rtt_init   = false;

    static constexpr int kMinRtoMs = 50;
    static constexpr int kMaxRtoMs = 60000;
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    RenoSender s(args);
    if (!s.init()) return 2;
    if (!s.run()) return 3;
    return 0;
}
