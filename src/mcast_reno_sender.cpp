// mcast_reno_sender.cpp
// Multicast reliable sender — sliding-window TCP Reno (three-component design).
//
// What is IDENTICAL to peel_sender.cpp:
//   - RmHeader, flags, all serialisation helpers
//   - init()      : socket creation, multicast options, SO_RCVTIMEO
//   - handshake() : SYN → cohort assembly → START   (line-for-line copy)
//   - send_fin()  : FIN multicast → wait_all_acks   (line-for-line copy)
//   - wait_all_acks(), xmit(), recv_header(),
//     fill_header(), serialize_header(), verify_header()
//
// Three-component design:
//
//  1. Reno State Machine (RenoSM)
//     - Owns cwnd, ssthresh, CC state, and recovery_point.
//     - Lives entirely in the main thread; no locking needed.
//     - on_first_ack()        : cwnd grows when the FIRST receiver ACKs a slot.
//     - on_recovery_ack()     : exit fast recovery when all receivers ACKed
//                               past recovery_point (committed_una > recovery_point).
//     - on_dup_ack_threshold(): enter fast recovery, record recovery_point.
//     - on_timeout()          : RTO timeout → slow start.
//
//  2. ACK Window (AckWindow / AckSlot)
//     - Per-packet state only: ack_count, first_ack_done, dup_ack_senders,
//       T_agg timer, retrans_id, is_retransmit.
//     - No per-receiver state inside the ACK Window.
//     - mark_retransmit() does a FULL slot reset so the new epoch starts clean.
//
//  3. ACK Aggregator (ack_aggregator_loop)
//     - retrans_id filter   : ACKs with rh.retrans_id < slot.retrans_id discarded.
//     - first_ack detection : signals main thread on ack_count 0 → 1.
//     - T_agg timer         : dup-ACK contributions accepted only within tagg_ms
//                             of the first dup-ACK for a given slot.
//     - x% dupack threshold : fast retransmit when ≥ dupack_pct % of cohort
//                             have each sent ≥ 1 dup-ACK within T_agg.
//     - committed_una       : min(peer_cum_ack); moves snd_una forward.
//
// Multicast Reno adaptations vs standard Reno:
//   cwnd    : updated on FIRST receiver ACK (not on full commit).
//   snd_una : advances on FULL COMMIT (all receivers ACKed past that seq).
//   Fast-recovery exit: deferred until committed_una > recovery_point.
//   RTO reset: rto_ms reverts to RTT estimate on each committed_una advance
//              (tweakable via --rto-reset-on-ack 0|1).
//
// Build:
//   g++ -std=c++17 -O2 -Wall -Wextra -pedantic -pthread \
//       -o mcast_reno_sender mcast_reno_sender.cpp
//
// Example:
//   ./mcast_reno_sender \
//     --group 239.255.0.1 --port 5000 \
//     --sender-port 45000 --expected 3 \
//     --file payload.bin --iface 10.169.144.14 --ttl 1 \
//     --rto-ms 250 --retries 20 \
//     --dupack-pct 50 --tagg-ms 100 --rto-reset-on-ack 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
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

// ─── Protocol header (22 bytes) — identical to peel_sender ───────────────────
#pragma pack(push, 1)
struct RmHeader {
    uint32_t seq;        // Sequence number (network order)
    uint16_t src_port;   // Sender's UDP port (network order)
    uint16_t flags;      // Bit flags (network order)
    uint8_t  retrans_id; // Retransmission epoch id (1..8)
    uint8_t  reserved;   // Must be zero
    uint16_t window;     // Window size (network order)
    uint16_t checksum;   // Internet checksum (header only)
    uint32_t tsval;      // Sender timestamp ms (network order)
    uint32_t tsecr;      // Echoed timestamp (network order)
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

// ─── Utilities ────────────────────────────────────────────────────────────────
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

// ─── Args ─────────────────────────────────────────────────────────────────────
struct Args {
    std::string group           = "239.255.0.1";
    uint16_t    port            = 5000;
    uint16_t    sender_port     = 45000;
    int         expected        = 1;
    std::string file;
    std::optional<std::string> iface_ip;
    int         ttl             = 1;
    int         rto_ms          = 250;    // initial / base RTO (ms)
    int         retries         = 20;
    size_t      max_app_payload = 1450;

    // ── Multicast Reno tuning ─────────────────────────────────────────────────
    // Percentage of cohort receivers that must each send ≥1 dup-ACK within
    // T_agg to trigger fast retransmit.  Range: (0, 100].
    float dupack_pct       = 50.0f;

    // T_agg aggregation window (ms).  Dup-ACK contributions for a given seq
    // are only accepted within tagg_ms of the FIRST dup-ACK for that seq.
    int   tagg_ms          = 100;

    // If true (default), rto_ms is reset to the current RTT estimate whenever
    // committed_una advances (i.e., the exponential backoff is undone on
    // a successful full commit).  Set to 0 to keep backoff across ACKs.
    bool  rto_reset_on_ack = true;
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --group A.B.C.D --port P --sender-port S --expected N"
              << " [--file path] [--iface X.Y.Z.W] [--ttl T]"
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
        else if (s == "--iface"            && need(1)) a.iface_ip        = argv[++i];
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
    if (a.expected <= 0)               { std::cerr << "--expected must be >= 1\n"; return false; }
    if (a.dupack_pct <= 0.0f || a.dupack_pct > 100.0f) {
        std::cerr << "--dupack-pct must be in (0, 100]\n"; return false;
    }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENT 1 — ACK Window (AckSlot + AckWindow)
//
// The sole per-packet state structure.  Covers the range [snd_una, snd_nxt).
// All access is under AckAggState::mtx.
//
// Design notes:
//  • first_ack_done     : set when ack_count goes 0 → 1; used to emit a cwnd
//                         update exactly once per slot per epoch.
//  • dup_ack_senders    : set of unique peer_keys that sent ≥1 dup-ACK; size
//                         drives the x%-threshold check.
//  • dupack_window_open : T_agg timer guard.  Dup-ACK contributions accepted
//                         only between dupack_window_start and +tagg_ms.
//  • mark_retransmit()  : full slot reset — ack_count, first_ack_done, dup
//                         state — so the new epoch starts from scratch.
// ═══════════════════════════════════════════════════════════════════════════════

struct AckSlot {
    // ── Forward-progress state ────────────────────────────────────────────────
    uint32_t ack_count      = 0;     // # receivers that ACKed past this seq
    bool     first_ack_done = false; // ack_count went 0→1 at least once

    // ── Duplicate-ACK state ───────────────────────────────────────────────────
    // Unique peer_keys that sent ≥1 dup-ACK for this slot within T_agg.
    std::unordered_set<uint64_t> dup_ack_senders;
    uint32_t dup_ack_count     = 0;      // == dup_ack_senders.size()
    Clock::time_point dupack_window_start{}; // when T_agg opened
    bool     dupack_window_open = false; // is T_agg timer active?

    // ── Epoch / retransmit state ──────────────────────────────────────────────
    uint8_t  retrans_id    = 1;     // epoch in use for current transmission
    bool     is_retransmit = false; // most recent tx was a retransmission
};

struct AckWindow {
    std::unordered_map<uint32_t, AckSlot> slots; // TODO: is unordered_map the best data structure to manage this? or a vector of size (max cwnd) more efficient? the index corresponding to seq can be calculated using snd_una and segment size

    // Called by main thread when a segment is first transmitted.
    void add_slot(uint32_t seq, uint8_t retrans_id = 1) {
        AckSlot s{};
        s.retrans_id = retrans_id;
        slots[seq]   = std::move(s);
    }

    // Called by main thread on retransmission (req 4).
    // Resets ALL per-slot counters so the new epoch is clean:
    //   - ack_count and first_ack_done reset -> next ACK with new retrans_id
    //     will be treated as the first ACK and update cwnd.
    //   - dup state cleared → T_agg reopens fresh for the new epoch.
    void mark_retransmit(uint32_t seq, uint8_t new_retrans_id) {
        auto it = slots.find(seq);
        if (it == slots.end()) return;
        AckSlot& s          = it->second;
        s.retrans_id        = new_retrans_id;
        s.is_retransmit     = true;
        s.ack_count         = 0;
        s.first_ack_done    = false;
        s.dup_ack_count     = 0;
        s.dup_ack_senders.clear();
        s.dupack_window_open = false;
    }

    // Called by main thread when committed_una advances.
    void erase_below(uint32_t committed_una) {
        for (auto it = slots.begin(); it != slots.end(); )
            it = (it->first < committed_una) ? slots.erase(it) : std::next(it);
    }

    AckSlot* get(uint32_t seq) { // TODO: why are there two functions for get
        auto it = slots.find(seq);
        return it != slots.end() ? &it->second : nullptr;
    }
    const AckSlot* get(uint32_t seq) const {
        auto it = slots.find(seq);
        return it != slots.end() ? &it->second : nullptr;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENT 2 — Reno State Machine (RenoSM)
//
// Lives entirely in the main thread (no locking).
// Consumes aggregated events only.
//
// Multicast Reno split-event model:
//   on_first_ack()        : first receiver ACKs a slot -> cwnd grows
//   on_recovery_ack()     : committed_una > recovery_point -> exit FR
//   on_dup_ack_threshold(): x% cohort dupacked -> enter FR, set recovery_point
//   on_timeout()          : RTO fired -> slow start
//
// snd_una is NOT moved by on_first_ack(); only the committed_una advance in
// transfer() does that.
// ═══════════════════════════════════════════════════════════════════════════════

enum class CCState { SLOW_START, CONG_AVOIDANCE, FAST_RECOVERY };

struct RenoSM {
    double   cwnd           = 1.0;
    double   ssthresh       = 65536.0; // TODO: would it be easier to deal in packet number rather than seq?
    CCState  state          = CCState::SLOW_START;

    // The sequence number the sender retransmitted during fast recovery.
    // Fast recovery exits only when committed_una > recovery_point, i.e. every
    // cohort receiver has confirmed receipt of the lost packet.
    uint32_t recovery_point = 0;

    // Pure CC window in packets.  Caller caps against min_rwnd for flow control.
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

    // ── Req 1: first ACK of a slot -> cwnd update (snd_una does not move) ─────
    // In FAST_RECOVERY this is window inflation (one cwnd unit per first ACK),
    // matching Reno's "inflate for each additional ACK" during recovery.
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
            cwnd += static_cast<double>(count); // window inflation
            break;
        }
    }

    // ── Req 6: exit fast recovery when all receivers ACKed past recovery_point ─
    // Called by transfer() when committed_una > recovery_point while in FR.
    void on_recovery_ack() {
        cwnd  = ssthresh;
        state = CCState::CONG_AVOIDANCE;
    }

    // ── Req 5: x%-dupack threshold reached -> enter fast recovery ─────────────
    // If not yet in FR: set ssthresh/cwnd and enter FR.
    // In ALL cases: extend recovery_point to cover the furthest outstanding loss
    // so that a secondary loss during FR doesn't cause premature FR exit.
    void on_dup_ack_threshold(uint32_t lost_seq) {
        if (state != CCState::FAST_RECOVERY) {
            ssthresh = std::max(cwnd / 2.0, 2.0);
            cwnd     = ssthresh + 3.0; // RFC 5681: inflate by 3 on entry
            state    = CCState::FAST_RECOVERY;
        }
        // Always push recovery_point to the furthest known loss so FR exit
        // (committed_una > recovery_point) waits for ALL losses to be resolved.
        if (lost_seq > recovery_point)
            recovery_point = lost_seq;
    }

    // ── Req 8/9: RTO timeout → slow start (identical to standard Reno) ────────
    void on_timeout() {
        ssthresh = std::max(cwnd / 2.0, 2.0);
        cwnd     = 1.0;
        state    = CCState::SLOW_START;
    }

    // ── Partial ACK during fast recovery (RFC 5681 §3.2 step 4) ──────────────
    // Deflate cwnd by the number of newly acknowledged packets (newly_acked),
    // then add back 1 SMSS to allow one new segment to be sent per partial ACK.
    // Ensures cwnd >= 1 to keep the pipeline moving.
    void on_partial_ack(uint32_t newly_acked) {
        cwnd -= static_cast<double>(newly_acked);
        cwnd += 1.0; // add back 1 SMSS per RFC 5681 §3.2 step 4
        if (cwnd < 1.0) cwnd = 1.0;
    }
};

// RTT estimator (Jacobson/Karels, RFC 6298).  srtt < 0 = not yet sampled.
static void update_rtt(double& srtt, double& rttvar, int& rto_ms,
                       double sample_ms) {
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

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENT 3 — Shared state between main thread and ACK Aggregator thread
// ═══════════════════════════════════════════════════════════════════════════════

struct AckAggState {
    std::mutex              mtx;
    std::condition_variable cv;

    // ── Per-receiver tracking (aggregator writes, main thread reads) ──────────
    std::unordered_map<uint64_t, uint32_t> peer_cum_ack; // peer_key → rcv_nxt // TODO: do i need it? We are ditching per receiver tracking.. can't we do it directly in ack window?

    // Per-peer most-recently-advertised window (in packets).
    // Updated on every valid ACK (forward-progress and dup-ACK alike) so that
    // min_rwnd can INCREASE when a constrained receiver's buffer drains — unlike
    // a plain running-min which is monotonically non-increasing.
    std::unordered_map<uint64_t, uint32_t> peer_rwnd; // peer_key → latest adv_wnd

    // ── ACK Window (Component 1) ──────────────────────────────────────────────
    AckWindow ack_wnd;

    // ── Window base: all receivers confirmed everything below this ────────────
    uint32_t committed_una = 1;

    // ── Signals from aggregator to main thread ────────────────────────────────

    // Number of slots that went from ack_count=0 to ack_count≥1 since the
    // last time the main thread drained this counter.  Drives on_first_ack().
    uint32_t first_ack_count = 0;

    // Set by aggregator when x%-dupack threshold fires.
    bool     fast_retransmit_needed = false;
    uint32_t fast_retransmit_seq    = 0;

    // Most recent tsecr from a non-retransmit ACK (for RTT sampling / Karn's).
    uint32_t last_tsecr  = 0;
    bool     tsecr_valid = false;

    // Minimum receiver advertised window across all cohort peers (in packets).
    // Each ACK carries h.window = remaining receive-buffer space; we track the
    // most-constrained receiver so the send window is min(cwnd, min_rwnd).
    uint32_t min_rwnd = 0xFFFF;
};

// ─── In-flight metadata (main thread only) ────────────────────────────────────
// Payload lives in all_segs[seq-1] — no copy needed.
// is_retransmit is tracked solely in AckSlot (set by mark_retransmit).
struct InFlightMeta {
    Clock::time_point sent_at;
    uint32_t          tsval;
    uint8_t           retrans_id = 1;
};

// ─── McastRenoSender ──────────────────────────────────────────────────────────
class McastRenoSender {
public:
    explicit McastRenoSender(const Args& args) : A(args) {}
    ~McastRenoSender() { if (fd >= 0) close(fd); }

    // ── init — identical to PeelSender::init() ───────────────────────────────
    bool init() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return false; }

        sockaddr_in local{};
        local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(A.sender_port);
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) {
            perror("bind sender_port"); return false;
        }

        if (A.iface_ip) {
            in_addr ifaceAddr{};
            if (inet_pton(AF_INET, A.iface_ip->c_str(), &ifaceAddr) != 1) {
                std::cerr << "Invalid --iface IP: " << *A.iface_ip << "\n"; return false;
            }
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaceAddr, sizeof(ifaceAddr)) < 0) {
                perror("setsockopt IP_MULTICAST_IF"); return false;
            }
        }
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &A.ttl, sizeof(A.ttl)) < 0) {
            perror("setsockopt IP_MULTICAST_TTL"); return false;
        }
        int loop = 0;
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
            perror("setsockopt IP_MULTICAST_LOOP"); return false;
        }

        memset(&mcast, 0, sizeof(mcast));
        mcast.sin_family = AF_INET; mcast.sin_port = htons(A.port);
        if (inet_pton(AF_INET, A.group.c_str(), &mcast.sin_addr) != 1) {
            std::cerr << "Invalid --group IP\n"; return false;
        }

        timeval tv{}; tv.tv_sec = A.rto_ms / 1000; tv.tv_usec = (A.rto_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_RCVTIMEO"); return false;
        }

        std::cerr << "Bound for ACKs on :" << A.sender_port << ", sending to "
                  << A.group << ":" << A.port
                  << ", expected=" << A.expected
                  << ", dupack_pct=" << A.dupack_pct
                  << ", tagg_ms=" << A.tagg_ms
                  << ", rto_reset_on_ack=" << A.rto_reset_on_ack << "\n";
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
                // Initialise per-peer rwnd to maximum; first real ACK will correct it.
                agg.peer_rwnd[k] = 0xFFFF;
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
        agg.cv.notify_all(); // unblock aggregator if it's waiting
        if (agg_thread.joinable()) agg_thread.join();

        if (!ok) return false;

        std::cerr << "Transfer complete. Sending FIN.\n";
        return send_fin(total + 1);
    }

private:
    // ════════════════════════════════════════════════════════════════════════
    // HANDSHAKE — line-for-line copy of PeelSender::handshake()
    // ════════════════════════════════════════════════════════════════════════
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
             ++attempt, ++retrans_id) {

            if (attempt > 0) cohort_map.clear();

            uint32_t ts = now_ms();
            RmHeader h{};
            fill_header(h, /*seq*/0, FLG_SYN, /*wnd*/1, ts, /*tsecr*/0, (uint8_t)retrans_id);
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
            auto us = elapsed_us();
            std::cerr << "Handshake failed after " << us << " us: got "
                      << cohort_map.size() << "/" << A.expected << " receivers\n";
            return false;
        }

        cohort.clear(); cohort.reserve(cohort_map.size());
        for (auto& kv : cohort_map) cohort.push_back(kv.second);

        uint32_t ts = now_ms();
        RmHeader start{};
        fill_header(start, /*seq*/0, FLG_START, /*wnd*/1, ts, 0, /*retrans_id*/1);
        std::vector<uint8_t> pkt(sizeof(RmHeader));
        serialize_header(start, pkt.data());
        if (!xmit(pkt)) {
            std::cerr << "Handshake failed sending START after " << elapsed_us() << " us\n";
            return false;
        }

        auto us = elapsed_us();
        std::cerr << "Handshake complete in " << us << " us ("
                  << (us / 1000.0) << " ms). Cohort=" << cohort.size() << ". Sent START.\n";
        return true;
    }

    // ════════════════════════════════════════════════════════════════════════
    // FIN TEARDOWN — line-for-line copy of PeelSender
    // ════════════════════════════════════════════════════════════════════════
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
            for (auto& c : cohort) {
                if (c.sin_addr.s_addr == peer.sin_addr.s_addr &&
                    c.sin_port == peer.sin_port) { member = true; break; }
            }
            if (!member) continue;

            got.insert(pack_key(peer));
            if (got.size() >= cohort.size()) return true;
        }
        return false;
    }

    // ════════════════════════════════════════════════════════════════════════
    // COMPONENT 3 — ACK AGGREGATOR THREAD
    //
    // Implements requirements 3, 4 (retrans_id filter + slot reset on retransmit),
    // 5 (x%-dupack threshold), 7 (T_agg timer), and the first-ACK signal (req 1).
    // ════════════════════════════════════════════════════════════════════════
    void ack_aggregator_loop() {
        constexpr int kPollMs = 10;

        // Compute fast-retransmit threshold: ceil(cohort_size * dupack_pct / 100).
        // Cached here; cohort is fixed after handshake.
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
            uint32_t cum_ack  = ntohl(rh.seq);    // receiver's rcv_nxt (cumulative)
            uint32_t tsecr    = ntohl(rh.tsecr);
            uint8_t  pkt_rid  = rh.retrans_id;    // epoch echoed from the DATA packet

            std::lock_guard<std::mutex> lk(agg.mtx);

            auto pit = agg.peer_cum_ack.find(peer_key);
            if (pit == agg.peer_cum_ack.end()) continue;
            uint32_t peer_prev = pit->second;

            // ── Receiver flow control: per-peer rwnd, recompute global min ──────
            // Done before the forward-progress / dup-ACK split so window updates
            // are captured from every valid cohort ACK, not only from those that
            // advance cum_ack.  This allows min_rwnd to INCREASE when a constrained
            // receiver's buffer drains and it advertises more space.
            {
                uint16_t adv_wnd = ntohs(rh.window);
                if (adv_wnd > 0) {
                    agg.peer_rwnd[peer_key] = (uint32_t)adv_wnd;
                    uint32_t new_min = 0xFFFFu;
                    for (auto& [k, w] : agg.peer_rwnd)
                        if (w < new_min) new_min = w;
                    agg.min_rwnd = new_min;
                }
            }

            if (cum_ack > peer_prev) {
                // ── Req 3: retrans_id filter (forward-progress path) ──────────
                // The ACK's retrans_id reflects the packet at cum_ack-1 (the last
                // received in-order data packet that triggered rcv_nxt to advance).
                // If that slot still exists and pkt_rid < slot.retrans_id, the ACK
                // is from a stale epoch — discard.
                if (cum_ack > 0) {
                    const AckSlot* chk = agg.ack_wnd.get(cum_ack - 1);
                    if (chk && pkt_rid < chk->retrans_id) continue; // stale
                }

                // ── Req 1: credit ack_count; detect first-ACK events ──────────
                uint32_t local_first_acks = 0;
                for (uint32_t s = peer_prev; s < cum_ack; ++s) {
                    AckSlot* slot = agg.ack_wnd.get(s);
                    if (!slot) continue;
                    slot->ack_count++;
                    if (!slot->first_ack_done) {
                        slot->first_ack_done = true;
                        agg.first_ack_count++;
                        local_first_acks++;
                    }
                }

                pit->second = cum_ack;

                // ── Req 2: recompute committed_una = min(peer_cum_ack) ────────
                uint32_t new_committed = compute_committed_una();
                bool     advanced      = (new_committed > agg.committed_una);
                if (advanced) agg.committed_una = new_committed;

                // ── RTT sample — Karn's algorithm (fix) ───────────────────────
                // tsecr echoes the tsval of the packet at cum_ack-1 specifically
                // (the last in-order packet that advanced rcv_nxt).  Only sample
                // if THAT slot is a fresh transmission, not a retransmit.
                const AckSlot* last_slot = agg.ack_wnd.get(cum_ack - 1);
                if (last_slot && !last_slot->is_retransmit && tsecr != 0) {
                    agg.last_tsecr  = tsecr;
                    agg.tsecr_valid = true;
                }

                if (local_first_acks > 0 || advanced)
                    agg.cv.notify_all();

            } else {
                // ── Duplicate ACK (cum_ack <= peer_prev) ─────────────────────

                // Receiver is stalling at peer_prev; the ACK echoes a DATA packet
                // at or below peer_prev.
                AckSlot* slot = agg.ack_wnd.get(peer_prev);
                if (!slot) continue;

                // ── Req 3: retrans_id filter (dup-ACK path) ───────────────────
                // If the receiver's dup-ACK has pkt_rid < slot.retrans_id, it was
                // generated for an old epoch of this packet — discard.
                if (pkt_rid < slot->retrans_id) continue;

                // ── Req 7: T_agg aggregation timer ────────────────────────────
                auto now_tp = Clock::now();
                if (!slot->dupack_window_open) {
                    // First dup-ACK for this slot: open the T_agg window.
                    slot->dupack_window_open  = true;
                    slot->dupack_window_start = now_tp;
                } else {
                    auto elapsed_ms =
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            now_tp - slot->dupack_window_start).count();
                    if (elapsed_ms > (long long)A.tagg_ms) continue; // T_agg expired
                }

                // ── Req 5: record unique sender; check x% threshold ───────────
                // Only count each receiver ONCE per T_agg window (unique-sender set).
                if (slot->dup_ack_senders.insert(peer_key).second) {
                    slot->dup_ack_count = (uint32_t)slot->dup_ack_senders.size();

                    if (slot->dup_ack_count >= fr_threshold &&
                        !agg.fast_retransmit_needed) {
                        agg.fast_retransmit_needed = true;
                        agg.fast_retransmit_seq    = peer_prev;
                        agg.cv.notify_all();
                    }
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // SLIDING-WINDOW TRANSFER
    //
    // Implements req 1 (first-ACK → cwnd, send more), req 2 (full-commit →
    // snd_una), req 6 (FR exit on committed_una > recovery_point), req 8
    // (RTO reset on commit), req 9 (standard Reno window/ssthresh elsewhere).
    // ════════════════════════════════════════════════════════════════════════
    bool transfer(uint32_t total) {
        snd_nxt = 1;
        uint32_t prev_committed  = 1; // tracks snd_una (committed_una at last advance)
        int      consec_timeouts = 0;

        double srtt   = -1.0; // Jacobson/Karels SRTT (-1 = unsampled)
        double rttvar =  0.0;
        int    rto_ms = A.rto_ms; // working RTO (may be backed off)

        RenoSM reno; // Reno State Machine — main thread only

        while (true) {
            // ── Completion ───────────────────────────────────────────────────
            {
                std::lock_guard<std::mutex> lk(agg.mtx);
                if (agg.committed_una > total) break;
            }

            // ── Read current snd_una and receiver window ──────────────────────
            uint32_t committed;
            uint32_t min_rwnd;
            {
                std::lock_guard<std::mutex> lk(agg.mtx);
                committed = agg.committed_una;
                min_rwnd  = agg.min_rwnd;
            }

            // ── Req 1 / 2: fill send window ───────────────────────────────────
            // Effective window = min(cwnd, min_rwnd) — flow control from the most
            // constrained receiver caps the CC window.
            uint32_t eff_wnd = std::min(reno.window_size(), min_rwnd);
            while (snd_nxt <= total &&
                   snd_nxt < committed + eff_wnd) {
                if (!send_segment(snd_nxt)) return false;
                {
                    std::lock_guard<std::mutex> lk(agg.mtx);
                    agg.ack_wnd.add_slot(snd_nxt, /*retrans_id*/1);
                }
                snd_nxt++;
            }

            if (in_flight.empty()) break; // safety

            // ── RTO deadline: oldest in-flight segment ────────────────────────
            // in_flight holds only {sent_at, tsval, retrans_id}; payload lives in
            // all_segs[seq-1] and AckWindow holds per-packet ACK state.
            auto& oldest   = in_flight.begin()->second;
            auto  expiry   = oldest.sent_at + std::chrono::milliseconds(rto_ms);
            auto  wait_dur = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 expiry - Clock::now());
            if (wait_dur.count() < 0) wait_dur = std::chrono::milliseconds(0);

            // ── Wait: CV fires on first_ack, fast_retransmit, or committed ────
            uint32_t first_ack_events    = 0;
            bool     fast_retransmit     = false;
            uint32_t fast_retransmit_seq = 0;
            uint32_t tsecr_sample        = 0;
            bool     have_tsecr          = false;

            std::unique_lock<std::mutex> lk(agg.mtx);
            bool woke_up = agg.cv.wait_for(lk, wait_dur, [&] {
                return agg.committed_una   > prev_committed ||
                       agg.first_ack_count > 0             ||
                       agg.fast_retransmit_needed;
            });
            uint32_t new_committed = agg.committed_una;

            // Drain all pending signals under the same lock.
            if (agg.first_ack_count > 0) {
                first_ack_events    = agg.first_ack_count;
                agg.first_ack_count = 0;
            }
            if (agg.fast_retransmit_needed) {
                fast_retransmit            = true;
                fast_retransmit_seq        = agg.fast_retransmit_seq;
                agg.fast_retransmit_needed = false; // aggregator re-arms only after !fast_retransmit_needed
            }
            if (agg.tsecr_valid) {
                tsecr_sample    = agg.last_tsecr;
                have_tsecr      = true;
                agg.tsecr_valid = false;
            }
            lk.unlock();

            // ── RTT update (Karn's: tsecr set only for non-retransmit ACKs) ───
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

            // ── Req 1: first-ACK events → cwnd grows, send more next iteration ─
            // ack_count is incremented inside ack_aggregator_loop() for each slot
            // in [peer_prev, cum_ack); first_ack_count is the aggregated signal.
            if (first_ack_events > 0) {
                reno.on_first_ack(first_ack_events);
                std::cerr << "  FIRST_ACK ×" << first_ack_events
                          << " cwnd=" << reno.cwnd
                          << " state=" << reno.state_str() << "\n";
                // Next loop iteration re-checks the window and sends new segments.
            }

            // ── Req 2: committed_una advance → snd_una moves ─────────────────
            if (woke_up && new_committed > prev_committed) {
                consec_timeouts = 0;

                // Remove committed segments from in_flight and ACK Window.
                for (auto it = in_flight.begin();
                     it != in_flight.end() && it->first < new_committed; )
                    it = in_flight.erase(it);
                {
                    std::lock_guard<std::mutex> lk2(agg.mtx);
                    agg.ack_wnd.erase_below(new_committed); // strict <: slot at new_committed is kept
                }

                uint32_t old_committed = prev_committed; // saved for partial-ACK deflation below
                prev_committed = new_committed;

                // ── Req 8: reset RTO backoff on committed_una advance ─────────
                // (tweakable: --rto-reset-on-ack 0 to keep exponential backoff)
                // Note: standard TCP only restarts the timer on ACK; reducing rto_ms
                // here is a multicast adaptation to undo unwarranted backoff.
                if (A.rto_reset_on_ack) {
                    rto_ms = (srtt > 0.0)
                             ? std::min(std::max((int)(srtt + 4.0 * rttvar), 10), 30000)
                             : A.rto_ms;
                }

                // ── Req 6: exit fast recovery when ALL receivers ACKed past ───
                //          the lost packet (committed_una > recovery_point).
                if (reno.state == CCState::FAST_RECOVERY &&
                    new_committed > reno.recovery_point) {
                    reno.on_recovery_ack();
                    std::cerr << "  EXIT FR committed=" << new_committed
                              << " cwnd=" << reno.cwnd
                              << " state=" << reno.state_str() << "\n";
                } else if (reno.state == CCState::FAST_RECOVERY) {
                    // Partial ACK (RFC 5681 §3.2 step 4): committed_una advanced
                    // but not past recovery_point — at least one loss still unresolved.
                    // Deflate cwnd by newly-ACKed count, add back 1 SMSS, then
                    // immediately retransmit the next unACKed segment so recovery
                    // pipelines instead of waiting for RTO.
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

            // ── Req 5: fast retransmit → enter fast recovery ──────────────────
            if (fast_retransmit) {
                // Guard: by the time the main thread processes the signal, the
                // segment may have been committed (all receivers ACKed it while
                // the signal was queued).  Entering FR for an already-committed
                // slot would set a stale recovery_point and stall the sender.
                if (in_flight.count(fast_retransmit_seq)) {
                    reno.on_dup_ack_threshold(fast_retransmit_seq);
                    std::cerr << "  FAST_RETRANSMIT seq=" << fast_retransmit_seq
                              << " cwnd=" << reno.cwnd
                              << " ssthresh=" << reno.ssthresh
                              << " state=" << reno.state_str() << "\n";
                    if (!retransmit_segment(fast_retransmit_seq)) return false;
                    // Req 4: update ACK Window slot with new epoch.
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

            // ── Req 8/9: RTO timeout ──────────────────────────────────────────
            if (!woke_up) {
                consec_timeouts++;
                if (consec_timeouts > A.retries) {
                    std::cerr << "Too many consecutive timeouts. Aborting.\n";
                    return false;
                }
                reno.on_timeout();
                rto_ms = std::min(rto_ms * 2, 30000); // exponential backoff

                std::cerr << "  RTO timeout committed=" << prev_committed
                          << " cwnd=" << reno.cwnd
                          << " new_rto=" << rto_ms << " ms\n";

                if (!retransmit_segment(prev_committed)) return false;
                // Req 4: update ACK Window slot with new epoch.
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

    // ─── Send a new (first-time) data segment ─────────────────────────────────
    bool send_segment(uint32_t seq) {
        const auto& payload = all_segs[seq - 1]; // direct ref; no copy

        uint32_t ts = now_ms();
        std::vector<uint8_t> pkt(sizeof(RmHeader) + payload.size());
        RmHeader h{};
        fill_header(h, seq, FLG_DATA, /*wnd*/1, ts, /*tsecr*/0, /*retrans_id*/1);
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

    // ─── Retransmit an in-flight segment ─────────────────────────────────────
    // Req 4: increments retrans_id in InFlightMeta; caller then calls
    // mark_retransmit on the AckWindow slot to complete the epoch reset.
    // Payload is read directly from all_segs — no per-segment copy needed.
    bool retransmit_segment(uint32_t seq) {
        auto it = in_flight.find(seq);
        if (it == in_flight.end()) return true; // already ACKed / not yet sent
        InFlightMeta& meta = it->second;

        uint8_t new_rid = static_cast<uint8_t>(
            std::min(static_cast<int>(meta.retrans_id) + 1, 8));
        meta.retrans_id = new_rid;

        const auto& payload = all_segs[seq - 1]; // direct ref; no copy
        uint32_t ts = now_ms();
        std::vector<uint8_t> pkt(sizeof(RmHeader) + payload.size());
        RmHeader h{};
        fill_header(h, seq, FLG_DATA, /*wnd*/1, ts, /*tsecr*/0, new_rid);
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

    // ─── Helpers ─────────────────────────────────────────────────────────────

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

    // committed_una = min(peer_cum_ack).  MUST be called with agg.mtx held. // TODO: instead of this, check the ackslot with agg_count == total peers/receivers. is that not better/easier?
    uint32_t compute_committed_una() const {
        uint32_t min_una = UINT32_MAX;
        for (auto& [key, una] : agg.peer_cum_ack)
            if (una < min_una) min_una = una;
        return (min_una == UINT32_MAX) ? 1 : min_una;
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

    // ════════════════════════════════════════════════════════════════════════
    // LOW-LEVEL HELPERS — identical to peel_sender
    // ════════════════════════════════════════════════════════════════════════
    bool xmit(const std::vector<uint8_t>& bytes) {
        ssize_t n = sendto(fd, bytes.data(), bytes.size(), 0,
                           (sockaddr*)&mcast, sizeof(mcast));
        if (n < 0) { perror("sendto"); return false; }
        if ((size_t)n != bytes.size()) {
            std::cerr << "Partial send!? sent=" << n
                      << " expected=" << bytes.size() << "\n";
            return false;
        }
        return true;
    }

    bool recv_header(sockaddr_in& from, RmHeader& out) {
        uint8_t buf[sizeof(RmHeader) + 16];
        socklen_t alen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&from, &alen);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) return false;
            perror("recvfrom"); return false;
        }
        if ((size_t)n < sizeof(RmHeader)) return false;
        deserialize_header(buf, out);
        return true;
    }

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

    void deserialize_header(const uint8_t* in, RmHeader& h) {
        memcpy(&h, in, sizeof(h));
    }

    bool verify_header(const RmHeader& net) {
        RmHeader tmp = net; uint16_t rcv = tmp.checksum;
        tmp.checksum = 0;
        return rcv == checksum16(&tmp, sizeof(tmp));
    }

private:
    Args A;
    int  fd = -1;

    sockaddr_in mcast{};
    std::vector<sockaddr_in> cohort; // fixed after handshake

    uint32_t                         snd_nxt  = 1;
    std::map<uint32_t, InFlightMeta> in_flight;
    std::vector<std::vector<uint8_t>> all_segs;

    AckAggState       agg;
    std::atomic<bool> agg_stop{false};
    std::thread       agg_thread;
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    McastRenoSender s(args);
    if (!s.init()) return 2;
    if (!s.run()) return 3;
    return 0;
}
