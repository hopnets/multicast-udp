#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netinet/tcp.h>

#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>

using Clock = std::chrono::steady_clock;

// How many payload-sized application writes to perform per connection.
constexpr int kNumWrites = 1000;

// For the derived "avg per packet" stat below, we approximate:
//   - TCP handshake as 2 packets (rough proxy)
//   - FIN/teardown as 1 packet (rough proxy)
// Note: TCP is a byte stream; the true on-wire segment count can differ.
constexpr int kAssumedHandshakePkts = 2;
constexpr int kAssumedFinPkts = 1;

struct Endpoint {
    std::string host;
    int port = 0;

    sockaddr_storage addr{};
    socklen_t addrlen = 0;
    bool resolved = false;
    std::string resolve_err;

    std::string label() const {
        return host + ":" + std::to_string(port);
    }
};

struct Result {
    bool success = false;

    // Total time for a connection = setup + transport + teardown
    long long us = 0;

    // Phase breakdown (microseconds)
    long long setup_us = 0;     // socket() + options + connect()
    long long xfer_us = 0;      // send N writes + wait for ACKs
    long long teardown_us = 0;  // close()

    // What we attempted to send
    int mss = 0;         // TCP_MAXSEG as returned by the kernel (bytes of payload)
    int payload_len = 0; // bytes per application write
    int num_writes = 0;  // number of application writes
    size_t bytes_sent = 0;

    std::string err;
};


// Simple reusable (cyclic) barrier for C++17
class CyclicBarrier {
public:
    explicit CyclicBarrier(int parties)
        : parties_(parties), count_(parties), generation_(0) {}

    void arrive_and_wait() {
        std::unique_lock<std::mutex> lk(m_);
        int gen = generation_;
        if (--count_ == 0) {
            generation_++;
            count_ = parties_;
            cv_.notify_all();
        } else {
            cv_.wait(lk, [&] { return gen != generation_; });
        }
    }

private:
    int parties_;
    int count_;
    int generation_;
    std::mutex m_;
    std::condition_variable cv_;
};

static inline std::string trim(std::string s) {
    auto notspace = [](unsigned char c) { return !std::isspace(c); };
    while (!s.empty() && !notspace((unsigned char)s.front())) s.erase(s.begin());
    while (!s.empty() && !notspace((unsigned char)s.back()))  s.pop_back();
    return s;
}

static bool resolve_endpoint(Endpoint& ep) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC; // allow v4/v6
    hints.ai_flags = AI_ADDRCONFIG;

    addrinfo* res = nullptr;
    std::string port_str = std::to_string(ep.port);

    int rc = ::getaddrinfo(ep.host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        ep.resolved = false;
        ep.resolve_err = gai_strerror(rc);
        return false;
    }

    // take the first result
    std::memset(&ep.addr, 0, sizeof(ep.addr));
    std::memcpy(&ep.addr, res->ai_addr, res->ai_addrlen);
    ep.addrlen = static_cast<socklen_t>(res->ai_addrlen);
    ep.resolved = true;

    ::freeaddrinfo(res);
    return true;
}

// Return milliseconds remaining until deadline (clamped at 0)
static inline int remaining_ms(Clock::time_point deadline) {
    auto now = Clock::now();
    if (now >= deadline) return 0;
    return (int)std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
}

// Send the full buffer (works with non-blocking sockets). Uses poll(POLLOUT)
// and a timeout.
static bool send_all_nb(int sock, const char* buf, size_t len, int timeout_ms, std::string& err) {
    size_t sent = 0;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);

    while (sent < len) {
        ssize_t n = ::send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int rem = remaining_ms(deadline);
            if (rem <= 0) {
                err = "send timeout";
                return false;
            }
            pollfd pfd{};
            pfd.fd = sock;
            pfd.events = POLLOUT;
            int pr = ::poll(&pfd, 1, rem);
            if (pr == 0) {
                err = "send timeout";
                return false;
            }
            if (pr < 0) {
                err = std::string("poll(POLLOUT): ") + std::strerror(errno);
                return false;
            }
            continue;
        }
        err = std::string("send: ") + std::strerror(errno);
        return false;
    }

    return true;
}

// Wait until all queued outgoing bytes are ACKed by the peer.
// On Linux, ioctl(TIOCOUTQ) returns the number of bytes currently in the socket
// send queue (includes unacked + unsent). When it reaches 0, everything is ACKed.
static bool wait_for_ack_linux(int sock, int timeout_ms, std::string& err) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);

    while (true) {
        int outq = 0;
        if (::ioctl(sock, TIOCOUTQ, &outq) < 0) {
            err = std::string("ioctl(TIOCOUTQ): ") + std::strerror(errno);
            return false;
        }
        if (outq == 0) return true;

        if (Clock::now() >= deadline) {
            err = "ACK timeout";
            return false;
        }

        // Detect early close/error without blocking.
        pollfd pfd{};
        pfd.fd = sock;
        pfd.events = POLLERR | POLLHUP;
        int pr = ::poll(&pfd, 1, 0);
        if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP))) {
            err = "peer closed/error before ACK";
            return false;
        }

        // Short sleep to avoid busy-spinning.
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

// Updated benchmark: time from the beginning of connect() until the ACK for the
// first (and only) TCP data segment arrives.
//
// We send a single payload sized to fit in a single TCP segment for MTU=1500.
// For IPv4 without options that's typically 1460 bytes (1500 - 20 IP - 20 TCP).
static Result connect_send_one_packet_and_wait_ack_us(const Endpoint& ep, int timeout_ms) {
    Result r;

    if (!ep.resolved) {
        r.success = false;
        r.err = "unresolved endpoint";
        return r;
    }

    // Measure setup starting at socket creation.
    auto t_setup0 = Clock::now();

    int sock = ::socket(((sockaddr*)&ep.addr)->sa_family, SOCK_STREAM, 0);
    if (sock < 0) {
        r.success = false;
        r.err = std::string("socket: ") + std::strerror(errno);
        return r;
    }

    // non-blocking for timed connect and safe send loop
    int flags = ::fcntl(sock, F_GETFL, 0);
    if (flags < 0 || ::fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        r.success = false;
        r.err = std::string("fcntl(O_NONBLOCK): ") + std::strerror(errno);
        ::close(sock);
        return r;
    }

    // Avoid any coalescing delays for small writes
    int one = 1;
    (void)::setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    // === timed connect ===
    int ret = ::connect(sock, (sockaddr*)&ep.addr, ep.addrlen);
    if (ret != 0) {
        if (ret < 0 && errno != EINPROGRESS) {
            r.success = false;
            r.err = std::string("connect: ") + std::strerror(errno);
            ::close(sock);
            return r;
        }

        pollfd pfd{};
        pfd.fd = sock;
        pfd.events = POLLOUT;

        int pr = ::poll(&pfd, 1, timeout_ms);
        if (pr == 0) {
            r.success = false;
            r.err = "connect timeout";
            ::close(sock);
            return r;
        }
        if (pr < 0) {
            r.success = false;
            r.err = std::string("poll(connect): ") + std::strerror(errno);
            ::close(sock);
            return r;
        }

        int so_error = 0;
        socklen_t slen = sizeof(so_error);
        if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &slen) < 0) {
            r.success = false;
            r.err = std::string("getsockopt(SO_ERROR): ") + std::strerror(errno);
            ::close(sock);
            return r;
        }
        if (so_error != 0) {
            r.success = false;
            r.err = std::string("connect: ") + std::strerror(so_error);
            ::close(sock);
            return r;
        }
    }

    auto t_setup1 = Clock::now();
    r.setup_us = std::chrono::duration_cast<std::chrono::microseconds>(t_setup1 - t_setup0).count();

    // === payload size (single segment) ===
    int mss = 1460;
    socklen_t mss_len = sizeof(mss);
    if (::getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len) == 0) {
        if (mss <= 0) mss = 1460;
    } else {
        mss = 1460;
    }

    int payload_len = std::min(mss, 1460);
    if (payload_len < 1) payload_len = 1;

    std::vector<char> payload((size_t)payload_len, 'x');

    // Record the payload configuration so printing/summary can confirm what was attempted.
    r.mss = mss;
    r.payload_len = payload_len;
    r.num_writes = kNumWrites;

    // === transport: send N payload-sized writes and wait until everything is ACKed ===
    r.bytes_sent = payload.size() * (size_t)kNumWrites;

    std::string err;
    auto t_xfer0 = Clock::now();

    // One overall deadline for the entire send phase (prevents 1000 * timeout_ms worst-case).
    auto send_deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    for (int i = 0; i < kNumWrites; ++i) {
        size_t sent = 0;
        while (sent < payload.size()) {
            ssize_t n = ::send(sock, payload.data() + sent, payload.size() - sent, MSG_NOSIGNAL);
            if (n > 0) {
                sent += (size_t)n;
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                int rem = remaining_ms(send_deadline);
                if (rem <= 0) {
                    r.success = false;
                    r.err = "send timeout";
                    ::close(sock);
                    return r;
                }
                pollfd pfd{};
                pfd.fd = sock;
                pfd.events = POLLOUT;
                int pr = ::poll(&pfd, 1, rem);
                if (pr == 0) {
                    r.success = false;
                    r.err = "send timeout";
                    ::close(sock);
                    return r;
                }
                if (pr < 0) {
                    r.success = false;
                    r.err = std::string("poll(POLLOUT): ") + std::strerror(errno);
                    ::close(sock);
                    return r;
                }
                continue;
            }

            r.success = false;
            r.err = std::string("send: ") + std::strerror(errno);
            ::close(sock);
            return r;
        }
    }

    // Wait until the peer ACKs all queued data.
    if (!wait_for_ack_linux(sock, timeout_ms, err)) {
        r.success = false;
        r.err = err;
        ::close(sock);
        return r;
    }

    auto t_xfer1 = Clock::now();
    r.xfer_us = std::chrono::duration_cast<std::chrono::microseconds>(t_xfer1 - t_xfer0).count();

    // === teardown: measure local close() cost (does not guarantee FIN handshake timing) ===
    auto t_td0 = Clock::now();
    ::close(sock);
    auto t_td1 = Clock::now();
    r.teardown_us = std::chrono::duration_cast<std::chrono::microseconds>(t_td1 - t_td0).count();

    r.success = true;
    r.us = r.setup_us + r.xfer_us + r.teardown_us;
    return r;
}


static std::optional<Endpoint> parse_line_to_endpoint(
    const std::string& line_in, int default_port)
{
    std::string line = line_in;
    // strip comments
    auto hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    line = trim(line);
    if (line.empty()) return std::nullopt;

    Endpoint ep;
    ep.port = default_port;

    // If whitespace separated: "host port"
    {
        std::istringstream iss(line);
        std::string a, b;
        if (iss >> a) {
            if (iss >> b) {
                ep.host = a;
                ep.port = std::stoi(b);
                return ep;
            }
        }
    }

    // Bracketed IPv6: "[addr]:port"
    if (!line.empty() && line.front() == '[') {
        auto rb = line.find(']');
        if (rb == std::string::npos) return std::nullopt;
        ep.host = line.substr(1, rb - 1);
        if (rb + 1 < line.size() && line[rb + 1] == ':') {
            ep.port = std::stoi(line.substr(rb + 2));
        }
        return ep;
    }

    // Single ':' treated as host:port (IPv4/hostname). Multiple ':' => treat as host only (IPv6 w/o brackets).
    size_t first_colon = line.find(':');
    if (first_colon != std::string::npos && line.find(':', first_colon + 1) == std::string::npos) {
        ep.host = line.substr(0, first_colon);
        ep.port = std::stoi(line.substr(first_colon + 1));
        ep.host = trim(ep.host);
        return ep;
    }

    // Otherwise host only
    ep.host = line;
    return ep;
}

static std::vector<Endpoint> load_endpoints(const std::string& path, int default_port) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Failed to open file: " + path);
    }

    std::vector<Endpoint> eps;
    std::string line;
    while (std::getline(in, line)) {
        auto ep = parse_line_to_endpoint(line, default_port);
        if (ep) eps.push_back(*ep);
    }
    return eps;
}

int main(int argc, char** argv) {
    std::string file = "ip.txt";
    int num_runs = 15;
    int timeout_ms = 3000;
    int default_port = 5001;

    if (argc > 1) file = argv[1];
    if (argc > 2) num_runs = std::stoi(argv[2]);
    if (argc > 3) timeout_ms = std::stoi(argv[3]);
    if (argc > 4) default_port = std::stoi(argv[4]);

    std::vector<Endpoint> endpoints;
    try {
        endpoints = load_endpoints(file, default_port);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    if (endpoints.empty()) {
        std::cerr << "No endpoints found in " << file << "\n";
        return 1;
    }

    // Resolve everything up front so DNS doesn't skew timing
    int resolved_ok = 0;
    for (auto& ep : endpoints) {
        if (resolve_endpoint(ep)) resolved_ok++;
    }

    std::cout << "Loaded " << endpoints.size() << " endpoints from " << file << "\n";
    std::cout << "Resolved: " << resolved_ok << "/" << endpoints.size() << "\n";
    std::cout << "Runs: " << num_runs << ", connect timeout: " << timeout_ms << " ms\n\n";

    const int N = static_cast<int>(endpoints.size());
    std::vector<Result> results(N);

    // Barriers include main thread so it can “release” the simultaneous start.
    CyclicBarrier start_barrier(N + 1);
    CyclicBarrier done_barrier(N + 1);

    // Workers persist across runs to avoid thread creation overhead in the measurement window.
    std::vector<std::thread> workers;
    workers.reserve(N);

	for (int i = 0; i < N; ++i) {
		workers.emplace_back([&, i] {
			for (int r = 0; r < num_runs; ++r) {
				start_barrier.arrive_and_wait(); // synchronized start

				results[i] =
					connect_send_one_packet_and_wait_ack_us(
						endpoints[i], timeout_ms);

				done_barrier.arrive_and_wait();  // synchronized end
				// 0.5 ms sleep at end of iteration
				std::this_thread::sleep_for(std::chrono::microseconds(500));

			}
		});
	}
	
    long long min_slowest_total_us = std::numeric_limits<long long>::max();
long long max_slowest_total_us = 0;
long long sum_slowest_total_us = 0;

long long min_slowest_setup_us = std::numeric_limits<long long>::max();
long long max_slowest_setup_us = 0;
long long sum_slowest_setup_us = 0;

long long min_slowest_xfer_us = std::numeric_limits<long long>::max();
long long max_slowest_xfer_us = 0;
long long sum_slowest_xfer_us = 0;

long long min_slowest_close_us = std::numeric_limits<long long>::max();
long long max_slowest_close_us = 0;
long long sum_slowest_close_us = 0;

double min_slowest_bw_gbps = std::numeric_limits<double>::infinity();
double max_slowest_bw_gbps = 0.0;
double sum_slowest_bw_gbps = 0.0;

double min_slowest_avg_xfer_per_write_us = std::numeric_limits<double>::infinity();
double max_slowest_avg_xfer_per_write_us = 0.0;
double sum_slowest_avg_xfer_per_write_us = 0.0;

double min_slowest_avg_total_per_assumed_pkt_us = std::numeric_limits<double>::infinity();
double max_slowest_avg_total_per_assumed_pkt_us = 0.0;
double sum_slowest_avg_total_per_assumed_pkt_us = 0.0;

int batch_success_runs = 0;

    for (int r = 0; r < num_runs; ++r) {
        start_barrier.arrive_and_wait(); // release all connects
        done_barrier.arrive_and_wait();  // wait for all to finish

        std::cout << "=== Run " << (r + 1) << " (connect + " << kNumWrites << " payload writes + wait for ACK, simultaneous) ===\n";

        long long slowest_us = -1;
        int slowest_idx = -1;
        int success_cnt = 0;

        for (int i = 0; i < N; ++i) {
            const auto& ep = endpoints[i];
            const auto& rs = results[i];

            if (rs.success) {
                success_cnt++;
				double total_ms = rs.us / 1000.0;
				double setup_ms = rs.setup_us / 1000.0;
				double xfer_ms  = rs.xfer_us / 1000.0;
				double td_ms    = rs.teardown_us / 1000.0;

				double gbps = 0.0;
				if (rs.xfer_us > 0 && rs.bytes_sent > 0) {
					// Gbps = bytes*8 / (us*1000)
					gbps = (rs.bytes_sent * 8.0) / (rs.xfer_us * 1000.0);
				}

				double avg_xfer_per_write_us = 0.0;
				if (rs.num_writes > 0) {
					avg_xfer_per_write_us = static_cast<double>(rs.xfer_us) / rs.num_writes;
				}

				const int assumed_pkts = rs.num_writes + kAssumedHandshakePkts + kAssumedFinPkts;
				double avg_total_per_assumed_pkt_us = 0.0;
				if (assumed_pkts > 0) {
					avg_total_per_assumed_pkt_us = static_cast<double>(rs.us) / assumed_pkts;
				}

				std::cout << "  " << std::left << std::setw(28) << ep.label()
						  << "  total " << std::right << std::setw(10) << rs.us
						  << " us (" << total_ms << " ms)"
						  << " | setup " << rs.setup_us << " us (" << setup_ms << " ms)"
						  << " | xfer " << rs.xfer_us << " us (" << xfer_ms << " ms)"
						  << " | close " << rs.teardown_us << " us (" << td_ms << " ms)"
						  << " | cfg mss " << rs.mss << "B, payload " << rs.payload_len << "B x " << rs.num_writes
						  << " = " << rs.bytes_sent << "B"
						  << " | avg_xfer/write " << std::fixed << std::setprecision(3) << avg_xfer_per_write_us << " us"
						  << " | avg_total/assumed_pkt " << std::fixed << std::setprecision(3) << avg_total_per_assumed_pkt_us << " us"
						  << " | xfer_bw " << std::fixed << std::setprecision(3) << gbps << " Gbps"
						  << std::defaultfloat
						  << "\n";

                if (rs.us > slowest_us) {
                    slowest_us = rs.us;
                    slowest_idx = i;
                }
            } else {
                std::cout << "  " << std::left << std::setw(28) << ep.label()
                          << "  FAILED: " << (ep.resolved ? rs.err : ep.resolve_err) << "\n";
            }
        }

        if (success_cnt > 0) {
            std::cout << "  -> Slowest successful endpoint (by total): "
                      << endpoints[slowest_idx].label()
                      << " = " << slowest_us << " us ("
                      << (slowest_us / 1000.0) << " ms)\n\n";

            const auto& s = results[slowest_idx];

if (s.us < min_slowest_total_us) min_slowest_total_us = s.us;
if (s.us > max_slowest_total_us) max_slowest_total_us = s.us;
sum_slowest_total_us += s.us;

if (s.setup_us < min_slowest_setup_us) min_slowest_setup_us = s.setup_us;
if (s.setup_us > max_slowest_setup_us) max_slowest_setup_us = s.setup_us;
sum_slowest_setup_us += s.setup_us;

if (s.xfer_us < min_slowest_xfer_us) min_slowest_xfer_us = s.xfer_us;
if (s.xfer_us > max_slowest_xfer_us) max_slowest_xfer_us = s.xfer_us;
sum_slowest_xfer_us += s.xfer_us;

if (s.teardown_us < min_slowest_close_us) min_slowest_close_us = s.teardown_us;
if (s.teardown_us > max_slowest_close_us) max_slowest_close_us = s.teardown_us;
sum_slowest_close_us += s.teardown_us;

double bw = 0.0;
if (s.xfer_us > 0 && s.bytes_sent > 0) {
    bw = (s.bytes_sent * 8.0) / (s.xfer_us * 1000.0); // Gbps
}
if (bw < min_slowest_bw_gbps) min_slowest_bw_gbps = bw;
if (bw > max_slowest_bw_gbps) max_slowest_bw_gbps = bw;
sum_slowest_bw_gbps += bw;

double avg_xfer_per_write = 0.0;
if (s.num_writes > 0) avg_xfer_per_write = static_cast<double>(s.xfer_us) / s.num_writes;
if (avg_xfer_per_write < min_slowest_avg_xfer_per_write_us) min_slowest_avg_xfer_per_write_us = avg_xfer_per_write;
if (avg_xfer_per_write > max_slowest_avg_xfer_per_write_us) max_slowest_avg_xfer_per_write_us = avg_xfer_per_write;
sum_slowest_avg_xfer_per_write_us += avg_xfer_per_write;

const int assumed_pkts = s.num_writes + kAssumedHandshakePkts + kAssumedFinPkts;
double avg_total_per_assumed_pkt = 0.0;
if (assumed_pkts > 0) avg_total_per_assumed_pkt = static_cast<double>(s.us) / assumed_pkts;
if (avg_total_per_assumed_pkt < min_slowest_avg_total_per_assumed_pkt_us) min_slowest_avg_total_per_assumed_pkt_us = avg_total_per_assumed_pkt;
if (avg_total_per_assumed_pkt > max_slowest_avg_total_per_assumed_pkt_us) max_slowest_avg_total_per_assumed_pkt_us = avg_total_per_assumed_pkt;
sum_slowest_avg_total_per_assumed_pkt_us += avg_total_per_assumed_pkt;

batch_success_runs++;
        } else {
            std::cout << "  -> No successful connections in this run.\n\n";
        }
    }

    for (auto& t : workers) t.join();

    if (batch_success_runs > 0) {
        const double avg_total_us = static_cast<double>(sum_slowest_total_us) / batch_success_runs;
        const double avg_setup_us = static_cast<double>(sum_slowest_setup_us) / batch_success_runs;
        const double avg_xfer_us  = static_cast<double>(sum_slowest_xfer_us)  / batch_success_runs;
        const double avg_close_us = static_cast<double>(sum_slowest_close_us) / batch_success_runs;

        const double avg_bw_gbps = sum_slowest_bw_gbps / batch_success_runs;
        const double avg_avg_xfer_per_write_us = sum_slowest_avg_xfer_per_write_us / batch_success_runs;
        const double avg_avg_total_per_assumed_pkt_us = sum_slowest_avg_total_per_assumed_pkt_us / batch_success_runs;

        std::cout << "=== Benchmark Summary - TCP connect + bulk send ===\n"
                  << "  endpoints: " << N << "\n"
                  << "  runs: " << num_runs << " (successful: " << batch_success_runs << "/" << num_runs << ")\n"
                  << "  per-connection target: " << kNumWrites << " application writes of <=MSS bytes\n"
                  << "  summary basis: SLOWEST successful endpoint each run (by total time)\n\n"
                  << "  total_us        min/avg/max: " << min_slowest_total_us << " / " << avg_total_us << " / " << max_slowest_total_us
                  << "  (" << (avg_total_us / 1000.0) << " ms avg)\n"
                  << "  setup_us        min/avg/max: " << min_slowest_setup_us << " / " << avg_setup_us << " / " << max_slowest_setup_us
                  << "  (" << (avg_setup_us / 1000.0) << " ms avg)\n"
                  << "  xfer_us         min/avg/max: " << min_slowest_xfer_us  << " / " << avg_xfer_us  << " / " << max_slowest_xfer_us
                  << "  (" << (avg_xfer_us / 1000.0) << " ms avg)\n"
                  << "  close_us        min/avg/max: " << min_slowest_close_us << " / " << avg_close_us << " / " << max_slowest_close_us
                  << "  (" << (avg_close_us / 1000.0) << " ms avg)\n"
                  << "  xfer_bw_gbps    min/avg/max: " << std::fixed << std::setprecision(3)
                  << min_slowest_bw_gbps << " / " << avg_bw_gbps << " / " << max_slowest_bw_gbps
                  << std::defaultfloat << "\n"
                  << "  avg_xfer/write  min/avg/max: " << std::fixed << std::setprecision(3)
                  << min_slowest_avg_xfer_per_write_us << " / " << avg_avg_xfer_per_write_us << " / " << max_slowest_avg_xfer_per_write_us
                  << " us\n"
                  << "  avg_total/assumed_pkt (handshake=2, fin=1) min/avg/max: " << std::fixed << std::setprecision(3)
                  << min_slowest_avg_total_per_assumed_pkt_us << " / " << avg_avg_total_per_assumed_pkt_us << " / " << max_slowest_avg_total_per_assumed_pkt_us
                  << " us\n"
                  << std::defaultfloat;
    } else {
        std::cout << "No successful connections across all runs.\n";
        return 2;
    }



    return 0;
}
