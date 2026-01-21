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
#include <algorithm>


using Clock = std::chrono::steady_clock;

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
    long long us = 0;
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

// --- Dummy layer ---
// The benchmark now mimics a "real" call path where some higher layer prepares
// a payload in memory and then invokes a lower layer to send it.
//
// Timing requirement for this variant:
//   Measure from *right before* invoking the layer until the connection finishes.
//   This includes: socket creation, connect, payload send, ACK, and close.

// Conservative one-segment payload size for MTU=1500.
// IPv4 typical max payload is 1460, IPv6 typical is 1440.
static inline size_t mtu1500_one_segment_payload_len(const Endpoint& ep) {
    int fam = ((sockaddr*)&ep.addr)->sa_family;
    return (fam == AF_INET6) ? 1440u : 1460u;
}

// The "dummy" send layer: takes endpoint + pointer/len to a memory region.
// It is responsible for socket creation, connect, send, ACK wait, and close.
static bool dummy_layer_send_one_packet(
    const Endpoint& ep,
    const char* payload,
    size_t payload_len,
    int timeout_ms,
    std::string& err)
{
    if (!ep.resolved) {
        err = "unresolved endpoint";
        return false;
    }

    int sock = ::socket(((sockaddr*)&ep.addr)->sa_family, SOCK_STREAM, 0);
    if (sock < 0) {
        err = std::string("socket: ") + std::strerror(errno);
        return false;
    }

    auto close_sock = [&] {
        if (sock >= 0) {
            ::close(sock);
            sock = -1;
        }
    };

    // non-blocking for timed connect and safe send loop
    int flags = ::fcntl(sock, F_GETFL, 0);
    if (flags < 0 || ::fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        err = std::string("fcntl(O_NONBLOCK): ") + std::strerror(errno);
        close_sock();
        return false;
    }

    // Avoid any coalescing delays for a single small write.
    int one = 1;
    (void)::setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    // === timed connect ===
    int ret = ::connect(sock, (sockaddr*)&ep.addr, ep.addrlen);
    if (ret != 0) {
        if (ret < 0 && errno != EINPROGRESS) {
            err = std::string("connect: ") + std::strerror(errno);
            close_sock();
            return false;
        }

        pollfd pfd{};
        pfd.fd = sock;
        pfd.events = POLLOUT;

        int pr = ::poll(&pfd, 1, timeout_ms);
        if (pr == 0) {
            err = "connect timeout";
            close_sock();
            return false;
        }
        if (pr < 0) {
            err = std::string("poll(connect): ") + std::strerror(errno);
            close_sock();
            return false;
        }

        int so_error = 0;
        socklen_t slen = sizeof(so_error);
        if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &slen) < 0) {
            err = std::string("getsockopt(SO_ERROR): ") + std::strerror(errno);
            close_sock();
            return false;
        }
        if (so_error != 0) {
            err = std::string("connect: ") + std::strerror(so_error);
            close_sock();
            return false;
        }
    }

    // === determine max single-segment bytes ===
    // Use TCP_MAXSEG if available and clamp to the MTU=1500 safe payload.
    int mss = (int)mtu1500_one_segment_payload_len(ep);
    socklen_t mss_len = sizeof(mss);
    if (::getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len) == 0) {
        if (mss <= 0) mss = (int)mtu1500_one_segment_payload_len(ep);
    } else {
        mss = (int)mtu1500_one_segment_payload_len(ep);
    }

    size_t max_one_segment = std::min<size_t>((size_t)mss, mtu1500_one_segment_payload_len(ep));
    if (max_one_segment < 1) max_one_segment = 1;
    size_t send_len = std::min(payload_len, max_one_segment);

    // === send exactly one TCP segment ===
    if (!send_all_nb(sock, payload, send_len, timeout_ms, err)) {
        close_sock();
        return false;
    }

    // === wait until the peer ACKs the data ===
    if (!wait_for_ack_linux(sock, timeout_ms, err)) {
        close_sock();
        return false;
    }

    // Connection teardown is INCLUDED in this benchmark variant.
    close_sock();
    return true;
}

// Benchmark wrapper: time from right before invoking the dummy layer until it returns.
static Result invoke_dummy_layer_and_measure_total_us(
    const Endpoint& ep,
    const char* payload,
    size_t payload_len,
    int timeout_ms)
{
    Result r;
    std::string err;
    auto t0 = Clock::now();
    bool ok = dummy_layer_send_one_packet(ep, payload, payload_len, timeout_ms, err);
    auto t1 = Clock::now();

    r.success = ok;
    r.us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    r.err = ok ? "" : err;
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
    int num_runs = 10;
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
			// Thread-local payload buffer: reused across runs, prepared before each timed invoke.
			std::vector<char> payload;

			for (int r = 0; r < num_runs; ++r) {
				// (1) "Read" payload first (outside the timed region).
				// In a real app this could be reading from a mem-region / ring buffer.
				size_t payload_len = mtu1500_one_segment_payload_len(endpoints[i]);
				payload.assign(payload_len, 'x');

				start_barrier.arrive_and_wait(); // synchronized start

				// (2) Measure from right before invoking the dummy layer until it finishes.
				results[i] = invoke_dummy_layer_and_measure_total_us(
					endpoints[i], payload.data(), payload.size(), timeout_ms);

				done_barrier.arrive_and_wait();  // synchronized end
			}
		});
    }

    long long min_batch_max = std::numeric_limits<long long>::max();
    long long max_batch_max = 0;
    long long sum_batch_max = 0;
    int batch_success_runs = 0;

    for (int r = 0; r < num_runs; ++r) {
        start_barrier.arrive_and_wait(); // release all connects
        done_barrier.arrive_and_wait();  // wait for all to finish

        std::cout << "=== Run " << (r + 1)
          << " (dummy layer: connect + 1 packet + ACK + close, simultaneous) ===\n";


        long long slowest_us = -1;
        int slowest_idx = -1;
        int success_cnt = 0;

        for (int i = 0; i < N; ++i) {
            const auto& ep = endpoints[i];
            const auto& rs = results[i];

            if (rs.success) {
                success_cnt++;
                double ms = rs.us / 1000.0;
                std::cout << "  " << std::left << std::setw(28) << ep.label()
                          << "  " << std::right << std::setw(10) << rs.us
                          << " us (" << ms << " ms)\n";
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
            std::cout << "  -> Slowest successful (invoke->finish): "
                      << endpoints[slowest_idx].label()
                      << " = " << slowest_us << " us ("
                      << (slowest_us / 1000.0) << " ms)\n\n";

            if (slowest_us < min_batch_max) min_batch_max = slowest_us;
            if (slowest_us > max_batch_max) max_batch_max = slowest_us;
            sum_batch_max += slowest_us;
            batch_success_runs++;
        } else {
            std::cout << "  -> No successful connections in this run.\n\n";
        }
    }

    for (auto& t : workers) t.join();

    if (batch_success_runs > 0) {
        double avg = static_cast<double>(sum_batch_max) / batch_success_runs;
        std::cout << "=== Summary of slowest-per-run (your benchmark metric) ===\n"
                  << "  successful runs: " << batch_success_runs << "/" << num_runs << "\n"
                  << "  min(slowest) = " << min_batch_max << " us\n"
                  << "  max(slowest) = " << max_batch_max << " us\n"
                  << "  avg(slowest) = " << avg << " us (" << (avg / 1000.0) << " ms)\n";
    } else {
        std::cout << "No successful connections across all runs.\n";
        return 2;
    }

    return 0;
}
