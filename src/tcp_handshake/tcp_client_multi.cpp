#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

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

static Result connect_handshake_us(const Endpoint& ep, int timeout_ms) {
    Result r;

    if (!ep.resolved) {
        r.success = false;
        r.err = "unresolved endpoint";
        return r;
    }

    int sock = ::socket(((sockaddr*)&ep.addr)->sa_family, SOCK_STREAM, 0);
    if (sock < 0) {
        r.success = false;
        r.err = std::string("socket: ") + std::strerror(errno);
        return r;
    }

    // non-blocking for timed connect
    int flags = ::fcntl(sock, F_GETFL, 0);
    if (flags < 0 || ::fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        r.success = false;
        r.err = std::string("fcntl(O_NONBLOCK): ") + std::strerror(errno);
        ::close(sock);
        return r;
    }

    auto t0 = Clock::now();
    int ret = ::connect(sock, (sockaddr*)&ep.addr, ep.addrlen);
    if (ret == 0) {
        auto t1 = Clock::now();
        r.success = true;
        r.us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        ::close(sock);
        return r;
    }

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
        r.err = std::string("poll: ") + std::strerror(errno);
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

    auto t1 = Clock::now();
    r.success = true;
    r.us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    ::close(sock);
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
            for (int r = 0; r < num_runs; ++r) {
                start_barrier.arrive_and_wait(); // synchronized start
                results[i] = connect_handshake_us(endpoints[i], timeout_ms);
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

        std::cout << "=== Run " << (r + 1) << " (simultaneous connects) ===\n";

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
            std::cout << "  -> Slowest successful handshake: "
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
