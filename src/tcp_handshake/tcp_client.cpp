#include <iostream>
#include <chrono>
#include <string>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

using Clock = std::chrono::steady_clock;

int main(int argc, char** argv) {
    // Default: connect to your receiver 10.169.144.15:5001
    const char* server_ip = "10.169.144.15";
    int port = 5001;
    int num_runs = 10; // number of connect() attempts for statistics

    if (argc > 1) server_ip = argv[1]; // optional override
    if (argc > 2) port      = std::stoi(argv[2]);
    if (argc > 3) num_runs  = std::stoi(argv[3]);

    std::cout << "Measuring TCP handshake (connect) to " << server_ip
              << ":" << port << " for " << num_runs << " runs\n";

    long long min_us = std::numeric_limits<long long>::max();
    long long max_us = 0;
    long long sum_us = 0;
    int       success_runs = 0;

    for (int i = 0; i < num_runs; ++i) {
        int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            return 1;
        }

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        if (inet_pton(AF_INET, server_ip, &server.sin_addr) <= 0) {
            std::cerr << "Invalid server IP: " << server_ip << std::endl;
            ::close(sock);
            return 1;
        }

        auto t0 = Clock::now();
        int ret = ::connect(sock, reinterpret_cast<sockaddr*>(&server), sizeof(server));
        auto t1 = Clock::now();

        if (ret < 0) {
            perror("connect");
            ::close(sock);
            continue;
        }

        long long us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        double ms    = us / 1000.0;

        std::cout << "Run " << (i + 1) << ": " << us << " us (" << ms << " ms)\n";

        if (us < min_us) min_us = us;
        if (us > max_us) max_us = us;
        sum_us += us;
        success_runs++;

        ::close(sock);

        // Optional small pause between runs (comment out if you want them back-to-back)
        // usleep(10000); // 10 ms
    }

    if (success_runs > 0) {
        double avg_us = static_cast<double>(sum_us) / success_runs;
        std::cout << "Summary over " << success_runs << " successful runs:\n"
                  << "  min = " << min_us   << " us\n"
                  << "  max = " << max_us   << " us\n"
                  << "  avg = " << avg_us   << " us ("
                  <<  avg_us / 1000.0       << " ms)\n";
    } else {
        std::cout << "No successful connections.\n";
    }

    return 0;
}
