#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

int main(int argc, char** argv) {
    int port = 5001; // you can change this if you like
    if (argc > 1) {
        port = std::stoi(argv[1]);
    }

    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    // Bind to all interfaces on this host; you can also hardcode an IP if you prefer:
    // inet_pton(AF_INET, "10.169.144.15", &addr.sin_addr);
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(listen_fd, 128) < 0) {
        perror("listen");
        return 1;
    }

    std::cout << "TCP server listening on port " << port << " ..." << std::endl;

    // Big reusable read buffer (not memory-efficient on purpose; good for experiments).
    std::vector<char> buf(4 * 1024 * 1024);

    while (true) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);

        int conn_fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (conn_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
        int peer_port = ntohs(peer.sin_port);
        std::cout << "Accepted connection from " << peer_ip
                  << ":" << peer_port << std::endl;

        // IMPORTANT for the 1000+ packet client:
        // Drain everything the client sends until it closes (EOF). Otherwise the receive
        // buffer can fill up and the client's send loop will stall (zero window).
        //
        // You can bump SO_RCVBUF to reduce the chance of stalls if the app is busy.
        int rcvbuf = 16 * 1024 * 1024; // 16 MB
        (void)setsockopt(conn_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        size_t total_bytes = 0;
        while (true) {
            ssize_t n = ::recv(conn_fd, buf.data(), buf.size(), 0);
            if (n > 0) {
                total_bytes += static_cast<size_t>(n);
                continue;
            }
            if (n == 0) {
                // peer performed an orderly shutdown (close)
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            break;
        }

        std::cout << "Connection from " << peer_ip << ":" << peer_port
                  << " closed; received " << total_bytes << " bytes" << std::endl;

        ::close(conn_fd);
    }

    ::close(listen_fd);
    return 0;
}
