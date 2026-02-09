#include "PeelReceiver.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

PeelReceiver::PeelReceiver(const PeelReceiverArgs& args) : A(args) {}

PeelReceiver::~PeelReceiver() {
    if (fd >= 0) close(fd);
    if (ofs.is_open()) ofs.close();
}

bool PeelReceiver::init() {
    fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return false; }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        return false;
    }
    if (A.rcvbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &A.rcvbuf, sizeof(A.rcvbuf)) < 0) {
        perror("setsockopt SO_RCVBUF"); /* non-fatal */
    }

    // Bind to INADDR_ANY:port to receive multicast
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(A.port);

    if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) {
        perror("bind");
        return false;
    }

    // Join multicast group
    ip_mreq mreq{};
    if (inet_pton(AF_INET, A.group.c_str(), &mreq.imr_multiaddr) != 1) {
        std::cerr << "Invalid --group IP\n";
        return false;
    }
    if (A.iface_ip) {
        if (inet_pton(AF_INET, A.iface_ip->c_str(), &mreq.imr_interface) != 1) {
            std::cerr << "Invalid --iface IP\n";
            return false;
        }
    } else {
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    }

    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt IP_ADD_MEMBERSHIP");
        return false;
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

bool PeelReceiver::run() {
    bool started = false;
    uint32_t delivered = 0; // last in-order seq delivered
    uint64_t total_bytes = 0;

    std::vector<uint8_t> buf(65536);
    while (true) {
        sockaddr_in peer{};
        socklen_t alen = sizeof(peer);

        ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0, (sockaddr*)&peer, &alen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            return false;
        }
        if ((size_t)n < sizeof(PeelHeader)) continue;

        PeelHeader h{};
        std::memcpy(&h, buf.data(), sizeof(h));
        if (!verify_header(h)) continue;

        uint16_t flags = ntohs(h.flags);
        uint32_t seq = ntohl(h.seq);
        uint32_t tsval = ntohl(h.tsval);
        uint16_t sender_port_hdr = ntohs(h.src_port);
        uint8_t retrans_id = h.retrans_id;

        // Destination for ACKs: sender IP from packet, port from header's src_port
        sockaddr_in ack_to{};
        ack_to.sin_family = AF_INET;
        ack_to.sin_addr = peer.sin_addr;
        ack_to.sin_port = htons(sender_port_hdr);

        if (flags & FLG_SYN) {
            send_ack(ack_to, /*seq*/0, (uint16_t)(FLG_SYN | FLG_ACK), /*tsecr*/tsval, retrans_id);
            continue;
        }

        // NOTE: keeping your current logic as-is (START handling is commented out in your original).
        // if (flags & FLG_START) {
        //     started = true;
        //     std::cerr << "START received. Entering data phase.\n";
        //     continue;
        // }

        if (!started && (flags & (FLG_DATA | FLG_FIN))) {
            send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id);

            std::cerr << "DATA/FIN before START; ACKed but ignored for delivery.\n";
            if (flags & FLG_FIN) {
                std::cerr << "FIN observed before START; exiting anyway.\n";
                return true;
            }
            continue;
        }

        if (flags & FLG_DATA) {
            if (seq == delivered + 1) {
                size_t app_len = (size_t)n - sizeof(PeelHeader);
                if (app_len > 0) {
                    if (ofs.is_open()) {
                        ofs.write(reinterpret_cast<const char*>(buf.data() + sizeof(PeelHeader)),
                                  (std::streamsize)app_len);
                    }
                    total_bytes += app_len;
                }
                delivered = seq;
                send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id);

                std::cerr << "DATA seq=" << seq
                          << " len=" << (n - (ssize_t)sizeof(PeelHeader))
                          << " -> delivered, total=" << total_bytes << " bytes\n";
            } else if (seq == delivered) {
                send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id);
                std::cerr << "Duplicate DATA seq=" << seq << " -> re-ACK\n";
            } else {
                std::cerr << "Out-of-order DATA seq=" << seq
                          << " (expected " << (delivered + 1)
                          << ") -> ignoring (no ACK)\n";
            }
            continue;
        }

        if (flags & FLG_FIN) {
            send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id);
            std::cerr << "FIN seq=" << seq << " -> ACKed. Total received=" << total_bytes << " bytes\n";
            return true;
        }
    }
}

bool PeelReceiver::verify_header(const PeelHeader& net) {
    return peel_verify_header_checksum(net);
}

void PeelReceiver::send_ack(const sockaddr_in& to, uint32_t seq, uint16_t flags,
                            uint32_t tsecr_in, uint8_t retrans_id_in) {
    PeelHeader a{};
    a.seq = htonl(seq);
    a.src_port = htons(local_port()); // informative only
    a.flags = htons(flags);
    a.retrans_id = retrans_id_in;
    a.reserved = 0;
    a.window = htons(1);
    a.checksum = 0;
    a.tsval = htonl(peel_now_ms());
    a.tsecr = htonl(tsecr_in);

    peel_set_header_checksum(a);

    ssize_t n = sendto(fd, &a, sizeof(a), 0, (const sockaddr*)&to, sizeof(to));
    if (n < 0) perror("sendto ACK");
}

uint16_t PeelReceiver::local_port() const {
    sockaddr_in sa{};
    socklen_t sl = sizeof(sa);
    if (getsockname(fd, (sockaddr*)&sa, &sl) == 0) return ntohs(sa.sin_port);
    return 0;
}
