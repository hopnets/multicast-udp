// peel_receiver.cpp
// A matching reliable multicast RECEIVER for peel_sender.
//
// Behavior
// - Joins IPv4 multicast group at --group/--port
// - On receiving SYN (multicast), unicast replies to sender with SYN|ACK (tsecr echoes tsval)
// - Waits for START, then receives DATA packets in order. For each DATA, sends ACK back to sender.
// - On FIN, sends ACK and exits. Duplicate DATA are ACKed but not re-written.
// - Uses the same 20-byte Reliable Multicast Header as the sender.
//
// Build: g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o peel_receiver peel_receiver.cpp
// Example:
//   ./peel_receiver --group 239.255.0.1 --port 5000 --out received.bin --iface 10.169.144.14
//
// Notes:
// - ACKs are UNICAST to the sender IP and to the port specified in the received header's src_port field.
// - We validate the header checksum and ignore frames that fail.
// - Stop-and-wait assumption: we ACK only the next expected seq (n+1) or a duplicate (n). Out-of-order (> n+1) is ignored to trigger retransmission.

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
#include <optional>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

#pragma pack(push, 1)
struct RmHeader {
    uint32_t seq;        // Sequence Number (network order on wire)
    uint16_t src_port;   // Sender's UDP port (network order)
    uint16_t flags;      // Flags (network order)
    uint8_t  retrans_id; // Retransmission attempt id (1..8)
    uint8_t  reserved;   // Must be zero
    uint16_t window;     // Window (network order)
    uint16_t checksum;   // Internet checksum over header only (network order)
    uint32_t tsval;      // Sender timestamp (network order)
    uint32_t tsecr;      // Echo timestamp (network order)
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

struct Args {
    std::string group = "239.255.0.1"; // multicast group
    uint16_t port = 5000;               // multicast port
    std::optional<std::string> iface_ip; // optional local interface IPv4 for group join
    std::string out_path;               // optional output file
    int rcvbuf = 4 * 1024 * 1024;       // receive buffer size
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog << " --group A.B.C.D --port P [--iface X.Y.Z.W] [--out file] [--rcvbuf BYTES]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more){ if (i + more >= argc) { usage(argv[0]); return false; } return true; };
        if (s == "--group" && need(1)) a.group = argv[++i];
        else if (s == "--port" && need(1)) a.port = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--iface" && need(1)) a.iface_ip = argv[++i];
        else if (s == "--out" && need(1)) a.out_path = argv[++i];
        else if (s == "--rcvbuf" && need(1)) a.rcvbuf = std::stoi(argv[++i]);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); return false; }
    }
    return true;
}

static std::string addr_to_string(const sockaddr_in& a) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
    char out[128];
    snprintf(out, sizeof(out), "%s:%u", buf, ntohs(a.sin_port));
    return std::string(out);
}

class PeelReceiver {
public:
    explicit PeelReceiver(const Args& args) : A(args) {}
    ~PeelReceiver() { if (fd >= 0) close(fd); if (ofs.is_open()) ofs.close(); }

    bool init() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return false; }

        int yes = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            perror("setsockopt SO_REUSEADDR"); return false;
        }
        if (A.rcvbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &A.rcvbuf, sizeof(A.rcvbuf)) < 0) {
            perror("setsockopt SO_RCVBUF"); /* non-fatal */
        }

        // Bind to INADDR_ANY:port to receive multicast
        sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_ANY); local.sin_port = htons(A.port);
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) {
            perror("bind"); return false;
        }

        // Join multicast group
        ip_mreq mreq{};
        if (inet_pton(AF_INET, A.group.c_str(), &mreq.imr_multiaddr) != 1) {
            std::cerr << "Invalid --group IP\n"; return false; }
        if (A.iface_ip) {
            if (inet_pton(AF_INET, A.iface_ip->c_str(), &mreq.imr_interface) != 1) {
                std::cerr << "Invalid --iface IP\n"; return false; }
        } else {
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        }
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            perror("setsockopt IP_ADD_MEMBERSHIP"); return false;
        }

        if (!A.out_path.empty()) {
            ofs.open(A.out_path, std::ios::binary | std::ios::trunc);
            if (!ofs) { std::cerr << "Failed to open --out file: " << A.out_path << "\n"; return false; }
        }

        std::cerr << "Listening on group " << A.group << ":" << A.port
                  << (A.iface_ip ? (" via iface " + *A.iface_ip) : "")
                  << (A.out_path.empty() ? " (no file output)" : (" -> " + A.out_path))
                  << "\n";
        return true;
    }

    bool run() {
        bool started = false;
        uint32_t delivered = 0; // last in-order seq delivered
        uint64_t total_bytes = 0;

        std::vector<uint8_t> buf(65536);
        while (true) {
            sockaddr_in peer{}; socklen_t alen = sizeof(peer);
            ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0, (sockaddr*)&peer, &alen);
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("recvfrom"); return false;
            }
            if ((size_t)n < sizeof(RmHeader)) continue; // too small

            RmHeader h{}; memcpy(&h, buf.data(), sizeof(h));
            // Verify checksum
            if (!verify_header(h)) continue;

            uint16_t flags = ntohs(h.flags);
            uint32_t seq = ntohl(h.seq);
			uint32_t tsval = ntohl(h.tsval);
			uint16_t sender_port_hdr = ntohs(h.src_port);
			uint8_t retrans_id = h.retrans_id; // NEW: echo this in ACKs


            // Destination for ACKs: sender IP from packet, port from header's src_port
            sockaddr_in ack_to{}; ack_to.sin_family = AF_INET; ack_to.sin_addr = peer.sin_addr; ack_to.sin_port = htons(sender_port_hdr);

            if (flags & FLG_SYN) {
                //std::cerr << "SYN from " << addr_to_string(peer) << " -> replying SYN|ACK to :" << sender_port_hdr << "\n";
                send_ack(ack_to, /*seq*/0, /*flags*/FLG_SYN | FLG_ACK, /*tsecr*/tsval, /*retrans_id*/retrans_id);

                // Do not switch to started yet; wait for START
                continue;
            }

            //if (flags & FLG_START) {
            //    started = true;
            //    std::cerr << "START received. Entering data phase.\n";
                // No ACK required for START in this protocol
            //    continue;
            //}

            if (!started && (flags & (FLG_DATA | FLG_FIN))) {
                // Be robust: still ACK, but do not deliver payload if not started
                send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id);

                std::cerr << "DATA/FIN before START; ACKed but ignored for delivery.\n";
                if (flags & FLG_FIN) {
                    std::cerr << "FIN observed before START; exiting anyway.\n";
                    return true;
                }
                continue;
            }

            if (flags & FLG_DATA) {
                // Stop-and-wait expectation: next seq should be delivered+1
                if (seq == delivered + 1) {
                    size_t app_len = (size_t)n - sizeof(RmHeader);
                    if (app_len > 0) {
                        if (ofs.is_open()) ofs.write(reinterpret_cast<const char*>(buf.data() + sizeof(RmHeader)), (std::streamsize)app_len);
                        total_bytes += app_len;
                    }
                    delivered = seq;
                    send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id);

                    std::cerr << "DATA seq=" << seq << " len=" << (n - (ssize_t)sizeof(RmHeader)) << " -> delivered, total=" << total_bytes << " bytes\n";
                } else if (seq == delivered) {
                    // Duplicate; re-ACK
                    send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id);

                    std::cerr << "Duplicate DATA seq=" << seq << " -> re-ACK\n";
                } else {
                    // Out-of-order (> delivered+1) should not happen in stop-and-wait; ignore to trigger retransmit
                    std::cerr << "Out-of-order DATA seq=" << seq << " (expected " << (delivered+1) << ") -> ignoring (no ACK)\n";
                }
                continue;
            }

            if (flags & FLG_FIN) {
                // ACK and exit
                send_ack(ack_to, seq, FLG_ACK, tsval, retrans_id);

                std::cerr << "FIN seq=" << seq << " -> ACKed. Total received=" << total_bytes << " bytes\n";
                return true;
            }
        }
        return true;
    }

private:
    bool verify_header(const RmHeader& net) {
        RmHeader tmp = net; uint16_t r = tmp.checksum; tmp.checksum = 0; uint16_t calc = checksum16(&tmp, sizeof(tmp));
        return r == calc;
    }

	void send_ack(const sockaddr_in& to, uint32_t seq, uint16_t flags, uint32_t tsecr_in, uint8_t retrans_id_in) {
		RmHeader a{};
		a.seq = htonl(seq);
		a.src_port = htons(local_port()); // informative only
		a.flags = htons(flags);
		a.retrans_id = retrans_id_in;
		a.reserved = 0;
		a.window = htons(1);
		a.checksum = 0;
		a.tsval = htonl(now_ms());
		a.tsecr = htonl(tsecr_in);

		// checksum (header only)
		RmHeader tmp = a; tmp.checksum = 0;
		a.checksum = checksum16(&tmp, sizeof(tmp));

		ssize_t n = sendto(fd, &a, sizeof(a), 0, (const sockaddr*)&to, sizeof(to));
		if (n < 0) perror("sendto ACK");
	}


    uint16_t local_port() const {
        sockaddr_in sa{}; socklen_t sl = sizeof(sa);
        if (getsockname(fd, (sockaddr*)&sa, &sl) == 0) return ntohs(sa.sin_port);
        return 0;
    }

private:
    Args A;
    int fd = -1;
    std::ofstream ofs;
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    PeelReceiver r(args);
    if (!r.init()) return 2;
    if (!r.run()) return 3;
    return 0;
}
