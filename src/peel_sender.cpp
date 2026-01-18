// peel_sender.cpp
// A simple reliable multicast sender over UDP with a TCP-like handshake.
// - Multicast group: user-provided (e.g., 239.255.0.1)
// - Port: user-provided (UDP dest port for multicast)
// - Sender binds a local UDP port to receive unicast ACKs from receivers
// - TCP-like 2-step handshake: Sender multicasts SYN, receivers reply unicast with SYN|ACK
// - Cohort is fixed once expected N receivers have replied
// - Stop-and-wait reliability: each DATA packet must be ACKed by all receivers before proceeding
// - Header per spec (20 bytes) with Internet 16-bit ones'-complement checksum over header only
//
// Build: g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o peel_sender peel_sender.cpp
// Example:
//   ./peel_sender \
//     --group 239.255.0.1 --port 5000 \
//     --sender-port 45000 --expected 3 \
//     --file payload.bin --iface 10.169.144.14 --ttl 1 \
//     --rto-ms 250 --retries 20
//
// Notes:
// - The OS sets IPv4(20) + UDP(8). We add a 20-byte Reliable Multicast header and optional payload.
// - Max UDP datagram payload on Ethernet is typically 1472 bytes (1500 - 20 - 8). Of that, 20 bytes is
//   our header, so max application payload per packet defaults to 1452 bytes unless overridden.
// - ACKs are unicast back to the sender's bound port.
// - This is a reference implementation intended for lab/LAN conditions.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <optional>
#include <cassert>
#include <atomic>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

// ---------------- Protocol header (20 bytes) ----------------
#pragma pack(push, 1)
struct RmHeader {
    uint32_t seq;        // Sequence Number
    uint16_t src_port;   // Sender's UDP port (network order)
    uint16_t flags;      // Bit flags
    uint16_t window;     // Window size (for future use)
    uint16_t checksum;   // Internet checksum (header only, checksum field = 0 when computing)
    uint32_t tsval;      // Sender timestamp (ms, monotonic truncated)
    uint32_t tsecr;      // Echoed timestamp from peer (ACKs echo tsval)
};
#pragma pack(pop)
static_assert(sizeof(RmHeader) == 20, "RmHeader must be 20 bytes");

// Flags
enum : uint16_t {
    FLG_SYN   = 0x0001,
    FLG_ACK   = 0x0002,
    FLG_START = 0x0004, // cohort established / start of data
    FLG_DATA  = 0x0008,
    FLG_FIN   = 0x0010,
    FLG_RST   = 0x0020,
};

// Utilities
static uint32_t now_ms() {
    auto now = Clock::now().time_since_epoch();
    return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

static uint16_t checksum16(const void* data, size_t len) {
    // Internet checksum (RFC 1071) over bytes
    uint32_t sum = 0;
    const uint16_t* p = static_cast<const uint16_t*>(data);
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<const uint8_t*>(p);
        sum += last;
    }
    // Fold 32->16
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

static std::string addr_to_string(const sockaddr_in& a) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
    std::ostringstream oss;
    oss << buf << ":" << ntohs(a.sin_port);
    return oss.str();
}

struct PeerKey {
    uint32_t ip;   // network order
    uint16_t port; // network order
    bool operator==(const PeerKey& o) const { return ip == o.ip && port == o.port; }
};

struct PeerKeyHash { size_t operator()(const PeerKey& k) const { return (size_t)k.ip * 1315423911u + k.port; } };

struct Args {
    std::string group = "239.255.0.1"; // multicast group
    uint16_t port = 5000;               // multicast dest port
    uint16_t sender_port = 45000;       // local bind port for ACKs
    int expected = 1;                   // expected receivers
    std::string file;                   // optional payload file
    std::optional<std::string> iface_ip; // optional egress interface IPv4 (e.g., 192.168.1.50)
    int ttl = 1;                        // multicast TTL
    int rto_ms = 250;                   // retransmission timeout
    int retries = 20;                   // max retries per step
    size_t max_app_payload = 1452;      // default for Ethernet MTU (1472 total - 20 header)
};

struct WindowEntry {
	std::vector<uint8_t> contents;
	bool ack_status = false;
    uint32_t sequence_number;
    uint64_t last_retry;
    int num_tries;
};

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog << " --group A.B.C.D --port P --sender-port S --expected N [--file path]"
              << " [--iface X.Y.Z.W] [--ttl T] [--rto-ms MS] [--retries K] [--chunk BYTES]\n";
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more){ if (i + more >= argc) { usage(argv[0]); return false; } return true; };
        if (s == "--group" && need(1)) a.group = argv[++i];
        else if (s == "--port" && need(1)) a.port = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--sender-port" && need(1)) a.sender_port = (uint16_t)std::stoi(argv[++i]);
        else if (s == "--expected" && need(1)) a.expected = std::stoi(argv[++i]);
        else if (s == "--file" && need(1)) a.file = argv[++i];
        else if (s == "--iface" && need(1)) a.iface_ip = argv[++i];
        else if (s == "--ttl" && need(1)) a.ttl = std::stoi(argv[++i]);
        else if (s == "--rto-ms" && need(1)) a.rto_ms = std::stoi(argv[++i]);
        else if (s == "--retries" && need(1)) a.retries = std::stoi(argv[++i]);
        else if (s == "--chunk" && need(1)) a.max_app_payload = (size_t)std::stoul(argv[++i]);
        else if (s == "-h" || s == "--help") { usage(argv[0]); return false; }
        else { std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); return false; }
    }
    if (a.expected <= 0) { std::cerr << "--expected must be >= 1\n"; return false; }
    if (a.max_app_payload < 1 || a.max_app_payload > 65507 - sizeof(RmHeader)) {
        std::cerr << "--chunk invalid; must be 1.." << (65507 - sizeof(RmHeader)) << "\n"; return false;
    }
    return true;
}

class PeelSender {
public:
    explicit PeelSender(const Args& args) : A(args) {}
    ~PeelSender() { if (fd >= 0) close(fd); }

    bool init() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return false; }

        // Bind local sender port to receive unicast ACKs
        sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_ANY); local.sin_port = htons(A.sender_port);
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) { perror("bind sender_port"); return false; }

        // Multicast options
        if (A.iface_ip) {
            in_addr ifaceAddr{};
            if (inet_pton(AF_INET, A.iface_ip->c_str(), &ifaceAddr) != 1) {
                std::cerr << "Invalid --iface IP: " << *A.iface_ip << "\n"; return false; }
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaceAddr, sizeof(ifaceAddr)) < 0) {
                perror("setsockopt IP_MULTICAST_IF"); return false; }
        }
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &A.ttl, sizeof(A.ttl)) < 0) {
            perror("setsockopt IP_MULTICAST_TTL"); return false; }
        int loop = 1; // was 0 with comment: avoid receiving our own multicast on this socket
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
            perror("setsockopt IP_MULTICAST_LOOP"); return false; }

        // Destination group
        memset(&mcast, 0, sizeof(mcast));
        mcast.sin_family = AF_INET; mcast.sin_port = htons(A.port);
        if (inet_pton(AF_INET, A.group.c_str(), &mcast.sin_addr) != 1) {
            std::cerr << "Invalid --group IP" << "\n"; return false; }

        // Socket recv timeout (we'll also layer a manual loop)
        timeval tv{}; tv.tv_sec = A.rto_ms / 1000; tv.tv_usec = (A.rto_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_RCVTIMEO"); return false; }

        std::cerr << "Bound for ACKs on :" << A.sender_port << ", sending to "
                  << A.group << ":" << A.port << ", expected receivers=" << A.expected << "\n";
        return true;
    }

    bool run() {
        if (!handshake()) return false;
        if (!A.file.empty()) return send_file(A.file);
        // Demo mode: send 5 small DATA packets and then FIN
        std::vector<std::string> msgs;
        for (int i = 1; i <= 5; ++i) {
            msgs.push_back("hello-" + std::to_string(i));
        }
        uint32_t seq = 1;
        for (auto& s : msgs) {
            if (!send_data(seq++, std::vector<uint8_t>(s.begin(), s.end()))) return false;
        }
        return send_fin(seq++);
    }

    bool send_file_windowed_twothreaded(std::string file) {
        return false;
    }


    static void add_dummy_elem_to_window(std::list<WindowEntry> *window, uint32_t *seq) {
        auto contents = std::vector<uint8_t>();
        contents.push_back('t');
        contents.push_back('e');
        contents.push_back('s');
        contents.push_back('t');
        window->push_back(WindowEntry{contents, false, (*seq)++,0,0});
    }

    static int get_num_additional_packets_sendable(std::list<WindowEntry> *window, int cwnd) {
        int len = window->size();
        return cwnd - len;
    }

    bool run_windowed_sliding() {
        auto cwnd = 10;
        if (!handshake()) return false;
        if (!A.file.empty()) return send_file_windowed_twothreaded(A.file);
        uint32_t seq = 1;

        std::cerr << "handshake successful, entering data transmission" << std::endl;

        // init the window with the data
        std::list window = std::list<WindowEntry>();

        for (int i = 0; i < cwnd; i++) {
            add_dummy_elem_to_window(&window, &seq);
        }

        // storing retries for all packets
        auto attempts = 0;
        std::atomic<bool> halt{false};
        std::mutex mutex;
        // while the window is not empty:
        std::thread ackthread(run_windowed_sliding_ackthread, this, &window, &mutex, &halt, cwnd, &seq);

        while (attempts < A.retries) {
            // attempt to send each packet in the window if it isn't flagged as sent
            mutex.lock();
            auto empty = window.empty();
            if (empty) {
                mutex.unlock();
                break;
            }

            for (auto it = window.begin(); it != window.end(); it++) {
                auto app =  (*it).contents;
                uint32_t ts = now_ms();
                std::vector<uint8_t> pkt(sizeof(RmHeader) + app.size());
                RmHeader h{}; fill_header(h, (*it).sequence_number, FLG_DATA, /*wnd*/1, ts, 0);
                serialize_header(h, pkt.data());
                if (!app.empty()) memcpy(pkt.data() + sizeof(RmHeader), app.data(), app.size());
                if (!xmit(pkt)) {
                    halt = true;
                    ackthread.join();
                    return false; // failed to transmit window
                }
                std::cerr << "DATA seq=" << (*it).sequence_number << " len=" << app.size() << " (try " << (attempts+1) << ")\n";
            }
            mutex.unlock();
            // wait the retry duration

            std::this_thread::sleep_for(std::chrono::milliseconds(A.rto_ms));
            attempts++;
        }
        halt = true;
        ackthread.join();
    }

    static void run_windowed_sliding_ackthread(PeelSender *p, std::list<WindowEntry> *window, std::mutex *mutex, std::atomic<bool> *halt, int cwnd, uint32_t *lastseq) {
        while (true) {
            // loop condition
            const bool halting = *halt;
            if (halting) {
                break;
            }
            // listen for acks and flag as acked
            auto [res, seq] = p->wait_for_ack();
            if (res) {
                mutex->lock();
                for (auto it = window->begin(); it != window->end(); it++) {
                    if ((*it).sequence_number == seq) {
                        std::cerr << "listen: received ack for seq number " << seq << std::endl;
                        (*it).ack_status = true;
                    }
                }
                // clean up the window, if empty, break
                while (!window->empty()) {
                    auto front = window->front();
                    if (front.ack_status != true) {
                        break;
                    }
                    window->pop_front();
                    std::cerr << "remove: popping back because of ack status true" << std::endl;
                    auto amt = get_num_additional_packets_sendable(window, cwnd);
                    for (int i = 0; i < amt; i++) {
                        add_dummy_elem_to_window(window, lastseq);
                    }
                }
                mutex->unlock();
            }
        }
    }

    bool run_windowed_twothreaded() {
        // separate thread for receiving acks
        auto cwnd = 10;
        if (!handshake()) return false;
        if (!A.file.empty()) return send_file_windowed_twothreaded(A.file);
        uint32_t seq = 1;

        std::cerr << "handshake successful, entering data transmission" << std::endl;

        // init the window with the data
        std::list window = std::list<WindowEntry>();

        for (int i = 0; i < cwnd; i++) {
            auto contents = std::vector<uint8_t>();
            contents.push_back('t');
            contents.push_back('e');
            contents.push_back('s');
            contents.push_back('t');
            window.push_back(WindowEntry{contents, false, seq++,0,0});
        }

        // storing retries for all packets
        auto attempts = 0;
        std::atomic<bool> halt{false};
        std::mutex mutex;
        // while the window is not empty:
        std::thread ackthread(run_windowed_twothreaded_ackthread, this, &window, &mutex, &halt);

        while (attempts < A.retries) {
            // attempt to send each packet in the window if it isn't flagged as sent
            mutex.lock();
            auto empty = window.empty();
            if (empty) {
                mutex.unlock();
                break;
            }

            for (auto it = window.begin(); it != window.end(); it++) {
                auto app =  (*it).contents;
                uint32_t ts = now_ms();
                std::vector<uint8_t> pkt(sizeof(RmHeader) + app.size());
                RmHeader h{}; fill_header(h, (*it).sequence_number, FLG_DATA, /*wnd*/1, ts, 0);
                serialize_header(h, pkt.data());
                if (!app.empty()) memcpy(pkt.data() + sizeof(RmHeader), app.data(), app.size());
                if (!xmit(pkt)) {
                    halt = true;
                    ackthread.join();
                    return false; // failed to transmit window
                }
                std::cerr << "DATA seq=" << (*it).sequence_number << " len=" << app.size() << " (try " << (attempts+1) << ")\n";
            }
            mutex.unlock();
            // wait the retry duration

            std::this_thread::sleep_for(std::chrono::milliseconds(A.rto_ms));
            attempts++;
        }
        halt = true;
        ackthread.join();
    }

    static void run_windowed_twothreaded_ackthread(PeelSender *p, std::list<WindowEntry> *window, std::mutex *mutex, std::atomic<bool> *halt) {
        while (true) {
            // loop condition
            const bool halting = *halt;
            if (halting) {
                break;
            }
            // listen for acks and flag as acked
            auto [res, seq] = p->wait_for_ack();
            if (res) {
                mutex->lock();
                for (auto it = window->begin(); it != window->end(); it++) {
                    if ((*it).sequence_number == seq) {
                        std::cerr << "listen: received ack for seq number " << seq << std::endl;
                        (*it).ack_status = true;
                    }
                }
                // clean up the window, if empty, break
                while (!window->empty()) {
                    auto front = window->front();
                    if (front.ack_status != true) {
                        break;
                    }
                    window->pop_front();
                    std::cerr << "remove: popping back because of ack status true" << std::endl;
                }
                mutex->unlock();
            }
        }
    }


    bool run_windowed_singlethreaded() {
        auto cwnd = 10;
        if (!handshake()) return false;
        if (!A.file.empty()) return send_file_windowed_singlethreaded(A.file);
        uint32_t seq = 1;

        std::cerr << "handshake successful, entering data transmission" << std::endl;

        // init the window with the data
        std::list window = std::list<WindowEntry>();

        for (int i = 0; i < cwnd; i++) {
            auto contents = std::vector<uint8_t>();
            contents.push_back('t');
            contents.push_back('e');
            contents.push_back('s');
            contents.push_back('t');
            window.push_back(WindowEntry{contents, false, seq++,0,0});
        }

        // storing retries for all packets
        auto attempts = 0;
        // while the window is not empty:

        while (!window.empty() and attempts < A.retries) {
            // attempt to send each packet in the window if it isn't flagged as sent
            for (auto it = window.begin(); it != window.end(); it++) {
                auto app =  (*it).contents;
                uint32_t ts = now_ms();
                std::vector<uint8_t> pkt(sizeof(RmHeader) + app.size());
                RmHeader h{}; fill_header(h, (*it).sequence_number, FLG_DATA, /*wnd*/1, ts, 0);
                serialize_header(h, pkt.data());
                if (!app.empty()) memcpy(pkt.data() + sizeof(RmHeader), app.data(), app.size());
                if (!xmit(pkt)) return false; // failed to transmit window

                std::cerr << "DATA seq=" << (*it).sequence_number << " len=" << app.size() << " (try " << (attempts+1) << ")\n";
            }
            attempts++;

            // for the retry duration:

            auto listen_start_time = now_ms();
            while (now_ms() - listen_start_time < A.rto_ms) {
                // listen for acks and flag as acked
                auto [res, seq] = wait_for_ack();
                if (res) {
                    for (auto it = window.begin(); it != window.end(); it++) {
                        if ((*it).sequence_number == seq) {
                            std::cerr << "listen: received ack for seq number" << seq << std::endl;
                            (*it).ack_status = true;
                        }
                    }
                    // clean up the window, if empty, break
                    const auto& first = window.front();
                    if (first.ack_status == true) {
                        window.pop_front();
                        std::cerr << "remove: popping back because of ack status true" << std::endl;
                    }
                }
            }
        }
    }

    bool send_file_windowed_singlethreaded(std::string file) {

    }

    // consider renaming
    bool run_windowed() {
        // this implementation will use a std::vector for now
        // it can later use a Dmitry Vyukov queue
        auto cwnd = 10;
        if (!handshake()) return false;
        if (!A.file.empty()) return send_file_windowed(A.file);
        uint32_t seq = 1;

        std::cerr << "handshake successful, entering data transmission" << std::endl;
        // auto window = new mpsc_bounded_queue<WindowEntry>(cwnd);

        // creating a window of packets
        std::mutex mutex;
        auto window = new std::vector<WindowEntry>();
        for (int i = 0; i < cwnd; i++) {
            auto contents = std::vector<uint8_t>();
            contents.push_back('t');
            contents.push_back('e');
            contents.push_back('s');
            contents.push_back('t');
            window->push_back(WindowEntry{contents, false, seq++,0,0});
        }
        std::cerr << "created dummy data" << std::endl;
        bool halt = false;
        auto seqs_to_timestamps_sent = std::map<uint32_t, uint64_t>();

        // sending packets all at once and waiting for ACKs
        // thread 1 (listenthread): listen for ACKs and mutate the ack statuses
        std::thread listener(&PeelSender::listenthread, this, window, &seqs_to_timestamps_sent, &halt, &mutex);
        // thread 2 (sendthread) (in this function): send all the packets, then exit
        // thread 3: (remthread) removing the first entry if its ack status is true
        std::thread remover(remthread, window, &mutex);

        std::cerr << "created listener and remover threads" << std::endl;

        // sending packets: all at once with retries for each
        uint64_t retry_delay = 10;
        while (!halt) {
            std::cerr << "trying from the top of the while loop in run_windowed" << std::endl;
            auto num_not_retrying = 0;
            auto acked = 0;
            mutex.lock();
            for (int window_index = 0; window_index < window->size(); ++window_index) {
                if (static_cast<uint64_t>(now_ms()) - (*window)[window_index].last_retry < retry_delay) {
                    mutex.unlock();
                    continue;
                }
                if ((*window)[window_index].ack_status == true) {
                    mutex.unlock();
                    acked++;
                    continue;
                }
                if ((*window)[window_index].num_tries > A.retries) {
                    num_not_retrying++;
                    mutex.unlock();
                    continue;
                }
                auto app = (*window)[window_index].contents;
                 // is this a good idea, the double lock/unlock?
                uint32_t ts = now_ms();
                std::vector<uint8_t> pkt(sizeof(RmHeader) + app.size());
                RmHeader h{}; fill_header(h, (*window)[window_index].sequence_number, FLG_DATA, /*wnd*/1, ts, 0);
                serialize_header(h, pkt.data());
                if (!app.empty()) memcpy(pkt.data() + sizeof(RmHeader), app.data(), app.size());
                if (!xmit(pkt)) return false; // failed to transmit window

                std::cerr << "DATA seq=" << (*window)[window_index].sequence_number << " len=" << app.size() << " (try " << ((*window)[window_index].num_tries+1) << ")\n";
                (*window)[window_index].num_tries++;
            }
            mutex.unlock();
            if (num_not_retrying == window->size()) {
                std::cerr << "Failed to deliver DATA seq=" << seq << " after retries\n";
                return false;
            }
            if (window->empty()) { // because of acks being sent
                return true;
            }
        }

        // cleanup
        delete window;
        return true;
    }
    static void remthread(std::vector<WindowEntry> *v, std::mutex *m) {
        std::cerr << "entering remthread" << std::endl;
        while (v->empty() != true) {
            const auto& first = v->front();
            if (first.ack_status == true) {
                m->lock();
                v->pop_back();
                m->unlock();
                std::cerr << "remthread: popping back because of ack status true" << std::endl;
            }
        }
    }
    void listenthread(std::vector<WindowEntry> *l, std::map<uint32_t, uint64_t> *seqs_to_timestamps_sent, bool *halt, std::mutex *m) {
        // listens for ACKs for all sequence numbers provided
        std::cerr << "entering listenthread" << std::endl;
        while (!*halt) {
            auto [res, seq] = wait_for_ack();
            if (res) {
                for (long unsigned int i = 0; i < l->size(); i++) {
                    if ((*l)[i].sequence_number == seq) {
                        std::cerr << "listenthread: received ack for seq number" << seq << std::endl;
                        m->lock();
                        (*l)[i].ack_status = true;
                        m->unlock();
                    }
                }
            }
        }
    }
private:
    bool handshake() {
        std::unordered_map<PeerKey, sockaddr_in, PeerKeyHash> cohort_map; // by (ip,port) from recvfrom
        int retries = 0;
        while (retries <= A.retries) {
            uint32_t ts = now_ms();
            RmHeader h{}; fill_header(h, /*seq*/0, FLG_SYN, /*wnd*/1, ts, /*tsecr*/0);
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            serialize_header(h, pkt.data());
            if (!xmit(pkt)) return false;
            std::cerr << "SYN -> group (try " << (retries+1) << "/" << (A.retries+1) << ")\n";

            auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
            while (Clock::now() < deadline) {
                sockaddr_in peer{}; RmHeader rh{};
                if (!recv_header(peer, rh)) break; // timeout or error -> break to maybe retransmit
                if (!verify_header(rh)) continue;
                if ((ntohs(rh.flags) & (FLG_SYN|FLG_ACK)) != (FLG_SYN|FLG_ACK)) continue; // need SYN|ACK
                if (ntohl(rh.tsecr) != ts) continue; // must echo our ts
                PeerKey k{ peer.sin_addr.s_addr, peer.sin_port };
                if (!cohort_map.count(k)) {
                    cohort_map[k] = peer;
                    std::cerr << "  SYN|ACK from " << addr_to_string(peer) << " (" << cohort_map.size() << "/" << A.expected << ")\n";
                }
                if ((int)cohort_map.size() >= A.expected) break;
            }
            if ((int)cohort_map.size() >= A.expected) break; // success
            ++retries;
        }
        if ((int)cohort_map.size() < A.expected) {
            std::cerr << "Handshake failed: got " << cohort_map.size() << "/" << A.expected << " receivers\n"; return false;
        }
        // Solidify cohort
        cohort.clear(); cohort.reserve(cohort_map.size());
        for (auto& kv : cohort_map) cohort.push_back(kv.second);
        // Inform cohort: START (multicast)
        uint32_t ts = now_ms();
        RmHeader start{}; fill_header(start, /*seq*/0, FLG_START, /*wnd*/1, ts, 0);
        std::vector<uint8_t> pkt(sizeof(RmHeader));
        serialize_header(start, pkt.data());
        if (!xmit(pkt)) return false;
        std::cerr << "Handshake complete. Cohort size=" << cohort.size() << ". Sent START.\n";
        return true;
    }

    bool send_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Failed to open file: " << path << "\n"; return false; }
        uint32_t seq = 1;
        std::vector<uint8_t> buf(A.max_app_payload);
        while (true) {
            f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
            std::streamsize got = f.gcount();
            if (got <= 0) break;
            std::vector<uint8_t> chunk(buf.begin(), buf.begin() + got);
            if (!send_data(seq++, chunk)) return false;
        }
        return send_fin(seq++);
    }

    bool send_file_windowed(const std::string& path) {
        std::cerr << "file given, sending file with window-based transmission" << std::endl;
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Failed to open file: " << path << "\n"; return false; }
        uint32_t seq = 1;
        std::vector<uint8_t> buf(A.max_app_payload);
    }

    bool send_data(uint32_t seq, const std::vector<uint8_t>& app) {
        for (int attempt = 0; attempt <= A.retries; ++attempt) {
            uint32_t ts = now_ms();
            std::vector<uint8_t> pkt(sizeof(RmHeader) + app.size());
            RmHeader h{}; fill_header(h, seq, FLG_DATA, /*wnd*/1, ts, 0);
            serialize_header(h, pkt.data());
            if (!app.empty()) memcpy(pkt.data() + sizeof(RmHeader), app.data(), app.size());
            if (!xmit(pkt)) return false;
            std::cerr << "DATA seq=" << seq << " len=" << app.size() << " (try " << (attempt+1) << ")\n";
            if (wait_all_acks(seq, ts)) return true; // success
            std::cerr << "  timeout waiting DATA ACKs -> retransmit\n";
        }
        std::cerr << "Failed to deliver DATA seq=" << seq << " after retries\n";
        return false;
    }

    bool send_fin(uint32_t seq) {
        for (int attempt = 0; attempt <= A.retries; ++attempt) {
            uint32_t ts = now_ms();
            std::vector<uint8_t> pkt(sizeof(RmHeader));
            RmHeader h{}; fill_header(h, seq, FLG_FIN, /*wnd*/0, ts, 0);
            serialize_header(h, pkt.data());
            if (!xmit(pkt)) return false;
            std::cerr << "FIN seq=" << seq << " (try " << (attempt+1) << ")\n";
            if (wait_all_acks(seq, ts)) {
                std::cerr << "All receivers ACKed FIN. Done.\n";
                return true;
            }
            std::cerr << "  timeout waiting FIN ACKs -> retransmit\n";
        }
        std::cerr << "Failed to deliver FIN after retries\n";
        return false;
    }

    bool wait_all_acks(uint32_t seq, uint32_t ts_sent) {
        std::unordered_set<uint64_t> got; got.reserve(cohort.size()*2);
        auto pack_key = [](const sockaddr_in& a){ return (uint64_t)a.sin_addr.s_addr << 16 | ntohs(a.sin_port); };
        auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
        while (Clock::now() < deadline) {
            sockaddr_in peer{}; RmHeader rh{};
            if (!recv_header(peer, rh)) break; // timeout -> break to trigger retransmit by caller
            if (!verify_header(rh)) continue;
            if ((ntohs(rh.flags) & FLG_ACK) == 0) continue;
            // We require ack.seq == our seq and rh.tsecr == ts_sent
            if (ntohl(rh.seq) != seq) continue;
            if (ntohl(rh.tsecr) != ts_sent) continue;
            // Check that peer is part of cohort
            bool member = false;
            for (auto& c : cohort) {
                if (c.sin_addr.s_addr == peer.sin_addr.s_addr && c.sin_port == peer.sin_port) { member = true; break; }
            }
            if (!member) continue; // ignore unknown
            got.insert(pack_key(peer));
            if (got.size() >= cohort.size()) return true;
        }
        return false;
    }
    std::tuple<bool, uint32_t> wait_for_ack() {
        std::unordered_set<uint64_t> got; got.reserve(cohort.size()*2);
        auto pack_key = [](const sockaddr_in& a){ return (uint64_t)a.sin_addr.s_addr << 16 | ntohs(a.sin_port); };
        auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
        while (Clock::now() < deadline) {
            sockaddr_in peer{}; RmHeader rh{};
            if (!recv_header(peer, rh)) break; // timeout -> break to trigger retransmit by caller
            if (!verify_header(rh)) continue;
            if ((ntohs(rh.flags) & FLG_ACK) == 0) continue;
            // We require ack.seq == our seq and rh.tsecr == ts_sent
            uint32_t seq = ntohl(rh.seq);
            // omitted temporarily
            // if (ntohl(rh.tsecr) != seq_to_timestamps_sent->find(seq)) continue;
            // Check that peer is part of cohort
            bool member = false;
            for (auto& c : cohort) {
                if (c.sin_addr.s_addr == peer.sin_addr.s_addr && c.sin_port == peer.sin_port) { member = true; break; }
            }
            if (!member) continue; // ignore unknown
            got.insert(pack_key(peer));
            if (got.size() >= cohort.size()) return std::tuple<bool,uint32_t>(true, seq);
        }
        return std::tuple<bool,uint32_t>(false, 0);
    }

    bool xmit(const std::vector<uint8_t>& bytes) {
        ssize_t n = sendto(fd, bytes.data(), bytes.size(), 0, (sockaddr*)&mcast, sizeof(mcast));
        if (n < 0) { perror("sendto"); return false; }
        if ((size_t)n != bytes.size()) {
            std::cerr << "Partial send!? sent=" << n << " expected=" << bytes.size() << "\n"; return false;
        }
        return true;
    }

    bool recv_header(sockaddr_in& from, RmHeader& out) {
        uint8_t buf[sizeof(RmHeader) + 16]; // header only expected; allow tiny extra
        socklen_t alen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&from, &alen);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) return false; // timeout
            perror("recvfrom"); return false;
        }
        if ((size_t)n < sizeof(RmHeader)) return false;
        deserialize_header(buf, out);
        return true;
    }

    void fill_header(RmHeader& h, uint32_t seq, uint16_t flags, uint16_t wnd, uint32_t ts, uint32_t tsecr) {
        h.seq = htonl(seq);
        h.src_port = htons(A.sender_port);
        h.flags = htons(flags);
        h.window = htons(wnd);
        h.checksum = 0;
        h.tsval = htonl(ts);
        h.tsecr = htonl(tsecr);
    }

    void serialize_header(RmHeader& h, uint8_t* out) {
        // compute checksum over header with checksum=0
        RmHeader tmp = h;
        tmp.checksum = 0;
        uint16_t sum = checksum16(&tmp, sizeof(tmp));
        h.checksum = sum;
        memcpy(out, &h, sizeof(h));
    }

    void deserialize_header(const uint8_t* in, RmHeader& h) {
        memcpy(&h, in, sizeof(h));
    }

    bool verify_header(const RmHeader& net) {
        // recompute checksum and compare
        RmHeader tmp = net; uint16_t rcv = tmp.checksum; tmp.checksum = 0; uint16_t calc = checksum16(&tmp, sizeof(tmp));
        if (rcv != calc) return false;
        return true;
    }

private:
    Args A;
    int fd = -1;
    sockaddr_in mcast{};
    std::vector<sockaddr_in> cohort; // fixed after handshake
};

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 1;
    PeelSender s(args);
    if (!s.init()) return 2;
    if (!s.run_windowed_sliding()) return 3;
    return 0;
}
