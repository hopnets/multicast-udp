#include "PeelSender.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Clock = std::chrono::steady_clock;

namespace {

struct PeerKey {
    uint32_t ip;   // network order
    uint16_t port; // network order
    bool operator==(const PeerKey& o) const { return ip == o.ip && port == o.port; }
};

struct PeerKeyHash {
    size_t operator()(const PeerKey& k) const {
        return static_cast<size_t>(k.ip) * 1315423911u + k.port;
    }
};

} // namespace

PeelSender::PeelSender(const PeelSenderArgs& args) : A(args) {}

PeelSender::~PeelSender() {
    if (fd >= 0) close(fd);
}

bool PeelSender::init() {
    fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return false; }

    // Bind local sender port to receive unicast ACKs
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(A.sender_port);
    if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) {
        perror("bind sender_port");
        return false;
    }

    // Multicast options
    if (A.iface_ip) {
        in_addr ifaceAddr{};
        if (inet_pton(AF_INET, A.iface_ip->c_str(), &ifaceAddr) != 1) {
            std::cerr << "Invalid --iface IP: " << *A.iface_ip << "\n";
            return false;
        }
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaceAddr, sizeof(ifaceAddr)) < 0) {
            perror("setsockopt IP_MULTICAST_IF");
            return false;
        }
    }
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &A.ttl, sizeof(A.ttl)) < 0) {
        perror("setsockopt IP_MULTICAST_TTL");
        return false;
    }
    int loop = 0; // avoid receiving our own multicast on this socket
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        perror("setsockopt IP_MULTICAST_LOOP");
        return false;
    }

    // Destination group
    std::memset(&mcast, 0, sizeof(mcast));
    mcast.sin_family = AF_INET;
    mcast.sin_port = htons(A.port);
    if (inet_pton(AF_INET, A.group.c_str(), &mcast.sin_addr) != 1) {
        std::cerr << "Invalid --group IP\n";
        return false;
    }

    // Socket recv timeout
    timeval tv{};
    tv.tv_sec = A.rto_ms / 1000;
    tv.tv_usec = (A.rto_ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        return false;
    }

    std::cerr << "Bound for ACKs on :" << A.sender_port
              << ", sending to " << A.group << ":" << A.port
              << ", expected receivers=" << A.expected << "\n";
    return true;
}

bool PeelSender::run() {
    if (!handshake()) return false;

    if (!A.file.empty()) return send_file(A.file);

    // Demo mode: send 5 small DATA packets and then FIN
    std::vector<std::string> msgs;
    for (int i = 1; i <= 5; ++i) msgs.push_back("hello-" + std::to_string(i));

    uint32_t seq = 1;
    for (auto& s : msgs) {
        if (!send_data(seq++, std::vector<uint8_t>(s.begin(), s.end()))) return false;
    }
    return send_fin(seq++);
}

bool PeelSender::handshake() {
    auto handshake_start = Clock::now();
    auto elapsed_us = [&]() -> long long {
        return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - handshake_start).count();
    };

    std::unordered_map<PeerKey, sockaddr_in, PeerKeyHash> cohort_map;

    constexpr uint8_t kMaxRetransId = 8;
    bool success = false;

    for (int attempt = 0, retrans_id = 1;
         attempt <= A.retries && retrans_id <= kMaxRetransId;
         ++attempt, ++retrans_id) {

        if (attempt > 0) cohort_map.clear();

        uint32_t ts = peel_now_ms();
        PeelHeader h{};
        fill_header(h, /*seq*/0, FLG_SYN, /*wnd*/1, ts, /*tsecr*/0, (uint8_t)retrans_id);

        std::vector<uint8_t> pkt(sizeof(PeelHeader));
        serialize_header(h, pkt.data());

        if (!xmit(pkt)) {
            auto us = elapsed_us();
            std::cerr << "Handshake failed while sending SYN after "
                      << us << " us (" << (us / 1000.0) << " ms)\n";
            return false;
        }

        auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
        while (Clock::now() < deadline) {
            sockaddr_in peer{};
            PeelHeader rh{};
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
        std::cerr << "Handshake failed after " << us << " us ("
                  << (us / 1000.0) << " ms): got " << cohort_map.size()
                  << "/" << A.expected << " receivers\n";
        return false;
    }

    cohort.clear();
    cohort.reserve(cohort_map.size());
    for (auto& kv : cohort_map) cohort.push_back(kv.second);

    // Inform cohort: START (multicast)
    uint32_t ts = peel_now_ms();
    PeelHeader start{};
    fill_header(start, /*seq*/0, FLG_START, /*wnd*/1, ts, 0, /*retrans_id*/1);

    std::vector<uint8_t> pkt(sizeof(PeelHeader));
    serialize_header(start, pkt.data());

    if (!xmit(pkt)) {
        auto us = elapsed_us();
        std::cerr << "Handshake failed while sending START after "
                  << us << " us (" << (us / 1000.0) << " ms), cohort size="
                  << cohort.size() << "\n";
        return false;
    }

    auto us = elapsed_us();
    std::cerr << "Handshake complete in " << us << " us ("
              << (us / 1000.0) << " ms). Cohort size=" << cohort.size()
              << ". Sent START.\n";
    return true;
}

bool PeelSender::send_file(const std::string& path) {
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

bool PeelSender::send_data(uint32_t seq, const std::vector<uint8_t>& app) {
    constexpr uint8_t kMaxRetransId = 8;

    for (int attempt = 0, rid = 1;
         attempt <= A.retries && rid <= kMaxRetransId;
         ++attempt, ++rid) {

        uint8_t retrans_id = (uint8_t)rid;
        uint32_t ts = peel_now_ms();

        std::vector<uint8_t> pkt(sizeof(PeelHeader) + app.size());
        PeelHeader h{};
        fill_header(h, seq, FLG_DATA, /*wnd*/1, ts, 0, retrans_id);
        serialize_header(h, pkt.data());

        if (!app.empty()) std::memcpy(pkt.data() + sizeof(PeelHeader), app.data(), app.size());
        if (!xmit(pkt)) return false;

        std::cerr << "DATA seq=" << seq << " len=" << app.size()
                  << " (try " << (attempt + 1) << ", retrans_id=" << (int)retrans_id << ")\n";

        if (wait_all_acks(seq, ts, retrans_id)) return true;
        std::cerr << "  timeout waiting DATA ACKs -> retransmit\n";
    }

    std::cerr << "Failed to deliver DATA seq=" << seq << " after retries/retrans_id limit\n";
    return false;
}

bool PeelSender::send_fin(uint32_t seq) {
    constexpr uint8_t kMaxRetransId = 8;

    for (int attempt = 0, rid = 1;
         attempt <= A.retries && rid <= kMaxRetransId;
         ++attempt, ++rid) {

        uint8_t retrans_id = (uint8_t)rid;
        uint32_t ts = peel_now_ms();

        std::vector<uint8_t> pkt(sizeof(PeelHeader));
        PeelHeader h{};
        fill_header(h, seq, FLG_FIN, /*wnd*/0, ts, 0, retrans_id);
        serialize_header(h, pkt.data());

        if (!xmit(pkt)) return false;

        std::cerr << "FIN seq=" << seq
                  << " (try " << (attempt + 1) << ", retrans_id=" << (int)retrans_id << ")\n";

        if (wait_all_acks(seq, ts, retrans_id)) {
            std::cerr << "All receivers ACKed FIN. Done.\n";
            return true;
        }
        std::cerr << "  timeout waiting FIN ACKs -> retransmit\n";
    }

    std::cerr << "Failed to deliver FIN after retries/retrans_id limit\n";
    return false;
}

bool PeelSender::wait_all_acks(uint32_t seq, uint32_t ts_sent, uint8_t retrans_id_expected) {
    std::unordered_set<uint64_t> got;
    got.reserve(cohort.size() * 2);

    auto pack_key = [](const sockaddr_in& a) {
        return (uint64_t)a.sin_addr.s_addr << 16 | ntohs(a.sin_port);
    };

    auto deadline = Clock::now() + std::chrono::milliseconds(A.rto_ms);
    while (Clock::now() < deadline) {
        sockaddr_in peer{};
        PeelHeader rh{};
        if (!recv_header(peer, rh)) break;

        if (!verify_header(rh)) continue;
        if ((ntohs(rh.flags) & FLG_ACK) == 0) continue;

        if (ntohl(rh.seq) != seq) continue;
        if (ntohl(rh.tsecr) != ts_sent) continue;
        if (rh.retrans_id != retrans_id_expected) continue;

        bool member = false;
        for (auto& c : cohort) {
            if (c.sin_addr.s_addr == peer.sin_addr.s_addr && c.sin_port == peer.sin_port) {
                member = true;
                break;
            }
        }
        if (!member) continue;

        got.insert(pack_key(peer));
        if (got.size() >= cohort.size()) return true;
    }
    return false;
}

bool PeelSender::xmit(const std::vector<uint8_t>& bytes) {
    ssize_t n = sendto(fd, bytes.data(), bytes.size(), 0, (sockaddr*)&mcast, sizeof(mcast));
    if (n < 0) { perror("sendto"); return false; }
    if ((size_t)n != bytes.size()) {
        std::cerr << "Partial send!? sent=" << n << " expected=" << bytes.size() << "\n";
        return false;
    }
    return true;
}

bool PeelSender::recv_header(sockaddr_in& from, PeelHeader& out) {
    uint8_t buf[sizeof(PeelHeader) + 16];
    socklen_t alen = sizeof(from);

    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&from, &alen);
    if (n < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) return false;
        perror("recvfrom");
        return false;
    }
    if ((size_t)n < sizeof(PeelHeader)) return false;

    deserialize_header(buf, out);
    return true;
}

void PeelSender::fill_header(PeelHeader& h, uint32_t seq, uint16_t flags, uint16_t wnd,
                             uint32_t ts, uint32_t tsecr, uint8_t retrans_id) {
    h.seq = htonl(seq);
    h.src_port = htons(A.sender_port);
    h.flags = htons(flags);
    h.retrans_id = retrans_id;
    h.reserved = 0;
    h.window = htons(wnd);
    h.checksum = 0;
    h.tsval = htonl(ts);
    h.tsecr = htonl(tsecr);
}

void PeelSender::serialize_header(PeelHeader& h, uint8_t* out) {
    peel_set_header_checksum(h);
    std::memcpy(out, &h, sizeof(h));
}

void PeelSender::deserialize_header(const uint8_t* in, PeelHeader& h) {
    std::memcpy(&h, in, sizeof(h));
}

bool PeelSender::verify_header(const PeelHeader& net) {
    return peel_verify_header_checksum(net);
}
