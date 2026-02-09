#pragma once

#include "peel_protocol.h"

#include <cstddef>
#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <vector>

struct PeelSenderArgs {
    std::string group = "239.255.0.1";          // multicast group
    uint16_t port = 5000;                        // multicast dest port
    uint16_t sender_port = 45000;                // local bind port for ACKs
    int expected = 1;                            // expected receivers
    std::string file;                            // optional payload file
    std::optional<std::string> iface_ip;         // optional egress interface IPv4
    int ttl = 1;                                 // multicast TTL
    int rto_ms = 250;                            // retransmission timeout
    int retries = 20;                            // max retries per step
    size_t max_app_payload = 1450;               // default (1472 total - 22 header)
};

class PeelSender {
public:
    explicit PeelSender(const PeelSenderArgs& args);
    ~PeelSender();

    PeelSender(const PeelSender&) = delete;
    PeelSender& operator=(const PeelSender&) = delete;

    bool init();
    bool run();

private:
    bool handshake();
    bool send_file(const std::string& path);
    bool send_data(uint32_t seq, const std::vector<uint8_t>& app);
    bool send_fin(uint32_t seq);
    bool wait_all_acks(uint32_t seq, uint32_t ts_sent, uint8_t retrans_id_expected);

    bool xmit(const std::vector<uint8_t>& bytes);
    bool recv_header(sockaddr_in& from, PeelHeader& out);

    void fill_header(PeelHeader& h, uint32_t seq, uint16_t flags, uint16_t wnd,
                     uint32_t ts, uint32_t tsecr, uint8_t retrans_id);

    void serialize_header(PeelHeader& h, uint8_t* out);
    void deserialize_header(const uint8_t* in, PeelHeader& h);
    bool verify_header(const PeelHeader& net);

private:
    PeelSenderArgs A;
    int fd = -1;
    sockaddr_in mcast{};
    std::vector<sockaddr_in> cohort; // fixed after handshake
};
