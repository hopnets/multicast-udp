#pragma once

#include "peel_protocol.h"

#include <cstdint>
#include <fstream>
#include <netinet/in.h>
#include <optional>
#include <string>

struct PeelReceiverArgs {
    std::string group = "239.255.0.1";          // multicast group
    uint16_t port = 5000;                        // multicast port
    std::optional<std::string> iface_ip;         // optional local interface IPv4 for group join
    std::string out_path;                        // optional output file
    int rcvbuf = 4 * 1024 * 1024;                // receive buffer size
};

class PeelReceiver {
public:
    explicit PeelReceiver(const PeelReceiverArgs& args);
    ~PeelReceiver();

    PeelReceiver(const PeelReceiver&) = delete;
    PeelReceiver& operator=(const PeelReceiver&) = delete;

    bool init();
    bool run();

private:
    bool verify_header(const PeelHeader& net);
    void send_ack(const sockaddr_in& to, uint32_t seq, uint16_t flags,
                  uint32_t tsecr_in, uint8_t retrans_id_in);
    uint16_t local_port() const;

private:
    PeelReceiverArgs A;
    int fd = -1;
    std::ofstream ofs;
};
