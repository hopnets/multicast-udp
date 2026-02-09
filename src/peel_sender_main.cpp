#include "PeelSender.h"

#include <iostream>
#include <string>

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --group A.B.C.D --port P --sender-port S --expected N [--file path]"
              << " [--iface X.Y.Z.W] [--ttl T] [--rto-ms MS] [--retries K] [--chunk BYTES]\n";
}

static bool parse_args(int argc, char** argv, PeelSenderArgs& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more) {
            if (i + more >= argc) { usage(argv[0]); return false; }
            return true;
        };

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
    if (a.max_app_payload < 1 || a.max_app_payload > 65507 - sizeof(PeelHeader)) {
        std::cerr << "--chunk invalid; must be 1.." << (65507 - sizeof(PeelHeader)) << "\n";
        return false;
    }
    return true;
}

int main(int argc, char** argv) {
    PeelSenderArgs args;
    if (!parse_args(argc, argv, args)) return 1;

    PeelSender s(args);
    if (!s.init()) return 2;
    if (!s.run()) return 3;
    return 0;
}
