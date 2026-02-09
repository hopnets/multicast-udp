#include "PeelReceiver.h"

#include <iostream>
#include <string>

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --group A.B.C.D --port P [--iface X.Y.Z.W] [--out file] [--rcvbuf BYTES]\n";
}

static bool parse_args(int argc, char** argv, PeelReceiverArgs& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](int more) {
            if (i + more >= argc) { usage(argv[0]); return false; }
            return true;
        };

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

int main(int argc, char** argv) {
    PeelReceiverArgs args;
    if (!parse_args(argc, argv, args)) return 1;

    PeelReceiver r(args);
    if (!r.init()) return 2;
    if (!r.run()) return 3;
    return 0;
}
