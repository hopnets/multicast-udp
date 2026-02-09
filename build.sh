#!/usr/bin/env bash
set -euo pipefail

mkdir -p build

# ---------------------------------
# peel_sender (new multi-file build)
# ---------------------------------
rm -f build/peel_sender
g++ -std=c++17 -O2 -Wall -Wextra -pedantic \
  -o build/peel_sender \
  src/peel_sender_main.cpp \
  src/PeelSender.cpp \
  src/peel_protocol.cpp

# ---------------------------------
# peel_receiver (new multi-file build)
# ---------------------------------
rm -f build/peel_receiver
g++ -std=c++17 -O2 -Wall -Wextra -pedantic \
  -o build/peel_receiver \
  src/peel_receiver_main.cpp \
  src/PeelReceiver.cpp \
  src/peel_protocol.cpp

# ---------------------------------
# gen_payload (unchanged)
# ---------------------------------
rm -f build/gen_payload
g++ -std=c++17 -O3 -Wall -Wextra \
  -o build/gen_payload \
  src/gen_payload.cpp
