mkdir build
rm build/peel_sender
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/peel_sender src/peel_sender.cpp
rm build/peel_receiver
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/peel_receiver src/peel_receiver.cpp
rm build/gen_payload
g++ -std=c++17 -O3 -Wall -Wextra -o build/gen_payload src/gen_payload.cpp
rm build/peel_sender_handshake
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/peel_sender_handshake src/peel_sender_handshake.cpp