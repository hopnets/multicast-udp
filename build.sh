mkdir build
rm build/peel_sender
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -ggdb -O0 -o build/peel_sender src/peel_sender.cpp
rm build/peel_sender_1000
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/peel_sender_1000 src/peel_sender_1000.cpp
rm build/peel_sender_1000_noack
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/peel_sender_1000_noack src/peel_sender_1000_noack.cpp
rm build/peel_receiver
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -ggdb -O0 -o build/peel_receiver src/peel_receiver.cpp
rm build/peel_receiver_silent
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/peel_receiver_silent src/peel_receiver_silent.cpp
rm build/gen_payload
# g++ -std=c++17 -O2 -Wall -Wextra -pedantic -ggdb -O0 -fsanitize=address -fno-omit-frame-pointer -o build/peel_sender src/peel_sender.cpp
  #rm build/peel_receiver
  #g++ -std=c++17 -O2 -Wall -Wextra -pedantic -ggdb -O0 -fsanitize=address -fno-omit-frame-pointer -o build/peel_receiver src/peel_receiver.cpp
  #rm build/gen_payload
g++ -std=c++17 -O3 -Wall -Wextra -o build/gen_payload src/gen_payload.cpp
rm build/peel_sender_handshake
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/peel_sender_handshake src/peel_sender_handshake.cpp
rm build/reno_receiver
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/reno_receiver src/reno_receiver.cpp
rm build/reno_sender
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/reno_sender src/reno_sender.cpp
rm build/reno_receiver_bench
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/reno_receiver_bench src/reno_receiver_bench.cpp
rm build/reno_sender_bench
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/reno_sender_bench src/reno_sender_bench.cpp
rm build/peel_sender_raw_bench
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/reno_receiver_bench src/peel_sender_raw_bench.cpp
rm build/peel_receiver_raw_bench
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o build/reno_sender_bench src/peel_receiver_raw_bench.cpp
