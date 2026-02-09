g++ -O2 -std=c++17 -pthread tcp_client_multi.cpp -o tcp_client_multi
g++ -O2 -std=c++17 -pthread tcp_client_multi_pp.cpp -o tcp_client_multi_pp
g++ -O2 -std=c++17 -pthread tcp_client_multi_1000.cpp -o tcp_client_multi_1000
g++ -O2 -std=c++17 -pthread tcp_client_multi_dummy.cpp -o tcp_client_multi_dummy
g++ -O2 -std=c++17 -pthread tcp_server.cpp -o tcp_server
g++ -O2 -std=c++17 -pthread tcp_server_1000.cpp -o tcp_server_1000