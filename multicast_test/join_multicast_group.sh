sudo apt install smcroute
sudo ip route add 239.255.0.1/32 dev ens64
sudo smcroutectl join ens64 239.255.0.1
netstat -g | grep 239.255.0.1
