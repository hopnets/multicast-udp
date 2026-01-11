sudo apt install smcroute
sudo ip route add 239.255.0.1/32 dev ens34
sudo smcroutectl join ens34 239.255.0.1
netstat -g | grep 239.255.0.1
