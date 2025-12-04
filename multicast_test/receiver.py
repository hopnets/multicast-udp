import socket

#BIND_IP = '10.10.2.255'
BIND_IP = '239.255.0.1'
PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((BIND_IP, PORT))

print(f"Listening for multicast on {BIND_IP}:{PORT}")
while True:
    data, addr = sock.recvfrom(1024)
    print(f"Received message from {addr}: {data.decode()}")
