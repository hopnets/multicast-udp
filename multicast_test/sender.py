import socket
import time

#BROADCAST_IP = '10.10.2.255'
BROADCAST_IP = '239.255.0.1'
PORT = 5005
MESSAGE = "Hello from multicast sender!"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

print(f"Sending brmulticastoadcast to {BROADCAST_IP}:{PORT}")
while True:
    sock.sendto(MESSAGE.encode(), (BROADCAST_IP, PORT))
    print(f"multicast message sent: {MESSAGE}")
    time.sleep(2)
