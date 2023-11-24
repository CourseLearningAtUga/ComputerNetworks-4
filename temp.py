from scapy.all import IP, TCP, send
import socket
# Replace the target IP address with the appropriate target
target_ip = "192.168.1.1"
hostname=socket.gethostname()
ip_address = socket.gethostbyname(hostname)
print(ip_address)
# Crafting a TCP SYN-ACK packet with additional parameters
packet = IP(dst=target_ip, src="192.168.1.2") / TCP(dport=80, sport=12345, flags="SA", seq=1000, ack=5000, window=8192)

# Sending the packet
send(packet)
