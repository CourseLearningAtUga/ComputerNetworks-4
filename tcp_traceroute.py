import socket
from scapy.all import IP, TCP


def get_my_ip():
    try:
        # Create a socket and connect to an external server (Google's DNS server)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error as e:
        print(f"Error: {e}")
        return None
def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None
    
def create_syn_ack_packet(destination_ip, destination_port,ttl):
    # Create an IP packet with the destination IP address
    ip_packet = IP(dst=destination_ip,ttl=ttl)

    # Create a TCP SYN-ACK packet with the destination port
    tcp_packet = TCP(dport=destination_port, flags="SA", seq=1000, ack=5000)

    # Combine the IP and TCP packets
    syn_ack_packet = ip_packet / tcp_packet

    # Display the packet details
    print("TCP SYN-ACK Packet:")
    print(syn_ack_packet.summary())
    print(bytes(syn_ack_packet))
    # Return the packet
    return bytes(syn_ack_packet)

def send_syn_packet(packet, dest_ip):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Set socket options to enable IP header included in the packet
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Send the packet
    raw_socket.sendto(packet, (dest_ip, 0))
    data,addr=raw_socket.recvfrom(2048)
    print(data)
    print(addr)
    return raw_socket


def traceroute(source_ip, source_port, destination_ip, destination_port):
    ttl=2
    syn_packet = create_syn_ack_packet(destination_ip, destination_port,ttl)
    
    send_syn_packet(syn_packet, destination_ip)
    return []

def main(targetdomain,maxhops,dst_port):
    source_ip = get_my_ip()
    destination_ip=get_ip_address(targetdomain)
    source_port=1234
    destination_port=80
    print(source_ip)
    print(destination_ip)
    traceroute(source_ip, source_port, destination_ip, destination_port)



if __name__ == "__main__":
    targetdomain="8.8.8.8"
    maxhops=30
    dst_port=80
    main(targetdomain,maxhops,dst_port)
