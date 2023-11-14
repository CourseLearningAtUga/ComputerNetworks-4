import socket
import struct

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
def create_syn_packet(source_ip, source_port, dest_ip, dest_port):
    # IP header
    ip_version = 4
    ip_ihl = 5
    ip_tos = 0
    ip_total_length = 0
    ip_id = 54321
    ip_flags = 0
    ip_fragment_offset = 0
    ip_ttl = 1
    ip_protocol = socket.IPPROTO_TCP
    ip_checksum = 0
    ip_source = socket.inet_aton(source_ip)
    ip_dest = socket.inet_aton(dest_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s', (ip_version << 4) + ip_ihl, ip_tos, ip_total_length, ip_id, (ip_flags << 13) + ip_fragment_offset, ip_ttl, ip_protocol, ip_checksum, ip_source, ip_dest)

    # TCP header
    tcp_source = source_port
    tcp_dest = dest_port
    tcp_seq = 12345
    tcp_ack_seq = 0
    tcp_offset_res = (5 << 4)
    tcp_flags = 0x02  # SYN flag
    tcp_window = socket.htons(5840)
    tcp_checksum = 0
    tcp_urg_ptr = 0

    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)

    # Pseudo header for TCP checksum calculation
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(source_ip), socket.inet_aton(dest_ip), 0, socket.IPPROTO_TCP, len(tcp_header))
    checksum_data = pseudo_header + tcp_header
    temp=struct.unpack('!HHHH', checksum_data)
    tcp_checksum = socket.htons(socket.htons(sum(temp)))

    # Update the TCP header with the calculated checksum
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)

    # Combine everything into a packet
    packet = ip_header + tcp_header
    print(packet)
    return packet

def send_syn_packet(packet, dest_ip):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Set socket options to enable IP header included in the packet
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Send the packet
    raw_socket.sendto(packet, (dest_ip, 0))


def traceroute(source_ip, source_port, destination_ip, destination_port):
    syn_packet = create_syn_packet(source_ip, source_port, destination_ip, destination_port)
    print(send_syn_packet(syn_packet, destination_ip))
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
    targetdomain="www.google.com"
    maxhops=30
    dst_port=80
    main(targetdomain,maxhops,dst_port)
