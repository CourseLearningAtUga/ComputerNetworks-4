import socket
import struct

def create_syn_packet(src_ip, src_port, dest_ip, dest_port):
    # IP header
    ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + 20, 0, 0, 64, socket.IPPROTO_TCP, 0, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))

    # TCP header
    tcp_source = src_port
    tcp_dest = dest_port
    tcp_seq = 0
    tcp_ack_seq = 0
    tcp_offset_res = (5 << 4)
    tcp_flags = 0x02  # SYN flag
    tcp_window = socket.htons(5840)
    tcp_checksum = 0
    tcp_urg_ptr = 0

    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)

    # Pseudo header for TCP checksum calculation
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dest_ip), 0, socket.IPPROTO_TCP, len(tcp_header))
    checksum_data = pseudo_header + tcp_header
    tcp_checksum = socket.htons(socket.htons(sum(struct.unpack('!HHHH', checksum_data))))

    # Update the TCP header with the calculated checksum
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)

    # Combine everything into a packet
    packet = ip_header + tcp_header

    return packet

def send_syn_packet(packet, dest_ip, dest_port):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Set socket options to enable IP header included in the packet
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Send the packet
    raw_socket.sendto(packet, (dest_ip, dest_port))

# Example usage
source_ip = "your_source_ip"  # Replace with your source IP address
source_port = 12345  # Replace with your source port
destination_ip = "example.com"  # Replace with the destination IP address
destination_port = 80  # Replace with the destination port

syn_packet = create_syn_packet(source_ip, source_port, destination_ip, destination_port)
send_syn_packet(syn_packet, destination_ip, destination_port)
