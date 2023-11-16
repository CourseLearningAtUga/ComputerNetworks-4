import socket
import struct
import argparse
import time
from scapy.all import IP, TCP,ICMP

def process_icmp_packet(response):
    # Check if the packet has an ICMP layer
    if ICMP in response:
        # Extract ICMP layer
        icmp_layer = response[ICMP]

        # Print information about the ICMP packet
        print(f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}")
        print(f"ID: {icmp_layer.id}, Seq: {icmp_layer.seq}")

        # Access the payload (data) of the ICMP packet
        payload_data = icmp_layer.payload
        print(f"Payload Data: {payload_data}")


def send_tcp_syn_packet(destination_ip, ttl, dst_port):
    
    # Create a raw socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Set the TTL in the IP header
    tcp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    packet = IP(dst=destination_ip, ttl=ttl) / TCP(dport=dst_port, flags="S")
    # print("sentpacket+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++start")
    # # Send the packet
    # print(packet)
    # print(bytes(packet))
    # print("sentpacket+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++end")
    tcp_socket.sendto(bytes(packet), (destination_ip, dst_port))
    
    # Record the time the packet was sent
    send_time = time.time()

    return tcp_socket, send_time

def receive_icmp():
    # Set a timeout on the socket
    icmp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        # Receive the TCP SYN-ACK packet
        while True:
            # Receive an ICMP packet
            icmp_raw_socket.settimeout(1)
            packet, addr = icmp_raw_socket.recvfrom(1024)
            
            recv_time=time.time()

            # print("=====================================2")
            # print(packet)
            # print(addr)
            # print("=====================================3")
            icmp_raw_socket.close()
            return addr,recv_time
    except socket.timeout:
        return None,0


def process_icmp_packet(response):
    # Check if the packet has an ICMP layer
    if ICMP in response:
        # Extract ICMP layer
        icmp_layer = response[ICMP]

        # Print information about the ICMP packet
        print(f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}")
        print(f"ID: {icmp_layer.id}, Seq: {icmp_layer.seq}")

        # Access the payload (data) of the ICMP packet
        payload_data = icmp_layer.payload
        print(f"Payload Data: {payload_data}")

def tcp_traceroute(tracerouteoutput,curriter,target, max_hops=5, dst_port=80):
    print(f"TCP Traceroute to {target}, {max_hops} hops max, TCP SYN to port {dst_port}")
    tracerouteoutput.append([])
    for ttl in range(1, max_hops + 1):
        # Send TCP SYN packet
        
        tcp_socket, send_time = send_tcp_syn_packet(target, ttl, dst_port)

        # Receive TCP SYN-ACK packet
        addr,receive_time = receive_icmp()
        # print("time=============================================start")
        # # print(send_time)
        # # print(receive_time)
        # print(receive_time-send_time)
        # print("time=============================================end")
        # Close the TCP socket
        tcp_socket.close()

        if addr:
            # Calculate round-trip time
            round_trip_time = (receive_time - send_time) * 1000  # in milliseconds
            print(f"{ttl}\t{addr}\t{round_trip_time:.3f} ms")
            tracerouteoutput[curriter].append([addr,round(round_trip_time,2)])      
        else:
            tracerouteoutput[curriter].append([addr,round(round_trip_time,2)])      
            print(f"{ttl}\t*")

        # Check if we reached the destination
        if addr == target:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP Traceroute")
    parser.add_argument("-m", type=int, default=30, help="Max hops to probe (default = 30)")
    parser.add_argument("-p", type=int, default=80, help="TCP destination port (default = 80)")
    parser.add_argument("-t", type=str, required=True, help="Target domain or IP")
    args = parser.parse_args()
    tracerouteoutput=[]
    
    tcp_traceroute(tracerouteoutput,0,args.t, max_hops=args.m, dst_port=args.p)
    
    # print(tracerouteoutput)
    for x in tracerouteoutput[0]:
        print(x)
