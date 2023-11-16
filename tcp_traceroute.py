import socket
import struct
import argparse
import time
from scapy.all import IP, TCP,ICMP
import multiprocessing
 


def parse_icmp_packet(icmp_packet):
    try:
        # Unpack ICMP header (assuming a basic ICMP header structure)
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_packet[:8])

        # Extract ICMP data
        icmp_data = icmp_packet[8:]

        # Print parsed information
        print(f"ICMP Type: {icmp_type}")
        print(f"ICMP Code: {icmp_code}")
        print(f"ICMP Checksum: {icmp_checksum}")
        print(f"ICMP Identifier: {icmp_id}")
        print(f"ICMP Sequence Number: {icmp_seq}")

        # Display ICMP data in hexadecimal format
        # print(f"ICMP Data (Hex): {binascii.hexlify(icmp_data).decode('utf-8')}")

    except Exception as e:
        # Handle parsing errors
        print(f"Error parsing ICMP packet: {str(e)}")






def send_tcp_syn_packet(destination_ip, ttl, dst_port):
    
    # Create a raw socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    # Set the TTL in the IP header
    tcp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    tcp_socket.settimeout(5)
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
            icmp_raw_socket.settimeout(5)
            packet, addr = icmp_raw_socket.recvfrom(1024)
           
            recv_time=time.time()

            print("=====================================2++")
            print(parse_icmp_packet(packet))
            # print(addr)
            print("=====================================3---")
            icmp_raw_socket.close()
            return addr,recv_time
    except socket.timeout:
        return None,time.time()

def proc1(tcp_socket,queue):
    try:
        packet_data, addr = tcp_socket.recvfrom(1024)
        queue.put(["1",addr,time.time()])
    except socket.timeout:
        queue.put(["1",None,time.time()])
 
def proc2(queue):
    addr,receive_time = receive_icmp()
    queue.put(["2",addr,receive_time])
    
def tcp_traceroute(tracerouteoutput,curriter,target, max_hops=5, dst_port=80):
    print(f"TCP Traceroute to {target}, {max_hops} hops max, TCP SYN to port {dst_port}")
    tracerouteoutput.append([])
    target = socket.gethostbyname(target)
    print("target==================================1")
    print(target)
    print("target==================================2")
    for ttl in range(1, max_hops + 1):
        # Send TCP SYN packet
        result_queue = multiprocessing.Queue()
        tcp_socket, send_time = send_tcp_syn_packet(target, ttl, dst_port)
        process1 = multiprocessing.Process(target=proc1, args=(tcp_socket,result_queue,))
        process2 = multiprocessing.Process(target=proc2, args=(result_queue,))
        process1.start()
        process2.start()
        process1.join()
        process2.join()
        result_one = result_queue.get()
        result_two = result_queue.get()
        addr="something went wrong"
        receive_time=0
        if result_two[0]=="2":
            if result_two[1]==None:
                addr,receive_time = result_one[1],result_one[2]
            else: 
                addr,receive_time = result_two[1],result_two[2]
        else:
            if result_one[1]==None:
                addr,receive_time = result_two[1],result_two[2]
            else: 
                addr,receive_time = result_one[1],result_one[2]
        # Receive TCP SYN-ACK packet
        # addr,receive_time = receive_icmp()
        
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
            # print(f"{ttl}\t{addr}\t{round_trip_time:.3f} ms")
            tracerouteoutput[curriter].append([addr,round(round_trip_time,2)])      
        else:
            round_trip_time = 0
            tracerouteoutput[curriter].append([addr,round(round_trip_time,2)])      
            # print(f"{ttl}\t*")

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
