import socket
import argparse
import time
from scapy.all import IP, TCP,Ether, ICMP, UDP

import multiprocessing

class SingleHop:
    def __init__(self, ipaddress, time):
        self.domain=""
        self.ipaddress = ipaddress  
        self.time=[time]

    def addtime(self,newtime):
        self.time.append(newtime)
    def __str__(self):
        return f" ({self.ipaddress}),  {self.time}"

def printtraceroute(tracerouteoutput):
    print("+=================================================================================================!")
    for x in tracerouteoutput:
        for y in x:
            print(y,end=" ")
        print()
    print("+=================================================================================================!")
    
def reverse_dns_lookup(ip_address):
    try:
        # Perform reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror as e:
        return f"Unable to perform reverse DNS lookup: {e}"

# def parse_icmp_packet(icmp_packet):
#     try:
#         # Unpack ICMP header (assuming a basic ICMP header structure)
#         icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_packet[:8])

#         # Extract ICMP data
#         icmp_data = icmp_packet[8:]

#         # Print parsed information
#         print(f"ICMP Type: {icmp_type}")
#         print(f"ICMP Code: {icmp_code}")
#         print(f"ICMP Checksum: {icmp_checksum}")
#         print(f"ICMP Identifier: {icmp_id}")
#         print(f"ICMP Sequence Number: {icmp_seq}")

#         # Display ICMP data in hexadecimal format
#         # print(f"ICMP Data (Hex): {binascii.hexlify(icmp_data).decode('utf-8')}")

#     except Exception as e:
#         # Handle parsing errors
#         print(f"Error parsing ICMP packet: {str(e)}")






def send_tcp_syn_packet(destination_ip, ttl, dst_port,source_port,timeout):
    
    # Create a raw socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    # Set the TTL in the IP header
    # tcp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    tcp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    tcp_socket.settimeout(timeout)
    packet = IP(dst=destination_ip, ttl=ttl) / TCP(dport=dst_port,sport=source_port, flags="S")
    # print("sentpacket+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++start")
    # # Send the packet
    # print(packet)
    # print(bytes(packet))
    # print("sentpacket+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++end")
    tcp_socket.sendto(bytes(packet), (destination_ip, dst_port))
    # print("++++++++++++++",tcp_socket)
    # packet_data, addr = tcp_socket.recvfrom(1024)
    # print("==========",addr,packet_data)
    # try:
    #     print("++++++++++++++",tcp_socket)
    #     packet_data, addr = tcp_socket.recvfrom(1024)
    #     print("==========",addr,packet_data)
        
    # except socket.timeout:
    #     print("in timeout++++++++++")
    #     pass
    # Record the time the packet was sent
    send_time = time.time()

    return tcp_socket, send_time

def receive_icmp(timeout,source_port):
    # Set a timeout on the socket
    icmp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        # Receive the TCP SYN-ACK packet
        while True:
            # Receive an ICMP packet
            icmp_raw_socket.settimeout(timeout)
            packet, addr = icmp_raw_socket.recvfrom(1024)
            if addr[0]!= "127.0.0.1":
                recv_time=time.time()
                return addr,recv_time
            # print("=====================================2++")
            # print(parse_icmp_packet(packet))
            # # print(addr)
            # print("=====================================3---")
            icmp_raw_socket.close()
            return None,time.time()
    except socket.timeout:
        return None,time.time()

def listenForTcpSynAck(source_port,timeout,queue):
    try:
        # print(tcp_socket)
        receive_ip_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        receive_ip_raw_socket.settimeout(timeout)
        receive_ip_raw_socket.bind(("0.0.0.0",source_port))
        packet_data, addr = receive_ip_raw_socket.recvfrom(1024)
        scapy_packet = IP(packet_data)
        tcp_dest_port=-1
        # tcp_source_port=-1
        # Check if the packet is a TCP packet
        if TCP in scapy_packet:
            # Extract source and destination ports from the TCP packet
            # tcp_source_port = scapy_packet[TCP].sport
            tcp_dest_port = scapy_packet[TCP].dport
            # Print the source and destination ports
            # print(f"Source Port: {tcp_source_port}")
            # print(f"Destination Port: {tcp_dest_port}")
            # print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++start0")
            # print(source_port,"<=====port i provided")
            # print(addr,tcp_source_port, tcp_dest_port)
            # print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++start0")
        if tcp_dest_port == source_port:
            # print(f"Captured TCP packet on port {source_port}")
            # print()
            # print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++start")
            # print(addr)
            # print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++start")
            # print(packet_data)
            # print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++end")
            # print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++end")

            queue.put(["1",addr,time.time()])
        else:
            queue.put(["1",None,time.time()])
        receive_ip_raw_socket.close()
    except socket.timeout:
        queue.put(["1",None,time.time()])
 
def listenForIcmpPacket(timeout,source_port,queue):
    addr,receive_time = receive_icmp(timeout,source_port)
    queue.put(["2",addr,receive_time])
    
def tcp_traceroute(tracerouteoutput,target, max_hops=5, dst_port=80):
    print(f"TCP Traceroute to {target}, {max_hops} hops max, TCP SYN to port {dst_port}")
    # ======================================all initialization variables start============================================================ #
    tracerouteoutput.append([])
    timeout=5 #timeout values seems to be very important since if i keep a low timeout value i am receiving packets from 127.0.0.1
    addr="something went wrong"
    receive_time=0
    source_port=12345
    icmp_packet=[]
    final_tcp_syn_ackpacket=[]
    # ======================================all initialization variables end============================================================ #
    target = socket.gethostbyname(target)
    print("target to traceroute==================================st")
    print(target)
    print("target to traceroute==================================end")
    for ttl in range(1, max_hops + 1):
        # Send TCP SYN packet
        result_queue = multiprocessing.Queue()
        tcp_socket, send_time = send_tcp_syn_packet(target, ttl, dst_port,source_port,timeout)
        process1 = multiprocessing.Process(target=listenForTcpSynAck, args=(source_port,timeout,result_queue,))
        process2 = multiprocessing.Process(target=listenForIcmpPacket, args=(timeout,source_port,result_queue,))
        process1.start()
        process2.start()
        process1.join()
        process2.join()
        result_one = result_queue.get()
        result_two = result_queue.get()
        
        if result_two[0]=="2":
            icmp_packet=result_two
            final_tcp_syn_ackpacket=result_one
        else:
            icmp_packet=result_one
            final_tcp_syn_ackpacket=result_two
     
        # print("addr testing++++++++++++++++++++++++++++++++++++++++++++st")
        # print(addr,receive_time,icmp_packet,final_tcp_syn_ackpacket)
        # print("addr testing========================after")
        if icmp_packet[1]==None and final_tcp_syn_ackpacket[1]!=None :
            addr,receive_time=final_tcp_syn_ackpacket[1],final_tcp_syn_ackpacket[2]
        elif final_tcp_syn_ackpacket[1]==None and icmp_packet[1]!=None:
            addr,receive_time=icmp_packet[1],icmp_packet[2]
        else:
            addr,receive_time=["*"],0
        # Receive TCP SYN-ACK packet
        # addr,receive_time = receive_icmp()
        # print("time=============================================start")
        # # print(send_time)
        # # print(receive_time)
        # print(receive_time-send_time)
        # print("time=============================================end")
        # Close the TCP socket
        
        
        # print(addr,receive_time)
        # print("addr testing++++++++++++++++++++++++++++++++++++++end")
        # print()
        tcp_socket.close()
        
        
        if addr[0]=="127.0.0.1":
            print("88888888888888888888888888888888888888888888888888888")
            print(addr[0],round(round_trip_time,2))
            print(icmp_packet,final_tcp_syn_ackpacket,ttl)
            print("88888888888888888888888888888888888888888888888888888")
        
        if addr[0]!="*" and addr[0]!="127.0.0.1":
            # Calculate round-trip time
            round_trip_time = (receive_time - send_time) * 1000  # in milliseconds
            # print(f"{ttl}\t{addr}\t{round_trip_time:.3f} ms")
            
            foundtheipinexisitingresult=False
            for x in tracerouteoutput[ttl]:
                if x.ipaddress==addr[0]:
                    x.addtime(round(round_trip_time,2))
                    foundtheipinexisitingresult=True
                    break
            
            if not foundtheipinexisitingresult:
                tracerouteoutput[ttl].append(SingleHop(addr[0],round(round_trip_time,2)))
            # tracerouteoutput[curriter].append([addr[0],round(round_trip_time,2)])
            # Check if we reached the destination
            if addr[0] == target:
                break      
        else:
            tracerouteoutput[ttl].append(SingleHop("*",0))     
            # print(f"{ttl}\t*")
    # printtraceroute(tracerouteoutput)

        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP Traceroute")
    parser.add_argument("-m", type=int, default=30, help="Max hops to probe (default = 30)")
    parser.add_argument("-p", type=int, default=80, help="TCP destination port (default = 80)")
    parser.add_argument("-t", type=str, required=True, help="Target domain or IP")
    args = parser.parse_args()
    tracerouteoutput=[]
    for i in range(args.m):
        tracerouteoutput.append([])
    for curriter in range(1):
        tcp_traceroute(tracerouteoutput,args.t, max_hops=args.m, dst_port=args.p)
    printtraceroute(tracerouteoutput)
