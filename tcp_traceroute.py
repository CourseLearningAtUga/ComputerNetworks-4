import socket
import argparse
import time
from scapy.all import IP, TCP,ICMP
import random


class SingleHop:
    def __init__(self, ipaddress,time, domain):
            self.domain=domain
            self.ipaddress = ipaddress  
            self.time=[time]
    def addtime(self,newtime):
        self.time.append(newtime)
    def __str__(self):
        if self.ipaddress=="*":
            return " * "
        elif self.ipaddress=="+":
            return "        +            "
        else:
            formatted_times = "  ".join([time+" " for time in self.time])
            return f" {self.domain} ({self.ipaddress})  {formatted_times}"
        


def printtraceroute(tracerouteoutput):
    # print("+=================================================================================================!")
    number=1
    # print(len(tracerouteoutput))
    for x in tracerouteoutput:
        print(number,end=" ")
        for y in x:
            print(y,end=" ")
        print()
        number+=1
    print()
    # print("+=================================================================================================!")
    
def reverse_dns_lookup(ip_address):
    try:
        # Perform reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror as e:
        return ip_address






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

def listen_for_packets(timeout,mysource_port):
    # Create a raw socket for ICMP
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_socket.settimeout(timeout)  # Set a timeout of 1 second
    icmp_socket.setblocking(0)
    icmp_socket.bind(('0.0.0.0', 0))

    # Create a raw socket for TCP
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    tcp_socket.settimeout(timeout)  # Set a timeout of 1 second
    tcp_socket.setblocking(0)
    tcp_socket.bind(('0.0.0.0', 0))
    whilelooptimeout_start=time.time()
    while True:
        if time.time()-whilelooptimeout_start>timeout:
            return "*",0
        try:
            data, addr = tcp_socket.recvfrom(1024)
            packet = IP(data)
            if TCP in packet and packet[TCP].flags & 0x12 == 0x12:  # Check for SYN and ACK flags
                tcp_packet = packet[TCP]
                if tcp_packet.dport == mysource_port:
                    timestamp = time.time()
                    # print(f"Received TCP SYN/ACK Packet at {timestamp}: Source Port={tcp_packet.sport}, Dest Port={tcp_packet.dport}, Seq={tcp_packet.seq}, Ack={tcp_packet.ack}, Addr={addr}")
                    return addr, timestamp
        except socket.timeout:
            return "*",0
        except socket.error:
            pass

        try:
            data, addr = icmp_socket.recvfrom(1024)
            packet = IP(data)
            if ICMP in packet:
                icmp_packet = packet[ICMP]
                timestamp = time.time()
                if icmp_packet.type==11 and icmp_packet.code==0:
                    # print(f"Received ICMP Packet at {timestamp}: Type={icmp_packet.type}, Code={icmp_packet.code}, Checksum={icmp_packet.chksum}, Addr={addr}")
                    return addr, timestamp
        except socket.timeout:
            return "*",0
        except socket.error:
            pass  # Ignore other socket errors


    
def tcp_traceroute(tracerouteoutput,curriter,timeout,target, max_hops, dst_port=80):
    
    # ======================================all initialization variables start============================================================ #
    
    timeout=timeout #timeout values seems to be very important since if i keep a low timeout value i am receiving packets from 127.0.0.1
    addr="something went wrong"
    receive_time=0
    source_port=random.randint(2000, 65000)
    ttl=1
    # ======================================all initialization variables end============================================================ #
    print()
    print("traceroute+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++started")
    print(f"TCP Traceroute to {target}, {max_hops} hops max, TCP SYN to port {dst_port}","run number is",curriter)
    # printtraceroute(tracerouteoutput)
    for ttl in range(1, max_hops + 1):
        # Send TCP SYN packet
        addr,receive_time=["*"],0
        tcp_socket, send_time = send_tcp_syn_packet(target, ttl, dst_port,source_port,timeout)  
        addr,receive_time=listen_for_packets(timeout,source_port)
        tcp_socket.close()
        if addr[0]!="*" and addr[0]!="127.0.0.1":
            # Calculate round-trip time
            round_trip_time = (receive_time - send_time) * 1000  # in milliseconds
            # print(f"{ttl}\t{addr}\t{round_trip_time:.3f} ms")
            
            foundthe_ipinexisitingresult=False
            prev=len(tracerouteoutput[ttl-1])-1
            # for x in tracerouteoutput[ttl]:
            #     print(x.ipaddress,addr[0],end=" ")
            # print()
            # print(addr[0])
            if ttl>0 and prev>=0 and tracerouteoutput[ttl-1][prev].ipaddress==addr[0]:
                tracerouteoutput[ttl-1][prev].addtime(str(round(round_trip_time,3))+"ms")
                foundthe_ipinexisitingresult=True
            
            if not foundthe_ipinexisitingresult:
                tracerouteoutput[ttl-1].append(SingleHop(addr[0],str(round(round_trip_time,3))+"ms",reverse_dns_lookup(addr[0])))
            # tracerouteoutput[curriter].append([addr[0],round(round_trip_time,2)])
            # Check if we reached the destination
            if addr[0] == target:
                print("traceroute+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ended")
                return ttl      
        else:
            tracerouteoutput[ttl-1].append(SingleHop("*","0",""))
    print("traceroute+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ended")
    return ttl     
            # print(f"{ttl}\t*")
    # printtraceroute(tracerouteoutput)
    
    

        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP Traceroute")
    parser.add_argument("-m", type=int, default=30, help="Max hops to probe (default = 30)")
    parser.add_argument("-p", type=int, default=80, help="TCP destination port (default = 80)")
    parser.add_argument("-t", type=str, required=True, help="Target domain or IP")
    parser.add_argument("-n", type=int, default=3, help="number of runs (default = 3)")
    args = parser.parse_args()
    tracerouteoutput=[]
    timeout=1
    numberofruns=args.n
    target="example.com"
    for i in range(args.m):
        tracerouteoutput.append([])
    # print(len(tracerouteoutput))
    try:
        target = socket.gethostbyname(args.t)
        
    except:
        print(args.t," No address associated with hostname")
    for curriter in range(numberofruns):
        breakiter=tcp_traceroute(tracerouteoutput,curriter+1,timeout,target, args.m, dst_port=args.p)
        # print(breakiter) 
        for i in range(breakiter,len(tracerouteoutput)):
            tracerouteoutput[i].append(SingleHop("+","finished nothing to show",""))
    print()
    print()
    printtraceroute(tracerouteoutput)
    
    
