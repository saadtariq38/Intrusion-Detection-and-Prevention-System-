import time
from scapy.all import *
from collections import Counter
from scapy.all import send, IP, TCP, Raw
    
class RealTimeIntrusionDetector:
    def __init__(self, threshold=10):
        self.threshold = threshold
        self.ip_counter = Counter()
        self.tcp_syn_counter = Counter()
        self.http_request_counter = Counter()
        self.port_scan_activity = defaultdict(list)
        self.port_scan_times = defaultdict(list)  # Tracks timestamps of port accesses per IP
        self.blacklist = set()

    def detect_anomaly(self, packet):
        if IP in packet:
            # Detect excessive traffic from a single IP
            if self.ip_counter[packet[IP].src] > self.threshold:
                print(f'High traffic volume detected from {packet[IP].src}')
                return True

        # Detect TCP SYN flood attack
        if TCP in packet and packet[TCP].flags == 'S':
            self.tcp_syn_counter[packet[IP].src] += 1
            if self.tcp_syn_counter[packet[IP].src] > self.threshold:
                print(f'TCP SYN Flood attack detected from {packet[IP].src}!')
                return True

        # Detect excessive HTTP requests
        if TCP in packet and packet[TCP].dport == 80:
            if packet.haslayer(Raw) and b"GET" in packet[Raw].load:
                self.http_request_counter[packet[IP].src] += 1
                if self.http_request_counter[packet[IP].src] > self.threshold:
                    print(f'Excessive HTTP requests detected from {packet[IP].src}!')
                    return True
                
        return False

    
    
    def detect_port_scan(self, packet):
        if TCP in packet and packet[TCP].flags == 'S':  # SYN flag indicates an attempt to establish connection
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            # Add the port to the list for the given IP
            self.port_scan_activity[src_ip].append(dst_port)
            self.port_scan_times[src_ip].append(time.time())

            # Check if more than 20 different ports have been scanned
            if len(self.port_scan_activity[src_ip]) > 3:
                current_time = time.time()
                # Calculate time difference between the first and the latest recorded scan times
                while self.port_scan_times[src_ip] and self.port_scan_times[src_ip][0] < current_time - 60:
                    self.port_scan_activity[src_ip].pop(0)
                    self.port_scan_times[src_ip].pop(0)
                if len(self.port_scan_activity[src_ip]) >= 3:
                    print(f"Potential port scan detected from {src_ip}")
                    return True

        return False

    def packet_handler(self, packet):
        if IP in packet:
            if(packet[IP].src not in self.blacklist):
                self.ip_counter[packet[IP].src] += 1
                if self.detect_anomaly(packet):
                    print(f'Intrusion detected from {packet[IP].src}!')
                    self.prevent_intrusion(packet[IP].src)
                    
                if self.detect_port_scan(packet):
                    print("found port scanning")
                    self.prevent_intrusion(packet[IP].src)
                
    def prevent_intrusion(self, ip_address):
        # Add the offending IP address to the blacklist
        self.blacklist.add(ip_address)

        # Log the incident (for simplicity, just printing here; in a real scenario, write to a log file)
        print(f"IP {ip_address} has been blacklisted due to suspected port scanning.")

    def sniff_traffic(self):
        sniff(prn=self.packet_handler, store=False)




    def send_syn_flood(self, target_ip, count=100, port=80):
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
            send(packet, verbose=False)

    def send_http_requests(self,target_ip, count=100, port=80):
        load = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip)
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=port) / Raw(load=load)
            print("packet")
            send(packet, verbose=False)
    
    def send_port_scanning_attack(self, target_ip):
        for port in range(100):
            packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
            # Sending the packet
            send(packet, verbose=False)
        print(f"Port scan simulation sent to {target_ip}")


if __name__ == '__main__':
    detector = RealTimeIntrusionDetector()
    curr = time.time()
    print(curr)

    print('Starting network traffic monitoring!')
    detector.sniff_traffic()
    
    
    target_ip = "YOUR IP HERE"
    detector.send_syn_flood(target_ip)
    #detector.send_http_requests(target_ip)
    detector.send_port_scanning_attack(target_ip)
    

    



