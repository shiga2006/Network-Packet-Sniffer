from scapy.all import *
import logging
import time
from collections import defaultdict
import threading

class NetworkSniffer:
    def __init__(self, max_packets=20, log_file='network_traffic.log', interface=None):
        self.packet_count = 0
        self.max_packets = max_packets
        self.interface = interface
        self.running = False
        self.protocol_stats = defaultdict(int)
        self.start_time = None
        
        # Enhanced logging setup
        logging.basicConfig(
            filename=log_file, 
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler for real-time output
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(console_handler)
        
    def packet_callback(self, packet):
        if self.packet_count >= self.max_packets:
            return
            
        self.packet_count += 1
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Log basic packet information
        log_message = f"Packet #{self.packet_count}: {packet.summary()}"
        logging.info(log_message)
        
        # Extract and log detailed information based on packet layers
        details = []
        
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            details.append(f"IP: {ip_layer.src} -> {ip_layer.dst}, Proto: {ip_layer.proto}")
            self.protocol_stats["IP"] += 1
            
        if packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            details.append(f"IPv6: {ipv6_layer.src} -> {ipv6_layer.dst}")
            self.protocol_stats["IPv6"] += 1
            
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            details.append(f"TCP: {tcp_layer.sport} -> {tcp_layer.dport}, Flags: {tcp_layer.flags}")
            self.protocol_stats["TCP"] += 1
            
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            details.append(f"UDP: {udp_layer.sport} -> {udp_layer.dport}")
            self.protocol_stats["UDP"] += 1
            
        if packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            details.append(f"ICMP: Type {icmp_layer.type}, Code {icmp_layer.code}")
            self.protocol_stats["ICMP"] += 1
            
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            details.append(f"DNS: ID {dns_layer.id}, QR {'Response' if dns_layer.qr else 'Query'}")
            self.protocol_stats["DNS"] += 1
            
        # Log all collected details
        for detail in details:
            logging.info(f"  -> {detail}")
            
        # Print progress to console
        if self.packet_count % 5 == 0:
            print(f"Captured {self.packet_count}/{self.max_packets} packets...")
            
    def display_stats(self):
        """Display statistics about captured packets"""
        duration = time.time() - self.start_time
        print("\n" + "="*50)
        print("CAPTURE STATISTICS")
        print("="*50)
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total packets captured: {self.packet_count}")
        print("\nProtocol Distribution:")
        for protocol, count in self.protocol_stats.items():
            print(f"  {protocol}: {count} packets")
        print("="*50)
        
    def start_sniffing(self):
        """Start the packet capture process"""
        self.start_time = time.time()
        self.running = True
        print(f"Starting packet capture on interface {self.interface or 'default'}")
        print(f"Will capture up to {self.max_packets} packets")
        print("Press Ctrl+C to stop early\n")
        
        try:
            # Start sniffing with additional parameters for better performance
            sniff(
                prn=self.packet_callback, 
                store=0,
                iface=self.interface,
                stop_filter=lambda x: self.packet_count >= self.max_packets
            )
        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            print(f"An error occurred: {e}")
        finally:
            self.running = False
            self.display_stats()
            
    def get_packet_count(self):
        """Get the current packet count (thread-safe)"""
        return self.packet_count

def main():
    # Configuration options
    MAX_PACKETS = 20
    INTERFACE = None  # Set to specific interface if needed, e.g., "eth0", "wlan0"
    
    # Create and start sniffer
    sniffer = NetworkSniffer(max_packets=MAX_PACKETS, interface=INTERFACE)
    sniffer.start_sniffing()

if __name__ == "__main__":
    main()