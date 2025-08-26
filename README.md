# Network Packet Sniffer

A Python-based network packet sniffer using Scapy that captures and analyzes network traffic with detailed logging and statistics.

## Features

- **Multi-Protocol Support**: Captures and analyzes IP, IPv6, TCP, UDP, ICMP, and DNS packets
- **Detailed Logging**: Records comprehensive packet information with timestamps
- **Real-time Statistics**: Tracks protocol distribution and capture metrics
- **User-friendly Interface**: Progress indicators and clean console output
- **Configurable**: Easy to customize packet limits and network interfaces

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-packet-sniffer.git
cd network-packet-sniffer
```

2. Install required dependencies:
```bash
pip install scapy
```

## Usage

Run the sniffer with default settings (captures 20 packets):
```bash
python packet_sniffer.py
```

### Command Line Options

You can customize the sniffer behavior by modifying the `main()` function:

```python
# Configuration options
MAX_PACKETS = 50  # Set your desired packet limit
INTERFACE = "eth0"  # Specify a network interface
LOG_FILE = "custom_traffic.log"  # Custom log file name

# Create and start sniffer
sniffer = NetworkSniffer(max_packets=MAX_PACKETS, interface=INTERFACE, log_file=LOG_FILE)
sniffer.start_sniffing()
```

### Available Network Interfaces

To list available interfaces on your system:
```python
from scapy.all import get_if_list
print(get_if_list())
```

## Output Example

The sniffer generates detailed logs in the specified file and displays real-time progress:

```
Starting packet capture on interface default
Will capture up to 20 packets
Press Ctrl+C to stop early

Captured 5/20 packets...
Captured 10/20 packets...
Captured 15/20 packets...
Capture completed!

==================================================
CAPTURE STATISTICS
==================================================
Duration: 12.45 seconds
Total packets captured: 20

Protocol Distribution:
  IP: 15 packets
  TCP: 15 packets
  UDP: 3 packets
  DNS: 2 packets
==================================================
```

### Sample Log Entries

```
2024-07-27 14:45:20,628 - INFO - Packet #1: Ether / IP / TCP 192.168.1.6:58421 > 34.170.65.59:https A / Raw
2024-07-27 14:45:20,628 - INFO -   -> IP: 192.168.1.6 -> 34.170.65.59, Proto: 6
2024-07-27 14:45:20,628 - INFO -   -> TCP: 58421 -> 443, Flags: A
2024-07-27 14:45:21,226 - INFO - Packet #9: Ether / IPv6 / UDP / DNS Qry "b'ctldl.windowsupdate.com.'" 
2024-07-27 14:45:21,226 - INFO -   -> UDP: 58913 -> 53
2024-07-27 14:45:21,226 - INFO -   -> DNS: ID 0, QR Query
```

## Advanced Customization

### Adding Protocol Handlers

Extend the sniffer by adding new protocol handlers in the `packet_callback` method:

```python
if packet.haslayer(HTTP):
    http_layer = packet[HTTP]
    details.append(f"HTTP: Method {http_layer.Method}, Host: {http_layer.Host}")
    self.protocol_stats["HTTP"] += 1
```

### Filtering Packets

Add packet filtering by modifying the sniff function:

```python
sniff(
    prn=self.packet_callback, 
    store=0,
    iface=self.interface,
    stop_filter=lambda x: self.packet_count >= self.max_packets,
    filter="tcp port 80 or tcp port 443"  # Add BPF filter
)
```

## Requirements

- Python 3.6+
- Scapy library
- Administrative/root privileges (for packet capture)

## Notes

- This tool requires elevated privileges to capture network packets
- Use responsibly and only on networks you have permission to monitor
- The tool is for educational and network diagnostic purposes only


## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Disclaimer

This tool is intended for educational purposes and legitimate network troubleshooting only. Always ensure you have proper authorization before monitoring any network traffic. The developers are not responsible for any misuse of this software.
