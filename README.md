# 🔍 Advanced Network Packet Analyzer

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)]()
[![Scapy](https://img.shields.io/badge/built%20with-Scapy-orange.svg)](https://scapy.net/)

A professional-grade network packet capture and analysis toolkit for Linux systems with advanced security monitoring capabilities.

![Dashboard Screenshot](docs/images/dashboard-preview.png)

## ✨ Features

### Core Capabilities
- 📦 **Real-time Packet Capture** - Live network traffic monitoring with BPF filtering
- 🎯 **Advanced Protocol Analysis** - Deep inspection of TCP, UDP, ICMP, ARP, DNS, HTTP, and TLS
- 🖥️ **Live Dashboard** - Beautiful terminal UI with real-time statistics
- 💾 **Multiple Export Formats** - PCAP, CSV, and JSON output options

### Security Features
- 🛡️ **Intrusion Detection System**
  - Port scan detection
  - DoS/DDoS attack identification
  - ARP spoofing detection
- 🔗 **Session Reconstruction** - TCP session tracking and flow analysis
- 📊 **Performance Monitoring** - Bandwidth analysis and latency estimation
- ⚠️ **Alert System** - Real-time security alerts with configurable thresholds

## 🚀 Quick Start

### Prerequisites

**Supported Operating Systems:**
- Ubuntu 20.04+ / Debian 11+
- Kali Linux 2020+
- Fedora 34+
- CentOS/RHEL 8+
- Arch Linux

**Requirements:**
- Python 3.8 or higher
- Root/sudo privileges
- libpcap development files

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
```

2. **Install system dependencies**

Ubuntu/Debian:
```bash
sudo apt update
sudo apt install python3 python3-pip tcpdump libpcap-dev
```

Fedora/RHEL:
```bash
sudo dnf install python3 python3-pip tcpdump libpcap-devel
```

Arch Linux:
```bash
sudo pacman -S python python-pip tcpdump libpcap
```

3. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

4. **Verify installation**
```bash
sudo python3 packet_analyzer.py --version
sudo python3 packet_analyzer.py --list-interfaces
```

### Basic Usage

**Start capturing with default settings:**
```bash
sudo python3 packet_analyzer.py
```

**Capture with intrusion detection enabled:**
```bash
sudo python3 packet_analyzer.py --ids
```

**Monitor HTTP/HTTPS traffic:**
```bash
sudo python3 packet_analyzer.py -f "tcp port 80 or tcp port 443" --ids --alerts
```

## 📖 Documentation

### Command Line Options

```
Usage: packet_analyzer.py [OPTIONS]

Capture Options:
  -i, --interface IFACE    Network interface to capture on
  -f, --filter FILTER      BPF filter expression
  -c, --count NUM          Number of packets to capture (0 = unlimited)
  -q, --quiet              Quiet mode (no dashboard)
  -o, --output DIR         Output directory for saved files

Output Options:
  --pcap                   Save packets to PCAP file
  --csv                    Save packet info to CSV file
  --json                   Save packet info to JSON file
  --alerts                 Save security alerts report

Features:
  --ids                    Enable intrusion detection system
  --list-interfaces        List available network interfaces
  --version                Show version information
```

### BPF Filter Examples

```bash
# Protocol filtering
tcp                                    # TCP packets only
udp                                    # UDP packets only
icmp                                   # ICMP packets only

# Port filtering
tcp port 80                            # HTTP traffic
tcp port 443                           # HTTPS traffic
udp port 53                            # DNS queries
tcp port 22                            # SSH connections

# Host filtering
host 192.168.1.100                     # Specific host traffic
src host 10.0.0.1                      # Traffic from source
dst host 8.8.8.8                       # Traffic to destination

# Combined filters
tcp and port 80                        # TCP on port 80
host 192.168.1.1 and port 22          # SSH to specific host
tcp or udp                             # TCP or UDP packets
not arp and not broadcast              # Exclude ARP/broadcast
```

### Usage Examples

**1. Monitor DNS queries:**
```bash
sudo python3 packet_analyzer.py -f "udp port 53" -c 100 --pcap --csv
```

**2. Detect port scans:**
```bash
sudo python3 packet_analyzer.py --ids --alerts -f "tcp"
```

**3. Capture all traffic from specific host:**
```bash
sudo python3 packet_analyzer.py -f "host 192.168.1.100" --pcap --json
```

**4. Monitor network performance:**
```bash
sudo python3 packet_analyzer.py -i eth0 --ids
```

**5. Capture and analyze HTTPS traffic:**
```bash
sudo python3 packet_analyzer.py -f "tcp port 443" --ids --pcap
```

**6. Automated capture for analysis:**
```bash
sudo python3 packet_analyzer.py -q -c 10000 --pcap --csv --json --alerts
```

## 🔒 Security Features

### Intrusion Detection System

The built-in IDS monitors for suspicious activities:

**Port Scan Detection:**
- Identifies hosts scanning multiple ports in short time window
- Configurable threshold (default: 15 ports in 10 seconds)
- Alerts include source IP and scanned ports

**DoS Attack Detection:**
- Monitors packet rates from individual sources
- Threshold: 500 packets/second (configurable)
- Helps identify flooding attacks

**ARP Spoofing Detection:**
- Tracks IP-to-MAC address mappings
- Alerts on MAC address changes for known IPs
- Prevents man-in-the-middle attacks

### Alert System

Alerts are categorized by severity:
- 🔥 **CRITICAL** - Immediate attention required
- 🚨 **HIGH** - Significant security concern
- ⚠️  **MEDIUM** - Potential security issue
- ⚠️  **LOW** - Informational alert

Alerts can be:
- Displayed in real-time dashboard
- Saved to CSV file
- Exported in detailed report format

## 📊 Output Formats

### PCAP Format
Standard packet capture format compatible with:
- Wireshark
- tcpdump
- tshark
- Other network analysis tools

```bash
# Analyze with Wireshark
wireshark captures/capture_20241101_143052.pcap
```

### CSV Format
Spreadsheet-compatible format with fields:
- Timestamp
- Protocol
- Source/Destination IP and Port
- Packet length
- Flags
- Info

### JSON Format
Structured data format for programmatic analysis:
```json
{
  "timestamp": "2024-11-01 14:30:52.123",
  "protocol": "TCP",
  "src_ip": "192.168.1.100",
  "dst_ip": "93.184.216.34",
  "src_port": "54321",
  "dst_port": "443",
  "length": 66,
  "flags": "SYN"
}
```

## 🏗️ Architecture

### Modular Design

```
packet_analyzer.py
├── PacketCapture          # Packet capture engine
├── PacketAnalyzer         # Protocol analysis
├── PacketStats            # Statistics tracking
├── IntrusionDetector      # Security monitoring
├── SessionReconstructor   # Flow tracking
├── PerformanceMonitor     # Network metrics
├── AlertSystem            # Alert management
├── AdvancedDashboard      # Terminal UI
└── DataExporter           # Export functionality
```

### Key Components

**PacketCapture:**
- Threaded packet capture using Scapy
- BPF filter support
- Memory-efficient packet storage

**IntrusionDetector:**
- Port scan detection algorithm
- DoS attack identification
- ARP spoofing detection

**SessionReconstructor:**
- TCP session state tracking
- Flow-based analysis
- Session timeout management

**PerformanceMonitor:**
- Bandwidth calculation
- Latency estimation
- Retransmission tracking

## 🎯 Use Cases

### Network Security
- Monitor for intrusion attempts
- Detect port scanning activity
- Identify DoS attacks
- Track ARP spoofing

### Network Troubleshooting
- Analyze packet loss
- Measure bandwidth usage
- Identify retransmissions
- Monitor session states

### Protocol Analysis
- Inspect HTTP traffic
- Analyze DNS queries
- Study TCP handshakes
- Examine TLS connections

### Education & Training
- Learn packet analysis
- Understand network protocols
- Practice security monitoring
- Study traffic patterns

## ⚖️ Legal & Ethical Use

### ⚠️ IMPORTANT DISCLAIMER

This tool is designed for **educational purposes and authorized security testing only**.

**Legal Requirements:**
- ✅ Only use on networks you own
- ✅ Obtain explicit written authorization
- ✅ Follow organizational security policies
- ✅ Comply with applicable laws (GDPR, CCPA, etc.)

**Prohibited Uses:**
- ❌ Unauthorized network monitoring
- ❌ Intercepting private communications
- ❌ Stealing credentials or data
- ❌ Bypassing security controls

**Violation of these guidelines may result in criminal charges.**

### Responsible Disclosure

If you discover security vulnerabilities during authorized testing:
1. Document findings responsibly
2. Report to appropriate parties
3. Allow time for remediation
4. Follow coordinated disclosure

## 🤝 Contributing

Contributions are welcome! Here's how to help:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Development Guidelines

- Follow PEP 8 style guidelines
- Add docstrings to functions and classes
- Include unit tests for new features
- Update documentation as needed
- Test on multiple Linux distributions

## 🐛 Troubleshooting

### Common Issues

**Permission denied error:**
```bash
# Solution: Run with sudo
sudo python3 packet_analyzer.py
```

**No packets captured:**
- Check interface is up: `ip link show`
- Verify BPF filter syntax
- Ensure network traffic exists
- Check firewall rules

**Interface not found:**
```bash
# List available interfaces
sudo python3 packet_analyzer.py --list-interfaces
```

**Import errors:**
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more solutions.

## 📚 Additional Resources

### Documentation
- [Installation Guide](docs/INSTALLATION.md)
- [User Manual](docs/USER_MANUAL.md)
- [API Documentation](docs/API.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)

### Learning Resources
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [BPF Filter Syntax](https://biot.com/capstats/bpf.html)
- [Wireshark User Guide](https://www.wireshark.org/docs/)

### Related Tools
- [Wireshark](https://www.wireshark.org/) - GUI packet analyzer
- [tcpdump](https://www.tcpdump.org/) - Command-line packet capture
- [Zeek](https://zeek.org/) - Network security monitor
- [Suricata](https://suricata.io/) - IDS/IPS engine

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Cybersecurity Educational Toolkit Team**

## 🙏 Acknowledgments

- Scapy project for the powerful packet manipulation library
- Rich library for beautiful terminal interfaces
- The open-source security community

## 📧 Contact

- **Issues:** [GitHub Issues](https://github.com/yourusername/network-packet-analyzer/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/network-packet-analyzer/discussions)

## ⭐ Star History

If you find this tool useful, please consider giving it a star!

---

**Made with ❤️ for the cybersecurity community**

**Remember: Use responsibly and ethically!**