#!/usr/bin/env python3
"""
Advanced Network Packet Analyzer Toolkit
=========================================
Professional-grade network packet capture and analysis tool for Linux systems.

Features:
- Real-time packet capture with live dashboard
- Advanced protocol analysis (TCP, UDP, ICMP, ARP, DNS, HTTP, TLS)
- Intrusion detection (port scans, ARP spoofing, DoS)
- Session reconstruction and flow tracking
- Performance monitoring and bandwidth analysis
- Alert system with configurable rules
- Multiple export formats (PCAP, CSV, JSON)

ETHICAL USE ONLY - Only use on networks you own or have explicit authorization.

Author: Cybersecurity Educational Toolkit
License: MIT
Version: 2.0.0
"""

import os
import sys
import time
import json
import csv
import argparse
import threading
import signal
from datetime import datetime, timedelta
from collections import defaultdict, Counter, deque
from pathlib import Path
import hashlib
import re
import socket

# Core dependencies
try:
    from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
    from scapy.all import get_if_list, conf
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich.style import Style
except ImportError:
    print("ERROR: Rich not installed. Run: pip install rich")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Global configuration"""
    VERSION = "2.0.0"
    MAX_PACKETS = 10000
    REFRESH_RATE = 0.5
    PAYLOAD_PREVIEW_LEN = 50
    SESSION_TIMEOUT = 300  # 5 minutes
    ALERT_THRESHOLD_PORT_SCAN = 15  # unique ports in time window
    ALERT_THRESHOLD_DOS = 500  # packets per second from single source
    PORT_SCAN_WINDOW = 10  # seconds
    DOS_WINDOW = 5  # seconds


# ============================================================================
# INTRUSION DETECTION MODULE
# ============================================================================

class IntrusionDetector:
    """Detects suspicious network activities"""
    
    def __init__(self):
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'start_time': time.time()})
        self.packet_rate_tracker = defaultdict(lambda: deque(maxlen=1000))
        self.arp_table = {}
        self.alerts = []
        self.lock = threading.Lock()
        
    def check_port_scan(self, src_ip, dst_port, timestamp):
        """Detect port scanning activity"""
        if not dst_port or not src_ip:
            return None
            
        with self.lock:
            tracker = self.port_scan_tracker[src_ip]
            
            # Reset if window expired
            if timestamp - tracker['start_time'] > Config.PORT_SCAN_WINDOW:
                tracker['ports'].clear()
                tracker['start_time'] = timestamp
            
            tracker['ports'].add(dst_port)
            
            # Alert if threshold exceeded
            if len(tracker['ports']) >= Config.ALERT_THRESHOLD_PORT_SCAN:
                alert = {
                    'type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'source': src_ip,
                    'description': f'Port scan detected: {len(tracker["ports"])} ports scanned',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'details': {'ports': sorted(list(tracker['ports'])[:10])}
                }
                self.alerts.append(alert)
                tracker['ports'].clear()  # Reset to avoid duplicate alerts
                return alert
        return None
    
    def check_dos_attack(self, src_ip, timestamp):
        """Detect potential DoS attacks"""
        with self.lock:
            self.packet_rate_tracker[src_ip].append(timestamp)
            
            # Check packet rate in window
            recent_packets = [t for t in self.packet_rate_tracker[src_ip] 
                            if timestamp - t <= Config.DOS_WINDOW]
            
            rate = len(recent_packets) / Config.DOS_WINDOW
            
            if rate >= Config.ALERT_THRESHOLD_DOS:
                alert = {
                    'type': 'DOS_ATTACK',
                    'severity': 'CRITICAL',
                    'source': src_ip,
                    'description': f'Potential DoS: {rate:.0f} packets/sec',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'details': {'packet_rate': f'{rate:.2f}', 'window': Config.DOS_WINDOW}
                }
                self.alerts.append(alert)
                return alert
        return None
    
    def check_arp_spoofing(self, src_ip, src_mac):
        """Detect ARP spoofing attempts"""
        if not src_ip or not src_mac:
            return None
            
        with self.lock:
            if src_ip in self.arp_table:
                if self.arp_table[src_ip] != src_mac:
                    alert = {
                        'type': 'ARP_SPOOFING',
                        'severity': 'HIGH',
                        'source': src_ip,
                        'description': f'ARP spoofing detected: MAC changed',
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'details': {
                            'old_mac': self.arp_table[src_ip],
                            'new_mac': src_mac
                        }
                    }
                    self.alerts.append(alert)
                    self.arp_table[src_ip] = src_mac
                    return alert
            else:
                self.arp_table[src_ip] = src_mac
        return None
    
    def get_recent_alerts(self, limit=10):
        """Get recent security alerts"""
        with self.lock:
            return self.alerts[-limit:]


# ============================================================================
# SESSION RECONSTRUCTION MODULE
# ============================================================================

class SessionReconstructor:
    """Reconstructs TCP sessions and tracks flows"""
    
    def __init__(self):
        self.tcp_sessions = {}
        self.flows = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'start': None, 'last': None})
        self.lock = threading.Lock()
        
    def track_tcp_session(self, src_ip, dst_ip, src_port, dst_port, flags, seq_num, payload_len):
        """Track TCP session state"""
        if not all([src_ip, dst_ip, src_port, dst_port]):
            return None
            
        session_key = self._get_session_key(src_ip, dst_ip, src_port, dst_port)
        
        with self.lock:
            if session_key not in self.tcp_sessions:
                self.tcp_sessions[session_key] = {
                    'state': 'UNKNOWN',
                    'packets': 0,
                    'bytes': 0,
                    'start_time': time.time(),
                    'last_activity': time.time()
                }
            
            session = self.tcp_sessions[session_key]
            session['packets'] += 1
            session['bytes'] += payload_len
            session['last_activity'] = time.time()
            
            # Update state based on flags
            if 'SYN' in flags and 'ACK' not in flags:
                session['state'] = 'SYN_SENT'
            elif 'SYN' in flags and 'ACK' in flags:
                session['state'] = 'ESTABLISHED'
            elif 'FIN' in flags:
                session['state'] = 'CLOSING'
            elif 'RST' in flags:
                session['state'] = 'CLOSED'
            elif session['state'] == 'UNKNOWN' and 'ACK' in flags:
                session['state'] = 'ESTABLISHED'
            
            return session
    
    def track_flow(self, src_ip, dst_ip, protocol, packet_size):
        """Track network flow statistics"""
        if not src_ip or not dst_ip:
            return
            
        flow_key = f"{src_ip}->{dst_ip}:{protocol}"
        
        with self.lock:
            flow = self.flows[flow_key]
            if flow['start'] is None:
                flow['start'] = time.time()
            flow['packets'] += 1
            flow['bytes'] += packet_size
            flow['last'] = time.time()
    
    def _get_session_key(self, src_ip, dst_ip, src_port, dst_port):
        """Generate consistent session key"""
        # Normalize direction
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}"
    
    def get_active_sessions(self):
        """Get currently active TCP sessions"""
        with self.lock:
            current_time = time.time()
            active = []
            for key, session in self.tcp_sessions.items():
                if current_time - session['last_activity'] < Config.SESSION_TIMEOUT:
                    active.append({'key': key, **session})
            return active
    
    def get_top_flows(self, limit=10, by='bytes'):
        """Get top flows by packets or bytes"""
        with self.lock:
            sorted_flows = sorted(
                self.flows.items(),
                key=lambda x: x[1][by],
                reverse=True
            )[:limit]
            return [{'flow': k, **v} for k, v in sorted_flows]
    
    def cleanup_old_sessions(self):
        """Remove expired sessions"""
        with self.lock:
            current_time = time.time()
            expired = [k for k, v in self.tcp_sessions.items() 
                      if current_time - v['last_activity'] > Config.SESSION_TIMEOUT]
            for key in expired:
                del self.tcp_sessions[key]


# ============================================================================
# PERFORMANCE MONITOR MODULE
# ============================================================================

class PerformanceMonitor:
    """Monitors network performance metrics"""
    
    def __init__(self):
        self.packet_times = deque(maxlen=1000)
        self.packet_sizes = deque(maxlen=1000)
        self.retransmissions = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.tcp_handshakes = []
        self.lock = threading.Lock()
        
    def record_packet(self, packet_size, timestamp):
        """Record packet timing and size"""
        with self.lock:
            self.packet_times.append(timestamp)
            self.packet_sizes.append(packet_size)
            self.total_bytes += packet_size
    
    def record_retransmission(self):
        """Count TCP retransmission"""
        with self.lock:
            self.retransmissions += 1
    
    def calculate_bandwidth(self):
        """Calculate current bandwidth usage"""
        with self.lock:
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                bps = (self.total_bytes * 8) / elapsed
                return {
                    'bps': bps,
                    'kbps': bps / 1024,
                    'mbps': bps / (1024 * 1024)
                }
            return {'bps': 0, 'kbps': 0, 'mbps': 0}
    
    def calculate_latency_estimate(self):
        """Estimate network latency from packet timing"""
        with self.lock:
            if len(self.packet_times) < 2:
                return None
            
            # Calculate inter-packet timing
            times = list(self.packet_times)
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                return avg_interval * 1000  # Convert to ms
            return None
    
    def get_metrics(self):
        """Get all performance metrics"""
        bandwidth = self.calculate_bandwidth()
        latency = self.calculate_latency_estimate()
        
        with self.lock:
            avg_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
            
            return {
                'bandwidth_mbps': bandwidth['mbps'],
                'bandwidth_kbps': bandwidth['kbps'],
                'avg_packet_size': avg_size,
                'total_bytes': self.total_bytes,
                'retransmissions': self.retransmissions,
                'latency_ms': latency,
                'uptime': time.time() - self.start_time
            }


# ============================================================================
# ALERT SYSTEM MODULE
# ============================================================================

class AlertSystem:
    """Manages security alerts and notifications"""
    
    def __init__(self):
        self.alerts = []
        self.alert_counts = Counter()
        self.alert_file = None
        self.console = Console()
        self.lock = threading.Lock()
        
    def add_alert(self, alert):
        """Add new alert"""
        with self.lock:
            self.alerts.append(alert)
            self.alert_counts[alert['type']] += 1
            
            # Write to file if configured
            if self.alert_file:
                self._write_alert_to_file(alert)
            
            # Console notification
            self._print_alert(alert)
    
    def configure_file_output(self, filepath):
        """Configure alert file output"""
        self.alert_file = filepath
        # Write header
        with open(self.alert_file, 'w') as f:
            f.write("timestamp,type,severity,source,description\n")
    
    def _write_alert_to_file(self, alert):
        """Write alert to file"""
        try:
            with open(self.alert_file, 'a') as f:
                f.write(f"{alert['timestamp']},{alert['type']},{alert['severity']},"
                       f"{alert['source']},{alert['description']}\n")
        except Exception as e:
            pass  # Silently fail to avoid disrupting capture
    
    def _print_alert(self, alert):
        """Print alert to console"""
        severity_colors = {
            'LOW': 'yellow',
            'MEDIUM': 'orange',
            'HIGH': 'red',
            'CRITICAL': 'bright_red'
        }
        color = severity_colors.get(alert['severity'], 'white')
        # Note: This will be visible in quiet mode, but that's intended for alerts
    
    def get_alert_summary(self):
        """Get summary of alerts"""
        with self.lock:
            return {
                'total': len(self.alerts),
                'by_type': dict(self.alert_counts),
                'recent': self.alerts[-5:] if self.alerts else []
            }


# ============================================================================
# PACKET CAPTURE MODULE
# ============================================================================

class PacketCapture:
    """Handles packet capture operations"""
    
    def __init__(self, interface=None, filter_str="", packet_count=0):
        self.interface = interface or conf.iface
        self.filter_str = filter_str
        self.packet_count = packet_count
        self.packets = []
        self.stop_event = threading.Event()
        self.callback = None
        
    def start_capture(self, callback=None):
        """Start packet capture in separate thread"""
        self.callback = callback
        self.stop_event.clear()
        
        capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        capture_thread.start()
        return capture_thread
    
    def _capture_loop(self):
        """Internal capture loop"""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: self.stop_event.is_set(),
                filter=self.filter_str if self.filter_str else None,
                count=self.packet_count if self.packet_count > 0 else 0
            )
        except PermissionError:
            print("\n[ERROR] Permission denied. Run with sudo/root privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"\n[ERROR] Capture failed: {e}")
            sys.exit(1)
    
    def _packet_handler(self, packet):
        """Process each captured packet"""
        self.packets.append(packet)
        
        # Limit memory usage
        if len(self.packets) > Config.MAX_PACKETS:
            self.packets.pop(0)
        
        if self.callback:
            self.callback(packet)
    
    def stop_capture(self):
        """Stop packet capture"""
        self.stop_event.set()
    
    def save_pcap(self, filename):
        """Save captured packets to PCAP file"""
        if self.packets:
            wrpcap(filename, self.packets)
            return len(self.packets)
        return 0


# ============================================================================
# PACKET ANALYZER MODULE
# ============================================================================

class PacketAnalyzer:
    """Analyzes and extracts information from packets"""
    
    @staticmethod
    def analyze(packet):
        """Extract detailed information from packet"""
        info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'timestamp_float': time.time(),
            'length': len(packet),
            'protocol': 'Unknown',
            'src_mac': '',
            'dst_mac': '',
            'src_ip': '',
            'dst_ip': '',
            'src_port': '',
            'dst_port': '',
            'flags': '',
            'seq_num': '',
            'payload_preview': '',
            'info': '',
            'tls_version': '',
            'http_method': ''
        }
        
        # Layer 2 - Ethernet
        if packet.haslayer(Ether):
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
        
        # Layer 3 - IP
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto
        
        # ARP Protocol
        if packet.haslayer(ARP):
            info['protocol'] = 'ARP'
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
            info['src_mac'] = packet[ARP].hwsrc
            info['dst_mac'] = packet[ARP].hwdst
            op = packet[ARP].op
            if op == 1:
                info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            elif op == 2:
                info['info'] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
        
        # ICMP Protocol
        elif packet.haslayer(ICMP):
            info['protocol'] = 'ICMP'
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            type_names = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 
                         11: 'Time Exceeded'}
            info['info'] = f"{type_names.get(icmp_type, f'Type {icmp_type}')} (Code: {icmp_code})"
        
        # TCP Protocol
        elif packet.haslayer(TCP):
            info['protocol'] = 'TCP'
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['seq_num'] = packet[TCP].seq
            
            # TCP Flags
            flags = []
            if packet[TCP].flags.S: flags.append('SYN')
            if packet[TCP].flags.A: flags.append('ACK')
            if packet[TCP].flags.F: flags.append('FIN')
            if packet[TCP].flags.R: flags.append('RST')
            if packet[TCP].flags.P: flags.append('PSH')
            if packet[TCP].flags.U: flags.append('URG')
            info['flags'] = ','.join(flags)
            
            # Detect TLS/SSL
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                
                # TLS handshake detection
                if len(payload) > 5 and payload[0] == 0x16:
                    info['protocol'] = 'TLS'
                    tls_version = payload[1:3]
                    version_map = {
                        b'\x03\x01': 'TLS 1.0',
                        b'\x03\x02': 'TLS 1.1',
                        b'\x03\x03': 'TLS 1.2',
                        b'\x03\x04': 'TLS 1.3'
                    }
                    info['tls_version'] = version_map.get(tls_version, 'Unknown')
                    info['info'] = f'TLS Handshake ({info["tls_version"]})'
                
                # HTTP detection
                elif b'HTTP' in payload[:100]:
                    info['protocol'] = 'HTTP'
                    info['info'] = PacketAnalyzer._extract_http_info(payload)
                    
                    # Extract HTTP method
                    methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS']
                    for method in methods:
                        if payload.startswith(method):
                            info['http_method'] = method.decode()
                            break
        
        # UDP Protocol
        elif packet.haslayer(UDP):
            info['protocol'] = 'UDP'
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
            
            # DNS Detection
            if packet.haslayer(DNS):
                info['protocol'] = 'DNS'
                dns = packet[DNS]
                if dns.qr == 0:  # Query
                    if dns.qd:
                        qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                        info['info'] = f"Query: {qname}"
                else:  # Response
                    if dns.an:
                        info['info'] = f"Response: {dns.ancount} answers"
        
        # Payload preview (sanitized)
        if packet.haslayer(Raw) and info['protocol'] not in ['TLS', 'HTTP']:
            raw_data = bytes(packet[Raw].load)
            info['payload_preview'] = PacketAnalyzer._sanitize_payload(raw_data)
        
        return info
    
    @staticmethod
    def _extract_http_info(payload):
        """Extract HTTP request/response info"""
        try:
            data = payload.decode('utf-8', errors='ignore')
            first_line = data.split('\r\n')[0]
            return first_line[:100]
        except:
            return "HTTP Traffic"
    
    @staticmethod
    def _sanitize_payload(data):
        """Sanitize payload for display"""
        try:
            text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:Config.PAYLOAD_PREVIEW_LEN])
            return text
        except:
            return "[Binary Data]"


# ============================================================================
# STATISTICS MODULE
# ============================================================================

class PacketStats:
    """Maintains statistics about captured packets"""
    
    def __init__(self):
        self.total_packets = 0
        self.protocol_count = Counter()
        self.ip_conversations = defaultdict(int)
        self.port_count = Counter()
        self.start_time = time.time()
        self.packet_sizes = []
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.lock = threading.Lock()
    
    def update(self, packet_info):
        """Update statistics with new packet"""
        with self.lock:
            self.total_packets += 1
            self.protocol_count[packet_info['protocol']] += 1
            
            if packet_info['src_ip'] and packet_info['dst_ip']:
                conv = f"{packet_info['src_ip']} <-> {packet_info['dst_ip']}"
                self.ip_conversations[conv] += 1
                self.src_ips[packet_info['src_ip']] += 1
                self.dst_ips[packet_info['dst_ip']] += 1
            
            if packet_info['dst_port']:
                self.port_count[packet_info['dst_port']] += 1
            
            self.packet_sizes.append(packet_info['length'])
    
    def get_summary(self):
        """Get summary statistics"""
        with self.lock:
            elapsed = time.time() - self.start_time
            pps = self.total_packets / elapsed if elapsed > 0 else 0
            avg_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
            
            return {
                'total': self.total_packets,
                'elapsed': elapsed,
                'pps': pps,
                'avg_size': avg_size,
                'protocols': dict(self.protocol_count.most_common(10)),
                'top_conversations': dict(list(self.ip_conversations.most_common(5))),
                'top_ports': dict(list(self.port_count.most_common(5))),
                'top_src_ips': dict(list(self.src_ips.most_common(5))),
                'top_dst_ips': dict(list(self.dst_ips.most_common(5)))
            }


# ============================================================================
# ADVANCED DASHBOARD MODULE
# ============================================================================

class AdvancedDashboard:
    """Enhanced terminal dashboard with security alerts"""
    
    def __init__(self, stats, ids_system, session_recon, perf_monitor, alert_system):
        self.console = Console()
        self.stats = stats
        self.ids = ids_system
        self.sessions = session_recon
        self.perf = perf_monitor
        self.alerts = alert_system
        self.recent_packets = []
        self.recent_packets_limit = 15
        self.lock = threading.Lock()
    
    def add_packet(self, packet_info):
        """Add packet to recent packets list"""
        with self.lock:
            self.recent_packets.append(packet_info)
            if len(self.recent_packets) > self.recent_packets_limit:
                self.recent_packets.pop(0)
    
    def generate_layout(self):
        """Generate dashboard layout"""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        layout["left"].split_column(
            Layout(name="packets", ratio=2),
            Layout(name="alerts", ratio=1)
        )
        
        layout["right"].split_column(
            Layout(name="stats"),
            Layout(name="performance")
        )
        
        # Header
        header_text = Text()
        header_text.append("🔍 ", style="bold cyan")
        header_text.append("Advanced Network Packet Analyzer ", style="bold cyan")
        header_text.append(f"v{Config.VERSION}", style="dim cyan")
        layout["header"].update(Panel(header_text, style="cyan"))
        
        # Footer
        footer = Panel(
            Text("Press Ctrl+C to stop capture | ", style="dim") + 
            Text("Security Monitoring Active", style="bold green"),
            style="dim"
        )
        layout["footer"].update(footer)
        
        # Content panels
        layout["packets"].update(Panel(self._create_packets_table(), 
                                       title="📦 Recent Packets", border_style="green"))
        layout["alerts"].update(Panel(self._create_alerts_panel(), 
                                     title="⚠️  Security Alerts", border_style="red"))
        layout["stats"].update(Panel(self._create_stats_panel(), 
                                    title="📊 Statistics", border_style="blue"))
        layout["performance"].update(Panel(self._create_performance_panel(), 
                                          title="⚡ Performance", border_style="yellow"))
        
        return layout
    
    def _create_packets_table(self):
        """Create recent packets table"""
        table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
        table.add_column("Time", style="dim", width=11)
        table.add_column("Proto", width=7)
        table.add_column("Source", width=21)
        table.add_column("Dest", width=21)
        table.add_column("Info", overflow="fold")
        
        with self.lock:
            for pkt in self.recent_packets[-12:]:
                src = f"{pkt['src_ip']}:{pkt['src_port']}" if pkt['src_port'] else pkt['src_ip']
                dst = f"{pkt['dst_ip']}:{pkt['dst_port']}" if pkt['dst_port'] else pkt['dst_ip']
                
                proto_style = {
                    'TCP': 'cyan', 'UDP': 'yellow', 'ICMP': 'red',
                    'ARP': 'magenta', 'DNS': 'green', 'HTTP': 'bright_cyan',
                    'TLS': 'bright_blue'
                }.get(pkt['protocol'], 'white')
                
                table.add_row(
                    pkt['timestamp'].split()[1][:11],
                    f"[{proto_style}]{pkt['protocol']}[/{proto_style}]",
                    src[:21], dst[:21],
                    (pkt['info'] or pkt['flags'] or pkt['payload_preview'])[:35]
                )
        
        return table
    
    def _create_alerts_panel(self):
        """Create security alerts panel"""
        alert_summary = self.alerts.get_alert_summary()
        recent_alerts = self.ids.get_recent_alerts(5)
        
        if not recent_alerts:
            return Text("No security alerts", style="dim green")
        
        text = ""
        severity_symbols = {
            'LOW': '⚠️ ',
            'MEDIUM': '⚠️ ',
            'HIGH': '🚨',
            'CRITICAL': '🔥'
        }
        
        for alert in recent_alerts:
            symbol = severity_symbols.get(alert['severity'], '⚠️ ')
            text += f"{symbol} [{alert['severity']}] {alert['type']}\n"
            text += f"   {alert['description']}\n"
            text += f"   Source: {alert['source']}\n\n"
        
        return Text(text.strip())
    
    def _create_stats_panel(self):
        """Create statistics panel"""
        summary = self.stats.get_summary()
        
        text = f"[bold cyan]Capture Info[/bold cyan]\n"
        text += f"[yellow]Total Packets:[/yellow] {summary['total']:,}\n"
        text += f"[yellow]Duration:[/yellow] {summary['elapsed']:.1f}s\n"
        text += f"[yellow]Rate:[/yellow] {summary['pps']:.1f} pkt/s\n"
        text += f"[yellow]Avg Size:[/yellow] {summary['avg_size']:.0f} bytes\n\n"
        
        text += f"[bold cyan]Top Protocols[/bold cyan]\n"
        for proto, count in list(summary['protocols'].items())[:5]:
            pct = (count / summary['total'] * 100) if summary['total'] > 0 else 0
            text += f"  {proto:8s}: {count:4d} ({pct:4.1f}%)\n"
        
        text += f"\n[bold cyan]Top Sources[/bold cyan]\n"
        for ip, count in list(summary['top_src_ips'].items())[:3]:
            text += f"  {ip[:18]:18s}: {count}\n"
        
        return text
    
    def _create_performance_panel(self):
        """Create performance monitoring panel"""
        metrics = self.perf.get_metrics()
        
        text = f"[bold yellow]Network Performance[/bold yellow]\n\n"
        text += f"[cyan]Bandwidth[/cyan]\n"
        text += f"  {metrics['bandwidth_mbps']:.2f} Mbps\n"
        text += f"  {metrics['bandwidth_kbps']:.1f} Kbps\n\n"
        
        text += f"[cyan]Traffic Analysis[/cyan]\n"
        text += f"  Avg Packet: {metrics['avg_packet_size']:.0f} bytes\n"
        text += f"  Total Data: {metrics['total_bytes'] / (1024*1024):.2f} MB\n"
        
        if metrics['latency_ms']:
            text += f"  Est. Latency: {metrics['latency_ms']:.2f} ms\n"
        
        if metrics['retransmissions'] > 0:
            text += f"\n[red]Retransmissions: {metrics['retransmissions']}[/red]\n"
        
        # Session info
        active_sessions = len(self.sessions.get_active_sessions())
        text += f"\n[cyan]Active Sessions[/cyan]\n"
        text += f"  TCP: {active_sessions}\n"
        
        return text


# ============================================================================
# EXPORT MODULE
# ============================================================================

class DataExporter:
    """Export captured data to various formats"""
    
    @staticmethod
    def to_csv(packets_info, filename):
        """Export packet information to CSV"""
        if not packets_info:
            return False
        
        with open(filename, 'w', newline='') as f:
            # Select relevant fields for CSV
            fields = ['timestamp', 'protocol', 'src_ip', 'dst_ip', 'src_port', 
                     'dst_port', 'length', 'flags', 'info']
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(packets_info)
        
        return True
    
    @staticmethod
    def to_json(packets_info, filename):
        """Export packet information to JSON"""
        # Remove timestamp_float for cleaner JSON
        clean_packets = []
        for pkt in packets_info:
            clean_pkt = {k: v for k, v in pkt.items() if k != 'timestamp_float'}
            clean_packets.append(clean_pkt)
        
        with open(filename, 'w') as f:
            json.dump(clean_packets, f, indent=2)
        
        return True
    
    @staticmethod
    def to_alert_report(alerts, filename):
        """Export security alerts to text report"""
        with open(filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write("SECURITY ALERT REPORT\n")
            f.write("="*70 + "\n\n")
            
            alert_summary = Counter([a['type'] for a in alerts])
            f.write("SUMMARY:\n")
            f.write("-"*70 + "\n")
            for alert_type, count in alert_summary.items():
                f.write(f"{alert_type}: {count} incidents\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("DETAILED ALERTS:\n")
            f.write("="*70 + "\n\n")
            
            for i, alert in enumerate(alerts, 1):
                f.write(f"[{i}] {alert['type']} - {alert['severity']}\n")
                f.write(f"    Time: {alert['timestamp']}\n")
                f.write(f"    Source: {alert['source']}\n")
                f.write(f"    Description: {alert['description']}\n")
                if 'details' in alert:
                    f.write(f"    Details: {alert['details']}\n")
                f.write("\n")
        
        return True


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class AdvancedPacketAnalyzer:
    """Main application controller with all advanced features"""
    
    def __init__(self, args):
        self.args = args
        self.capture = None
        self.stats = PacketStats()
        self.ids = IntrusionDetector()
        self.sessions = SessionReconstructor()
        self.perf = PerformanceMonitor()
        self.alert_system = AlertSystem()
        self.dashboard = AdvancedDashboard(
            self.stats, self.ids, self.sessions, 
            self.perf, self.alert_system
        )
        self.packets_info = []
        
        # Configure alert file if requested
        if args.save_alerts:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_dir = Path(args.output) if args.output else Path('captures')
            output_dir.mkdir(exist_ok=True)
            alert_file = output_dir / f"alerts_{timestamp}.csv"
            self.alert_system.configure_file_output(str(alert_file))
    
    def show_banner(self):
        """Display application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║     Advanced Network Packet Analyzer Toolkit v2.0.0             ║
║                                                                  ║
║  Features:                                                       ║
║   ✓ Real-time packet capture and analysis                       ║
║   ✓ Intrusion detection (Port scans, DoS, ARP spoofing)        ║
║   ✓ Session reconstruction and flow tracking                    ║
║   ✓ Performance monitoring and bandwidth analysis               ║
║   ✓ Advanced protocol analysis (TCP/UDP/ICMP/ARP/DNS/HTTP/TLS) ║
║   ✓ Security alerting system                                    ║
║                                                                  ║
║  ⚠️  ETHICAL USE ONLY - EDUCATIONAL PURPOSE ⚠️                   ║
║                                                                  ║
║  Only use on networks you own or have explicit authorization.   ║
║  Unauthorized packet sniffing is illegal.                       ║
╚══════════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    def validate_interface(self):
        """Validate network interface"""
        available = get_if_list()
        
        if self.args.interface not in available:
            print(f"\n[ERROR] Interface '{self.args.interface}' not found.")
            print(f"Available interfaces: {', '.join(available)}")
            sys.exit(1)
    
    def check_permissions(self):
        """Check if running with sufficient privileges"""
        if os.geteuid() != 0:
            print("\n[WARNING] Not running as root. Packet capture may fail.")
            print("Run with: sudo python3 packet_analyzer.py")
            response = input("\nContinue anyway? (y/N): ")
            if response.lower() != 'y':
                sys.exit(0)
    
    def packet_callback(self, packet):
        """Callback for each captured packet"""
        # Analyze packet
        packet_info = PacketAnalyzer.analyze(packet)
        
        # Update statistics
        self.stats.update(packet_info)
        self.dashboard.add_packet(packet_info)
        self.packets_info.append(packet_info)
        
        # Performance monitoring
        self.perf.record_packet(packet_info['length'], packet_info['timestamp_float'])
        
        # Session tracking
        if packet_info['protocol'] == 'TCP':
            self.sessions.track_tcp_session(
                packet_info['src_ip'], packet_info['dst_ip'],
                packet_info['src_port'], packet_info['dst_port'],
                packet_info['flags'], packet_info['seq_num'],
                packet_info['length']
            )
        
        # Flow tracking
        if packet_info['src_ip'] and packet_info['dst_ip']:
            self.sessions.track_flow(
                packet_info['src_ip'], packet_info['dst_ip'],
                packet_info['protocol'], packet_info['length']
            )
        
        # Intrusion detection
        if self.args.enable_ids:
            # Check for port scanning
            if packet_info['dst_port']:
                alert = self.ids.check_port_scan(
                    packet_info['src_ip'], 
                    packet_info['dst_port'],
                    packet_info['timestamp_float']
                )
                if alert:
                    self.alert_system.add_alert(alert)
            
            # Check for DoS attacks
            if packet_info['src_ip']:
                alert = self.ids.check_dos_attack(
                    packet_info['src_ip'],
                    packet_info['timestamp_float']
                )
                if alert:
                    self.alert_system.add_alert(alert)
            
            # Check for ARP spoofing
            if packet_info['protocol'] == 'ARP':
                alert = self.ids.check_arp_spoofing(
                    packet_info['src_ip'],
                    packet_info['src_mac']
                )
                if alert:
                    self.alert_system.add_alert(alert)
    
    def run_dashboard_mode(self):
        """Run with live dashboard"""
        self.capture = PacketCapture(
            interface=self.args.interface,
            filter_str=self.args.filter,
            packet_count=self.args.count
        )
        
        capture_thread = self.capture.start_capture(callback=self.packet_callback)
        
        # Cleanup thread for old sessions
        def cleanup_loop():
            while not self.capture.stop_event.is_set():
                time.sleep(30)
                self.sessions.cleanup_old_sessions()
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        
        try:
            with Live(self.dashboard.generate_layout(), refresh_per_second=2) as live:
                while capture_thread.is_alive():
                    live.update(self.dashboard.generate_layout())
                    time.sleep(Config.REFRESH_RATE)
        except KeyboardInterrupt:
            print("\n\n[INFO] Stopping capture...")
        finally:
            self.capture.stop_capture()
            capture_thread.join(timeout=2)
    
    def run_quiet_mode(self):
        """Run without dashboard"""
        self.capture = PacketCapture(
            interface=self.args.interface,
            filter_str=self.args.filter,
            packet_count=self.args.count
        )
        
        print(f"\n[INFO] Starting capture on {self.args.interface}")
        if self.args.filter:
            print(f"[INFO] Filter: {self.args.filter}")
        if self.args.enable_ids:
            print("[INFO] Intrusion Detection: ENABLED")
        print("[INFO] Press Ctrl+C to stop\n")
        
        capture_thread = self.capture.start_capture(callback=self.packet_callback)
        
        # Progress indicator
        packet_count = [0]
        def progress_loop():
            while not self.capture.stop_event.is_set():
                time.sleep(5)
                packet_count[0] = self.stats.total_packets
                print(f"[INFO] Captured {packet_count[0]} packets...", end='\r')
        
        progress_thread = threading.Thread(target=progress_loop, daemon=True)
        progress_thread.start()
        
        try:
            capture_thread.join()
        except KeyboardInterrupt:
            print("\n\n[INFO] Stopping capture...")
            self.capture.stop_capture()
            capture_thread.join(timeout=2)
    
    def save_results(self):
        """Save capture results and generate reports"""
        if not self.packets_info:
            print("[INFO] No packets captured.")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = Path(self.args.output) if self.args.output else Path('captures')
        output_dir.mkdir(exist_ok=True)
        
        print(f"\n{'='*70}")
        print("Saving Results...")
        print(f"{'='*70}")
        
        # Save PCAP
        if self.args.save_pcap:
            pcap_file = output_dir / f"capture_{timestamp}.pcap"
            count = self.capture.save_pcap(str(pcap_file))
            print(f"[✓] Saved {count} packets to: {pcap_file}")
        
        # Save CSV
        if self.args.save_csv:
            csv_file = output_dir / f"capture_{timestamp}.csv"
            DataExporter.to_csv(self.packets_info, str(csv_file))
            print(f"[✓] Saved packet info to: {csv_file}")
        
        # Save JSON
        if self.args.save_json:
            json_file = output_dir / f"capture_{timestamp}.json"
            DataExporter.to_json(self.packets_info, str(json_file))
            print(f"[✓] Saved packet info to: {json_file}")
        
        # Save alert report
        alerts = self.ids.get_recent_alerts(1000)
        if alerts and self.args.save_alerts:
            alert_file = output_dir / f"alert_report_{timestamp}.txt"
            DataExporter.to_alert_report(alerts, str(alert_file))
            print(f"[✓] Saved alert report to: {alert_file}")
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print capture summary"""
        summary = self.stats.get_summary()
        perf = self.perf.get_metrics()
        alert_summary = self.alert_system.get_alert_summary()
        
        print(f"\n{'='*70}")
        print("CAPTURE SUMMARY")
        print(f"{'='*70}")
        
        # Basic stats
        print(f"\n📊 Packet Statistics:")
        print(f"  Total Packets: {summary['total']:,}")
        print(f"  Capture Duration: {summary['elapsed']:.2f} seconds")
        print(f"  Average Rate: {summary['pps']:.2f} packets/sec")
        print(f"  Average Size: {summary['avg_size']:.0f} bytes")
        
        # Protocol distribution
        print(f"\n🔍 Protocol Distribution:")
        for proto, count in summary['protocols'].items():
            percentage = (count / summary['total'] * 100) if summary['total'] > 0 else 0
            bar = '█' * int(percentage / 2)
            print(f"  {proto:10s}: {count:6d} ({percentage:5.1f}%) {bar}")
        
        # Performance metrics
        print(f"\n⚡ Performance Metrics:")
        print(f"  Bandwidth: {perf['bandwidth_mbps']:.2f} Mbps ({perf['bandwidth_kbps']:.1f} Kbps)")
        print(f"  Total Data: {perf['total_bytes'] / (1024*1024):.2f} MB")
        if perf['latency_ms']:
            print(f"  Est. Latency: {perf['latency_ms']:.2f} ms")
        if perf['retransmissions'] > 0:
            print(f"  TCP Retransmissions: {perf['retransmissions']}")
        
        # Top talkers
        print(f"\n💬 Top Conversations:")
        for conv, count in list(summary['top_conversations'].items())[:5]:
            print(f"  {conv}: {count} packets")
        
        # Active sessions
        active_sessions = self.sessions.get_active_sessions()
        if active_sessions:
            print(f"\n🔗 Active TCP Sessions: {len(active_sessions)}")
            for session in active_sessions[:5]:
                print(f"  {session['key']}: {session['packets']} pkts, "
                      f"{session['bytes']} bytes, State: {session['state']}")
        
        # Top flows
        top_flows = self.sessions.get_top_flows(5, by='bytes')
        if top_flows:
            print(f"\n📈 Top Data Flows:")
            for flow in top_flows:
                mb = flow['bytes'] / (1024 * 1024)
                print(f"  {flow['flow']}: {mb:.2f} MB ({flow['packets']} packets)")
        
        # Security alerts
        if alert_summary['total'] > 0:
            print(f"\n🚨 Security Alerts: {alert_summary['total']} total")
            for alert_type, count in alert_summary['by_type'].items():
                print(f"  {alert_type}: {count} incidents")
            
            if alert_summary['recent']:
                print(f"\n  Recent Alerts:")
                for alert in alert_summary['recent'][-3:]:
                    print(f"    [{alert['severity']}] {alert['type']}: {alert['description']}")
        
        print(f"\n{'='*70}\n")
    
    def run(self):
        """Main application entry point"""
        self.show_banner()
        self.check_permissions()
        self.validate_interface()
        
        # Run capture
        if self.args.quiet:
            self.run_quiet_mode()
        else:
            self.run_dashboard_mode()
        
        # Save results
        self.save_results()


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Network Packet Analyzer - Professional packet capture and analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full-featured capture with IDS and dashboard
  sudo python3 packet_analyzer.py --ids
  
  # Capture HTTP/HTTPS traffic with alerts
  sudo python3 packet_analyzer.py -f "tcp port 80 or tcp port 443" --ids --alerts
  
  # Capture and analyze DNS traffic
  sudo python3 packet_analyzer.py -f "udp port 53" -c 200
  
  # Monitor specific host with all features
  sudo python3 packet_analyzer.py -f "host 192.168.1.100" --ids --alerts --pcap --csv --json
  
  # Quiet mode for automation
  sudo python3 packet_analyzer.py -q --ids --pcap --alerts -c 1000
  
  # Monitor for security threats
  sudo python3 packet_analyzer.py --ids -f "not port 22" --alerts

BPF Filter Examples:
  "tcp"                          - TCP packets only
  "udp port 53"                  - DNS traffic
  "tcp port 80 or tcp port 443"  - HTTP/HTTPS
  "host 192.168.1.1"             - Specific host
  "net 10.0.0.0/8"               - Network range
  "not arp and not broadcast"    - Exclude ARP/broadcast
        """
    )
    
    # Capture options
    parser.add_argument('-i', '--interface', 
                       default=conf.iface,
                       help='Network interface (default: auto-detect)')
    
    parser.add_argument('-f', '--filter',
                       default='',
                       help='BPF filter expression')
    
    parser.add_argument('-c', '--count',
                       type=int,
                       default=0,
                       help='Number of packets to capture (0 = unlimited)')
    
    parser.add_argument('-q', '--quiet',
                       action='store_true',
                       help='Quiet mode (no dashboard)')
    
    parser.add_argument('-o', '--output',
                       default='captures',
                       help='Output directory for saved files')
    
    # Output options
    parser.add_argument('--pcap',
                       dest='save_pcap',
                       action='store_true',
                       help='Save packets to PCAP file')
    
    parser.add_argument('--csv',
                       dest='save_csv',
                       action='store_true',
                       help='Save packet info to CSV')
    
    parser.add_argument('--json',
                       dest='save_json',
                       action='store_true',
                       help='Save packet info to JSON')
    
    parser.add_argument('--alerts',
                       dest='save_alerts',
                       action='store_true',
                       help='Save security alerts report')
    
    # Feature options
    parser.add_argument('--ids',
                       dest='enable_ids',
                       action='store_true',
                       help='Enable intrusion detection system')
    
    parser.add_argument('--list-interfaces',
                       action='store_true',
                       help='List available network interfaces and exit')
    
    parser.add_argument('--version',
                       action='version',
                       version=f'%(prog)s {Config.VERSION}')
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        print("\n Available network interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        sys.exit(0)
    
    # Default to saving PCAP if no save option specified
    if not (args.save_pcap or args.save_csv or args.save_json):
        args.save_pcap = True
        args.save_csv = True
    
    # Run application
    app = AdvancedPacketAnalyzer(args)
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        print("\n\n[INFO] Received interrupt signal. Stopping...")
        if app.capture:
            app.capture.stop_capture()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    app.run()


if __name__ == '__main__':
    main()