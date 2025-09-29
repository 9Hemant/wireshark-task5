#!/usr/bin/env python3
"""
basic_analysis.py - Basic PCAP file analysis using Python and Scapy

This script provides basic analysis of captured network traffic.
Install requirements: pip install scapy matplotlib

Usage: python basic_analysis.py network_capture.pcap
"""

import sys
try:
    from scapy.all import rdpcap, TCP, UDP, IP, DNS, ICMP, Raw
    import matplotlib.pyplot as plt
    from collections import Counter, defaultdict
except ImportError:
    print("❌ Required libraries not found!")
    print("📦 Install with: pip install scapy matplotlib")
    sys.exit(1)

def analyze_pcap(filename):
    """Analyze a PCAP file and generate statistics"""

    print(f"🔍 Analyzing PCAP file: {filename}")
    print("=" * 50)

    try:
        packets = rdpcap(filename)
        print(f"📦 Total packets loaded: {len(packets)}")
    except Exception as e:
        print(f"❌ Error reading PCAP file: {e}")
        return

    # Protocol analysis
    protocol_stats = Counter()
    ip_stats = defaultdict(int)
    port_stats = defaultdict(int)
    dns_queries = []
    packet_sizes = []

    for packet in packets:
        packet_sizes.append(len(packet))

        # Protocol identification
        if packet.haslayer(DNS):
            protocol_stats['DNS'] += 1
            if packet[DNS].qd and packet[DNS].qr == 0:  # DNS query
                dns_queries.append(packet[DNS].qd.qname.decode('utf-8', errors='ignore'))

        if packet.haslayer(TCP):
            protocol_stats['TCP'] += 1
            port_stats[packet[TCP].dport] += 1

        if packet.haslayer(UDP):
            protocol_stats['UDP'] += 1
            port_stats[packet[UDP].dport] += 1

        if packet.haslayer(ICMP):
            protocol_stats['ICMP'] += 1

        if packet.haslayer(IP):
            ip_stats[packet[IP].src] += 1
            ip_stats[packet[IP].dst] += 1

        # Application layer protocols
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if 'HTTP' in payload:
                protocol_stats['HTTP'] += 1

    # Display results
    print("\n📊 Protocol Distribution:")
    for protocol, count in protocol_stats.most_common():
        percentage = (count / len(packets)) * 100
        print(f"   {protocol:8}: {count:4} packets ({percentage:5.1f}%)")

    print(f"\n🌐 Top 10 IP Addresses:")
    for ip, count in Counter(ip_stats).most_common(10):
        print(f"   {ip:15}: {count:4} packets")

    print(f"\n🔌 Top 10 Destination Ports:")
    for port, count in Counter(port_stats).most_common(10):
        port_name = get_port_name(port)
        print(f"   {port:5} ({port_name:8}): {count:4} packets")

    if dns_queries:
        print(f"\n🔍 DNS Queries ({len(dns_queries)} total):")
        for query in Counter(dns_queries).most_common(10):
            print(f"   {query[0]:30}: {query[1]:2} queries")

    # Packet size analysis
    avg_size = sum(packet_sizes) / len(packet_sizes)
    print(f"\n📏 Packet Size Statistics:")
    print(f"   Average size: {avg_size:.1f} bytes")
    print(f"   Min size:     {min(packet_sizes)} bytes")
    print(f"   Max size:     {max(packet_sizes)} bytes")

    # Generate visualization
    create_visualizations(protocol_stats, Counter(port_stats).most_common(10))

    print(f"\n✅ Analysis complete! Check the generated charts.")

def get_port_name(port):
    """Get common port names"""
    port_names = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        993: 'IMAPS', 995: 'POP3S', 587: 'SMTP'
    }
    return port_names.get(port, 'UNKNOWN')

def create_visualizations(protocol_stats, port_stats):
    """Create visualization charts"""

    # Protocol distribution pie chart
    plt.figure(figsize=(12, 5))

    plt.subplot(1, 2, 1)
    protocols = list(protocol_stats.keys())
    counts = list(protocol_stats.values())
    plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
    plt.title('Protocol Distribution')

    # Top ports bar chart
    plt.subplot(1, 2, 2)
    ports = [f"{p[0]}\n({get_port_name(p[0])})" for p in port_stats]
    counts = [p[1] for p in port_stats]
    plt.bar(range(len(ports)), counts)
    plt.xticks(range(len(ports)), ports, rotation=45, ha='right')
    plt.title('Top 10 Destination Ports')
    plt.ylabel('Packet Count')

    plt.tight_layout()
    plt.savefig('network_analysis.png', dpi=300, bbox_inches='tight')
    print("📊 Charts saved as 'network_analysis.png'")

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python basic_analysis.py <pcap_file>")
        print("Example: python basic_analysis.py network_capture.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)

if __name__ == "__main__":
    main()
