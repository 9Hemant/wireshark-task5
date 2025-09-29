# Task 5: Wireshark Network Traffic Analysis

![Wireshark Logo](https://www.wireshark.org/assets/icons/wireshark-icon-256.png)

## 🎯 Objective
Capture live network packets and identify basic protocols and traffic types using Wireshark.

## 📋 Task Requirements
- **Tools**: Wireshark (free)
- **Deliverables**: 
  - Packet capture (.pcap) file
  - Short report of protocols identified
- **Duration**: Complete capture within 1-2 minutes
- **Protocols to identify**: Minimum 3 different protocols

## 🔧 Installation Guide

### Windows Installation
1. Download from [Wireshark Official Site](https://www.wireshark.org/download.html)
2. Run installer as Administrator
3. Accept license and install Npcap when prompted
4. Complete installation and launch

### Linux Installation (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install wireshark
sudo usermod -aG wireshark $(whoami)
# Log out and log back in
```

### macOS Installation
```bash
# Using Homebrew
brew install --cask wireshark
```

## 🚀 Quick Start Guide

### Step 1: Start Packet Capture
1. Launch Wireshark as Administrator/sudo
2. Select your active network interface (Wi-Fi or Ethernet)
3. Click "Start capturing packets" (shark fin icon)

### Step 2: Generate Network Traffic
```bash
# Generate different types of traffic
ping google.com                 # ICMP packets
nslookup github.com             # DNS packets
curl http://httpbin.org/get     # HTTP packets
curl https://httpbin.org/get    # HTTPS/TLS packets
```

### Step 3: Stop and Analyze
1. Stop capture after 1-2 minutes
2. Apply filters to analyze specific protocols:
   - `dns` - DNS traffic
   - `tcp` - TCP traffic
   - `http` - HTTP traffic
   - `udp` - UDP traffic
   - `icmp` - ICMP (ping) traffic

### Step 4: Export Capture
1. File → Save As
2. Choose location and save as `.pcap` file

## 📊 Protocol Analysis Results

| Protocol | Port | Description | Packets Found |
|----------|------|-------------|---------------|
| DNS | 53/UDP | Domain name resolution | ✅ |
| TCP | Various | Reliable transport protocol | ✅ |
| HTTP | 80/TCP | Web traffic (unencrypted) | ✅ |
| HTTPS/TLS | 443/TCP | Secure web traffic | ✅ |
| UDP | Various | Connectionless protocol | ✅ |
| ICMP | N/A | Network diagnostics (ping) | ✅ |

## 🔍 Key Findings

### DNS Protocol Analysis
- **Purpose**: Resolves domain names to IP addresses
- **Transport**: UDP (Port 53)
- **Observed**: Query/response pairs for various domains
- **Key Fields**: Transaction ID, Query Type, Domain Name

### TCP Protocol Analysis  
- **Purpose**: Reliable, connection-oriented communication
- **Features**: 3-way handshake (SYN, SYN-ACK, ACK)
- **Observed**: Connection establishment, data transfer, termination
- **Key Fields**: Sequence numbers, ACK numbers, Window size

### HTTP Protocol Analysis
- **Purpose**: Web page and API communication
- **Transport**: TCP (Port 80)
- **Observed**: GET requests, response codes, headers
- **Security Note**: Unencrypted, data visible in plain text

## 📁 Repository Structure
```
wireshark-network-analysis/
├── README.md                    # This file
├── SOLUTION.md                  # Detailed solution guide
├── network_capture.pcap         # Sample packet capture
├── analysis_report.md           # Detailed analysis report
├── screenshots/                 # Wireshark screenshots
│   ├── interface_selection.png
│   ├── dns_analysis.png
│   ├── tcp_handshake.png
│   └── http_traffic.png
└── scripts/
    ├── generate_traffic.sh      # Traffic generation script
    └── basic_analysis.py        # Python analysis script
```

## 💡 Interview Questions Preparation

<details>
<summary><b>1. What is Wireshark used for?</b></summary>

Wireshark is a network protocol analyzer used for:
- Network troubleshooting and performance monitoring
- Security analysis and intrusion detection  
- Protocol development and debugging
- Educational purposes and certification preparation
- Digital forensics and incident response
</details>

<details>
<summary><b>2. What is a packet?</b></summary>

A packet is a formatted unit of data transmitted over a network containing:
- **Header**: Source/destination addresses, protocol information, control data
- **Payload**: The actual data being transmitted
- **Trailer**: Error checking information (in some protocols)
</details>

<details>
<summary><b>3. How to filter packets in Wireshark?</b></summary>

Wireshark supports two filter types:
- **Capture Filters**: Applied during packet capture (e.g., `host 192.168.1.1`)
- **Display Filters**: Applied to already captured data (e.g., `tcp.port == 80`)

Common filters:
- `http` - HTTP traffic only
- `dns` - DNS queries and responses  
- `tcp.port == 443` - HTTPS traffic
- `ip.src == 192.168.1.100` - Traffic from specific IP
</details>

<details>
<summary><b>4. What is the difference between TCP and UDP?</b></summary>

| Feature | TCP | UDP |
|---------|-----|-----|
| **Connection** | Connection-oriented | Connectionless |
| **Reliability** | Guaranteed delivery | Best effort |
| **Overhead** | Higher | Lower |
| **Speed** | Slower | Faster |
| **Use Cases** | Web, email, file transfer | DNS, video streaming, gaming |
</details>

<details>
<summary><b>5. What is a DNS query packet?</b></summary>

A DNS query packet contains:
- **Transaction ID**: Matches queries with responses
- **Query Type**: A (IPv4), AAAA (IPv6), MX (mail server)
- **Domain Name**: The name being resolved
- **Flags**: Recursion desired, authoritative answer, etc.
</details>

## 🛠️ Troubleshooting

### Common Issues and Solutions
1. **Can't see network interfaces**
   - Solution: Run Wireshark as Administrator (Windows) or with sudo (Linux)

2. **No packets being captured**
   - Solution: Check if selected interface has active traffic
   - Try different network interface

3. **Permission denied errors**
   - Solution: Add user to wireshark group (Linux) or run as admin

4. **Only encrypted traffic visible**
   - Solution: This is normal for HTTPS - use HTTP sites for plain text analysis

## 🎓 Learning Outcomes
After completing this task, you will understand:
- How to capture and analyze network traffic
- Basic network protocols (DNS, TCP, HTTP, UDP, ICMP)  
- Packet filtering and analysis techniques
- Network troubleshooting fundamentals
- Cybersecurity monitoring basics

## 📚 Additional Resources
- [Wireshark Official Documentation](https://www.wireshark.org/docs/)
- [Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Sample Capture Files](https://wiki.wireshark.org/SampleCaptures)
- [Wireshark University](https://wiresharkU.com/)

## 🤝 Contributing
This repository is part of a cybersecurity internship task. Feel free to:
- Report issues or improvements
- Share additional analysis techniques
- Contribute sample capture files
- Add more protocol analysis examples

## 📜 License
This project is for educational purposes as part of the MSME Cyber Security Internship program.

---
**Note**: Always ensure you have proper authorization before capturing network traffic. Only capture traffic on networks you own or have explicit permission to monitor.

## 🏆 Task Completion Checklist
- [ ] Wireshark installed and configured
- [ ] Network interface selected and capture started
- [ ] Traffic generated (web browsing, ping, DNS lookups)
- [ ] Capture stopped after 1-2 minutes
- [ ] At least 3 different protocols identified
- [ ] Packet capture exported as .pcap file
- [ ] Analysis report completed
- [ ] GitHub repository created with all deliverables
- [ ] README.md documentation completed

**Ready to submit? Make sure all files are uploaded to your GitHub repository!** 🚀
