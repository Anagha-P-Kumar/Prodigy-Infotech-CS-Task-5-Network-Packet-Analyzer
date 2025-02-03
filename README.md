# Task-5-Network-Packet-Analyzer
A Network Packet Analyzer, also known as a Packet Sniffer, is a tool that captures and inspects network packets traveling through a network. It helps in monitoring, analyzing, and troubleshooting network traffic, making it an essential tool for cybersecurity professionals, network administrators, and ethical hacker,displaying crucial details such as:
✅ Source & Destination IP Addresses
✅ Protocol Information
✅ Payload Data

The tool is designed for educational and ethical cybersecurity research purposes, allowing users to understand how network traffic flows.

# How Does a Packet Analyzer Work?
1. Captures Network Traffic
- It listens to network interfaces and collects packets in real time.
2. Decodes Packet Structure
- Breaks down packets into Ethernet, IP, and Transport Layer data.
3. Extracts Key Information
- Source & Destination IP addresses
- Protocol (TCP, UDP, ICMP, etc.)
- Payload (data being transmitted)
4. Displays or Stores Data
- Users can analyze traffic patterns, detect intrusions, or debug network issues.
  
# Components of a Packet Analyzer
A packet analyzer typically consists of:
- Packet Capture Engine – Captures raw network packets.
- Protocol Parser – Interprets packet headers and extracts meaningful details.
- Data Display & Logging – Shows the captured packet details for analysis.

# Features
- Captures live network packets using socket programming.
- Decodes Ethernet, IP, TCP, UDP, and ICMP packets.
- Extracts and displays key packet information.
- Supports both IPv4 & IPv6 traffic.
  
# Requirements
- Python 3.x
- Administrator/root privileges (required for capturing network traffic)
- socket and struct libraries (included in Python standard library)

# Use Cases of Packet Analysis
- Network Monitoring – Track bandwidth usage and performance.
- Cybersecurity – Detect anomalies, attacks (MITM, DDoS, etc.), and malware traffic.
- Troubleshooting – Debug network connectivity issues.
- Reverse Engineering – Analyze data transmission for vulnerabilities.

# Ethical & Legal Considerations
- Use only on authorized networks (your own or with permission).
- Unauthorized packet sniffing is illegal and violates privacy laws.
- Follow ethical hacking guidelines when using packet analyzers.
