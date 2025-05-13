# Network Sniffer IDS

## Project Description

The **Network Sniffer and Intrusion Detection System (IDS)** is a Python-based tool designed to monitor and analyze network traffic in real time. It uses the powerful **Scapy** library to capture packets and detect potential network security threats. This system focuses on identifying common forms of cyberattacks, such as **SYN Floods** and **Port Scans**, while also keeping an eye on traffic from **blacklisted IP addresses**.

The tool is built to assist in **network security monitoring** and can be used in a variety of environments to detect malicious behavior early. It logs all detected network traffic into a CSV file, providing a detailed record for further analysis or compliance purposes.

### Key Features:
- **Packet Sniffing**: Monitors all incoming and outgoing network traffic, capturing **TCP**, **UDP**, and **ICMP** packets.
- **Intrusion Detection**:
  - **SYN Flood Detection**: Identifies unusual SYN packet activity that could indicate a SYN flood attack, a common denial-of-service (DoS) attack.
  - **Port Scan Detection**: Flags excessive connections to multiple ports on a single IP address, which may suggest an attempted port scan.
  - **Blacklisted IP Detection**: Checks if the traffic is coming from any known **blacklisted IPs**, allowing for immediate action or investigation.
- **Real-time Alerts**: Provides real-time color-coded console output for detected security events, including SYN floods, port scans, and blacklisted IP traffic.
- **CSV Logging**: Logs each captured packet, including the timestamp, source and destination IPs, protocol, and additional information, into a CSV file for record-keeping and analysis.

### Use Cases:
- **Security Analysts**: Detect and monitor suspicious activity in a network environment.
- **Network Administrators**: Keep an eye on network traffic to ensure no unauthorized activity is happening.
- **Cybersecurity Enthusiasts**: Learn about real-time packet sniffing and intrusion detection techniques.
  
This tool serves as a simple yet powerful IDS that helps in protecting networks from basic attacks and monitoring network behavior for potential threats.

---

## Features

- **Packet Sniffing**: Monitors TCP, UDP, and ICMP packets.
- **Intrusion Detection**:
  - Detects **SYN Floods** based on excessive SYN packets.
  - Detects **Port Scans** by monitoring multiple port access to the same IP.
  - Identifies traffic from **blacklisted IPs**.
- **Logging**: Logs packet information (source, destination, protocol, etc.) in a CSV file.
- **Interactive Interface Selection**: Choose the network interface to monitor.

