import scapy.all as scapy
from collections import defaultdict
from datetime import datetime
import csv
import os
from colorama import Fore, Style
import platform
import subprocess

# Dictionary to track SYN packets per IP
syn_counter = defaultdict(int)
PORT_SCAN_THRESHOLD = 50
SYN_FLOOD_THRESHOLD = 100

# Blacklisted IPs (example)
BLACKLIST = {'192.168.1.100', '10.0.0.50'}

LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'packet_log.csv')

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Initialize log file with headers
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Time', 'Source IP', 'Destination IP', 'Protocol', 'Info'])

def log_packet(pkt_time, src, dst, proto, info):
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([pkt_time, src, dst, proto, info])

def detect_intrusion(packet):
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        proto = 'OTHER'
        info = ''

        if packet.haslayer(scapy.TCP):
            proto = 'TCP'
            tcp_layer = packet[scapy.TCP]
            info = f"SRC_PORT={tcp_layer.sport}, DST_PORT={tcp_layer.dport}"

            # SYN detection
            if tcp_layer.flags == 'S':
                syn_counter[src_ip] += 1

                if syn_counter[src_ip] > SYN_FLOOD_THRESHOLD:
                    print(Fore.RED + f"[!] SYN Flood Detected from {src_ip}" + Style.RESET_ALL)

            # Port scan detection (many ports to same IP)
            if syn_counter[src_ip] > PORT_SCAN_THRESHOLD:
                print(Fore.YELLOW + f"[!] Possible Port Scan by {src_ip}" + Style.RESET_ALL)

        elif packet.haslayer(scapy.UDP):
            proto = 'UDP'
            udp_layer = packet[scapy.UDP]
            info = f"SRC_PORT={udp_layer.sport}, DST_PORT={udp_layer.dport}"

        elif packet.haslayer(scapy.ICMP):
            proto = 'ICMP'
            info = "ICMP Packet"

        # Check for blacklist
        if src_ip in BLACKLIST:
            print(Fore.RED + f"[!] Traffic from Blacklisted IP: {src_ip}" + Style.RESET_ALL)

        log_packet(pkt_time, src_ip, dst_ip, proto, info)
        print(f"[{pkt_time}] {proto} | {src_ip} -> {dst_ip} | {info}")

def get_available_interfaces():
    try:
        return scapy.get_if_list()
    except Exception as e:
        print(Fore.RED + f"[!] Failed to retrieve network interfaces: {e}" + Style.RESET_ALL)
        return []

def select_interface():
    interfaces = get_available_interfaces()
    if not interfaces:
        return None
    print(Fore.CYAN + "\nAvailable Network Interfaces:" + Style.RESET_ALL)
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}. {iface}")
    while True:
        choice = input(Fore.GREEN + "\nSelect interface number to sniff on: " + Style.RESET_ALL)
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1]
        print(Fore.YELLOW + "[!] Invalid choice. Please enter a valid number." + Style.RESET_ALL)

if __name__ == '__main__':
    print(Fore.CYAN + "[*] Starting Network Sniffer & Intrusion Detection System..." + Style.RESET_ALL)
    iface = select_interface()
    if iface:
        print(Fore.CYAN + f"[*] Sniffing on interface: {iface}" + Style.RESET_ALL)
        scapy.sniff(iface=iface, prn=detect_intrusion, store=0)
    else:
        print(Fore.RED + "[!] Exiting: No valid network interface selected." + Style.RESET_ALL)

