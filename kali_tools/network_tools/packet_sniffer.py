#!/usr/bin/env python3
"""
Packet Sniffer - A simple network packet sniffer using Scapy
"""

import argparse
import sys
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, Raw
from colorama import init, Fore, Style

# Initialize colorama
init()

def print_banner():
    """Print the tool banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════╗
║ {Fore.GREEN}Python Packet Sniffer {Fore.YELLOW}v1.0{Fore.CYAN}                ║
║ {Fore.BLUE}A simple network packet sniffer using Scapy{Fore.CYAN}  ║
╚═══════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def packet_callback(packet, verbose=False, save_to_file=None, file_handle=None):
    """Process each captured packet"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    # Create a list to store packet details
    packet_details = []
    packet_details.append(f"{Fore.YELLOW}[{timestamp}]{Style.RESET_ALL}")
    
    # Ethernet Layer
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        packet_details.append(f"{Fore.BLUE}[Ethernet]{Style.RESET_ALL} {src_mac} -> {dst_mac}")
    
    # ARP Layer
    if ARP in packet:
        op_code = "request" if packet[ARP].op == 1 else "reply"
        packet_details.append(f"{Fore.MAGENTA}[ARP {op_code}]{Style.RESET_ALL} {packet[ARP].psrc} -> {packet[ARP].pdst}")
    
    # IP Layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        packet_details.append(f"{Fore.GREEN}[IP]{Style.RESET_ALL} {src_ip} -> {dst_ip} (TTL: {ttl})")
    
    # TCP Layer
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = []
        if packet[TCP].flags.S: flags.append("SYN")
        if packet[TCP].flags.A: flags.append("ACK")
        if packet[TCP].flags.F: flags.append("FIN")
        if packet[TCP].flags.R: flags.append("RST")
        if packet[TCP].flags.P: flags.append("PSH")
        if packet[TCP].flags.U: flags.append("URG")
        flags_str = " ".join(flags) if flags else "None"
        packet_details.append(f"{Fore.RED}[TCP]{Style.RESET_ALL} {sport} -> {dport} Flags: {flags_str}")
    
    # UDP Layer
    if UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        packet_details.append(f"{Fore.CYAN}[UDP]{Style.RESET_ALL} {sport} -> {dport}")
    
    # ICMP Layer
    if ICMP in packet:
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        type_str = "Echo Request" if icmp_type == 8 else "Echo Reply" if icmp_type == 0 else f"Type: {icmp_type}"
        packet_details.append(f"{Fore.YELLOW}[ICMP]{Style.RESET_ALL} {type_str} (Code: {icmp_code})")
    
    # Payload data
    if Raw in packet and verbose:
        payload = packet[Raw].load
        try:
            payload_str = payload.decode('utf-8', errors='replace')
            if any(c.isprintable() for c in payload_str):
                packet_details.append(f"{Fore.WHITE}[Payload]{Style.RESET_ALL} {payload_str[:100]}{'...' if len(payload_str) > 100 else ''}")
        except:
            packet_details.append(f"{Fore.WHITE}[Payload]{Style.RESET_ALL} Binary data: {len(payload)} bytes")
    
    # Join all details and print
    packet_str = " ".join(packet_details)
    print(packet_str)
    
    # Save to file if requested
    if save_to_file and file_handle:
        # Remove ANSI color codes for file output
        clean_str = packet_str
        for color in [Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.GREEN, Fore.RED, Fore.CYAN, Fore.WHITE, Style.RESET_ALL]:
            clean_str = clean_str.replace(str(color), "")
        file_handle.write(clean_str + "\n")
        file_handle.flush()

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Python Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 for infinite)')
    parser.add_argument('-f', '--filter', default='', help='BPF filter string (e.g., "tcp port 80" or "icmp")')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (show packet payloads)')
    parser.add_argument('-o', '--output', help='Save output to file')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Prepare file for output if specified
    file_handle = None
    if args.output:
        try:
            file_handle = open(args.output, 'w')
            print(f"{Fore.GREEN}[+] Saving output to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error opening output file: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    # Print sniffing information
    print(f"{Fore.BLUE}[*] Starting packet capture...{Style.RESET_ALL}")
    if args.interface:
        print(f"{Fore.BLUE}[*] Interface: {args.interface}{Style.RESET_ALL}")
    if args.filter:
        print(f"{Fore.BLUE}[*] Filter: {args.filter}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Verbose mode: {'Enabled' if args.verbose else 'Disabled'}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Packet count: {'Infinite' if args.count == 0 else args.count}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop capturing{Style.RESET_ALL}")
    print("-" * 80)
    
    try:
        # Start sniffing
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: packet_callback(pkt, args.verbose, args.output, file_handle),
            count=args.count if args.count > 0 else None,
            store=0
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Packet capture interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
    finally:
        if file_handle:
            file_handle.close()
            print(f"{Fore.GREEN}[+] Output saved to {args.output}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
