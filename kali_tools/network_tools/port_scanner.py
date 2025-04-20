#!/usr/bin/env python3
"""
Port Scanner - A simple port scanner similar to nmap
"""

import socket
import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

# Initialize colorama
init()

def print_banner():
    """Print the tool banner"""
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════╗
║ {Fore.GREEN}Python Port Scanner {Fore.YELLOW}v1.0{Fore.RED}                    ║
║ {Fore.BLUE}A simple port scanner inspired by nmap{Fore.RED}        ║
╚═══════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def scan_port(target, port, timeout=1):
    """Scan a single port on the target"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = "unknown"
            try:
                service = socket.getservbyport(port)
            except:
                pass
            print(f"{Fore.GREEN}[+] Port {port}/tcp is open{Style.RESET_ALL} - {Fore.YELLOW}{service}{Style.RESET_ALL}")
            return port, True
        sock.close()
    except socket.error:
        pass
    return port, False

def scan_target(target, ports, threads=100, timeout=1):
    """Scan a target for open ports"""
    print(f"\n{Fore.BLUE}[*] Starting scan on host: {target}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Scanning {len(ports)} ports with {threads} threads{Style.RESET_ALL}")
    
    start_time = time.time()
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = [executor.submit(scan_port, target, port, timeout) for port in ports]
        for future in results:
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n{Fore.BLUE}[*] Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] {len(open_ports)} ports open out of {len(ports)} ports scanned{Style.RESET_ALL}")
    
    return open_ports

def resolve_hostname(hostname):
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"{Fore.RED}[!] Error: Could not resolve hostname {hostname}{Style.RESET_ALL}")
        sys.exit(1)

def parse_ports(ports_str):
    """Parse port range string into a list of ports"""
    ports = []
    for part in ports_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Python Port Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan (e.g., 1-100 or 22,80,443 or 1-100,443)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads to use')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout for each connection attempt in seconds')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Resolve hostname if needed
    target_ip = resolve_hostname(args.target)
    print(f"{Fore.BLUE}[*] Target IP: {target_ip}{Style.RESET_ALL}")
    
    # Parse ports
    ports = parse_ports(args.ports)
    
    # Start scanning
    scan_target(target_ip, ports, args.threads, args.timeout)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
