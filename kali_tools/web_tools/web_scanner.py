#!/usr/bin/env python3
"""
Web Scanner - A simple web vulnerability scanner
"""

import argparse
import sys
import time
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

def print_banner():
    """Print the tool banner"""
    banner = f"""
{Fore.GREEN}╔═══════════════════════════════════════════════╗
║ {Fore.CYAN}Python Web Scanner {Fore.YELLOW}v1.0{Fore.GREEN}                   ║
║ {Fore.BLUE}A simple web vulnerability scanner{Fore.GREEN}           ║
╚═══════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

class WebScanner:
    """Web vulnerability scanner class"""
    
    def __init__(self, target_url, threads=10, timeout=10, user_agent=None, cookies=None, 
                 verify_ssl=False, max_depth=2, verbose=False):
        """Initialize the scanner"""
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_depth = max_depth
        self.verbose = verbose
        
        # Set default user agent if not provided
        if user_agent:
            self.user_agent = user_agent
        else:
            self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        
        # Parse cookies if provided
        self.cookies = {}
        if cookies:
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    self.cookies[name] = value
        
        # Initialize session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        if self.cookies:
            self.session.cookies.update(self.cookies)
        
        # Initialize data structures
        self.visited_urls = set()
        self.urls_to_visit = [self.target_url]
        self.forms = []
        self.findings = []
    
    def scan(self):
        """Start the scanning process"""
        print(f"{Fore.BLUE}[*] Starting scan on: {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Max depth: {self.max_depth}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Threads: {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Verify SSL: {self.verify_ssl}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] User-Agent: {self.user_agent}{Style.RESET_ALL}")
        if self.cookies:
            print(f"{Fore.BLUE}[*] Cookies: {self.cookies}{Style.RESET_ALL}")
        
        start_time = time.time()
        
        # Crawl the website
        self.crawl()
        
        # Scan for vulnerabilities
        print(f"\n{Fore.BLUE}[*] Crawling completed. Starting vulnerability scan...{Style.RESET_ALL}")
        
        # Scan for common vulnerabilities
        self.scan_xss()
        self.scan_sqli()
        self.scan_open_redirects()
        self.scan_directory_traversal()
        self.scan_server_info()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Print summary
        print(f"\n{Fore.BLUE}[*] Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] URLs crawled: {len(self.visited_urls)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Forms found: {len(self.forms)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Vulnerabilities found: {len(self.findings)}{Style.RESET_ALL}")
        
        # Print findings
        if self.findings:
            print(f"\n{Fore.YELLOW}[*] Findings:{Style.RESET_ALL}")
            for i, finding in enumerate(self.findings, 1):
                print(f"\n{Fore.YELLOW}[{i}] {finding['type']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}    URL: {finding['url']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}    Description: {finding['description']}{Style.RESET_ALL}")
                if 'payload' in finding:
                    print(f"{Fore.CYAN}    Payload: {finding['payload']}{Style.RESET_ALL}")
                if 'evidence' in finding:
                    print(f"{Fore.CYAN}    Evidence: {finding['evidence']}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+] No vulnerabilities found{Style.RESET_ALL}")
    
    def crawl(self):
        """Crawl the website to discover URLs and forms"""
        print(f"{Fore.BLUE}[*] Starting crawling process...{Style.RESET_ALL}")
        
        current_depth = 0
        urls_at_current_depth = len(self.urls_to_visit)
        urls_for_next_depth = 0
        
        while self.urls_to_visit and current_depth <= self.max_depth:
            print(f"{Fore.BLUE}[*] Crawling at depth {current_depth}, {len(self.urls_to_visit)} URLs to process{Style.RESET_ALL}")
            
            # Process URLs at current depth in parallel
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for _ in range(min(urls_at_current_depth, len(self.urls_to_visit))):
                    if not self.urls_to_visit:
                        break
                    
                    url = self.urls_to_visit.pop(0)
                    if url in self.visited_urls:
                        continue
                    
                    self.visited_urls.add(url)
                    executor.submit(self.process_url, url)
            
            # Move to next depth
            if current_depth < self.max_depth:
                urls_at_current_depth = urls_for_next_depth
                urls_for_next_depth = 0
                current_depth += 1
            else:
                break
    
    def process_url(self, url):
        """Process a single URL: fetch it and extract links and forms"""
        try:
            if self.verbose:
                print(f"{Fore.BLUE}[*] Processing: {url}{Style.RESET_ALL}")
            
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            
            # Extract links
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(url, href)
                    
                    # Only follow links to the same domain
                    if absolute_url.startswith(self.target_url) and absolute_url not in self.visited_urls and absolute_url not in self.urls_to_visit:
                        self.urls_to_visit.append(absolute_url)
                
                # Find all forms
                for form in soup.find_all('form'):
                    form_data = {
                        'url': url,
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'get').lower(),
                        'inputs': []
                    }
                    
                    # Extract form inputs
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        input_type = input_field.get('type', '')
                        input_name = input_field.get('name', '')
                        
                        if input_name and input_type != 'submit' and input_type != 'button':
                            form_data['inputs'].append({
                                'name': input_name,
                                'type': input_type
                            })
                    
                    self.forms.append(form_data)
        
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error processing {url}: {e}{Style.RESET_ALL}")
    
    def scan_xss(self):
        """Scan for XSS vulnerabilities in forms"""
        print(f"{Fore.BLUE}[*] Scanning for XSS vulnerabilities...{Style.RESET_ALL}")
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '"><img src="x" onerror="alert(\'XSS\')">',
            '\';alert(\'XSS\');//'
        ]
        
        for form in self.forms:
            if not form['inputs']:
                continue
            
            for payload in xss_payloads:
                data = {}
                for input_field in form['inputs']:
                    data[input_field['name']] = payload
                
                try:
                    if form['method'] == 'post':
                        response = self.session.post(form['action'], data=data, timeout=self.timeout, verify=self.verify_ssl)
                    else:
                        response = self.session.get(form['action'], params=data, timeout=self.timeout, verify=self.verify_ssl)
                    
                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        self.findings.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': form['action'],
                            'description': f"XSS vulnerability found in {form['method'].upper()} form",
                            'payload': payload,
                            'evidence': f"Payload was reflected in the response"
                        })
                        break  # Found XSS in this form, move to next
                
                except requests.exceptions.RequestException:
                    continue
    
    def scan_sqli(self):
        """Scan for SQL injection vulnerabilities in forms"""
        print(f"{Fore.BLUE}[*] Scanning for SQL Injection vulnerabilities...{Style.RESET_ALL}")
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "' OR 1=1#",
            "') OR ('1'='1",
            "1' OR '1'='1"
        ]
        
        sqli_errors = [
            "SQL syntax",
            "mysql_fetch_array",
            "mysql_fetch",
            "mysql_num_rows",
            "mysql_query",
            "pg_query",
            "ORA-01756",
            "ORA-00933",
            "sqlite_query",
            "SQLSTATE",
            "Microsoft SQL Server",
            "ODBC Driver"
        ]
        
        for form in self.forms:
            if not form['inputs']:
                continue
            
            for payload in sqli_payloads:
                data = {}
                for input_field in form['inputs']:
                    data[input_field['name']] = payload
                
                try:
                    if form['method'] == 'post':
                        response = self.session.post(form['action'], data=data, timeout=self.timeout, verify=self.verify_ssl)
                    else:
                        response = self.session.get(form['action'], params=data, timeout=self.timeout, verify=self.verify_ssl)
                    
                    # Check for SQL error messages
                    for error in sqli_errors:
                        if error in response.text:
                            self.findings.append({
                                'type': 'SQL Injection',
                                'url': form['action'],
                                'description': f"SQL Injection vulnerability found in {form['method'].upper()} form",
                                'payload': payload,
                                'evidence': f"SQL error message detected: {error}"
                            })
                            break
                
                except requests.exceptions.RequestException:
                    continue
    
    def scan_open_redirects(self):
        """Scan for open redirect vulnerabilities"""
        print(f"{Fore.BLUE}[*] Scanning for Open Redirect vulnerabilities...{Style.RESET_ALL}")
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'returnTo', 'goto', 'redir', 'destination']
        redirect_payloads = ['https://evil.com', '//evil.com', 'https:evil.com']
        
        for url in self.visited_urls:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in redirect_params:
                if param in query_params:
                    for payload in redirect_payloads:
                        test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={payload}")
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
                            
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if payload in location or payload.replace('https:', '') in location:
                                    self.findings.append({
                                        'type': 'Open Redirect',
                                        'url': test_url,
                                        'description': f"Open Redirect vulnerability found in '{param}' parameter",
                                        'payload': payload,
                                        'evidence': f"Redirected to: {location}"
                                    })
                                    break
                        
                        except requests.exceptions.RequestException:
                            continue
    
    def scan_directory_traversal(self):
        """Scan for directory traversal vulnerabilities"""
        print(f"{Fore.BLUE}[*] Scanning for Directory Traversal vulnerabilities...{Style.RESET_ALL}")
        
        traversal_params = ['file', 'path', 'dir', 'filepath', 'filename', 'include', 'page', 'view', 'doc']
        traversal_payloads = [
            '../../../etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '....//....//....//etc//passwd',
            '..\\..\\..\\windows\\win.ini',
            '..%5c..%5c..%5cwindows%5cwin.ini'
        ]
        
        traversal_evidence = [
            'root:x:0:0',
            '[fonts]',
            '[extensions]',
            'uid=',
            'boot loader'
        ]
        
        for url in self.visited_urls:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in traversal_params:
                if param in query_params:
                    for payload in traversal_payloads:
                        test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={payload}")
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                            
                            for evidence in traversal_evidence:
                                if evidence in response.text:
                                    self.findings.append({
                                        'type': 'Directory Traversal',
                                        'url': test_url,
                                        'description': f"Directory Traversal vulnerability found in '{param}' parameter",
                                        'payload': payload,
                                        'evidence': f"Found evidence: {evidence}"
                                    })
                                    break
                        
                        except requests.exceptions.RequestException:
                            continue
    
    def scan_server_info(self):
        """Scan for server information disclosure"""
        print(f"{Fore.BLUE}[*] Scanning for Server Information Disclosure...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl)
            
            # Check headers for server information
            server = response.headers.get('Server', '')
            x_powered_by = response.headers.get('X-Powered-By', '')
            
            if server:
                self.findings.append({
                    'type': 'Information Disclosure',
                    'url': self.target_url,
                    'description': 'Server header reveals server software information',
                    'evidence': f"Server: {server}"
                })
            
            if x_powered_by:
                self.findings.append({
                    'type': 'Information Disclosure',
                    'url': self.target_url,
                    'description': 'X-Powered-By header reveals technology information',
                    'evidence': f"X-Powered-By: {x_powered_by}"
                })
        
        except requests.exceptions.RequestException:
            pass

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Python Web Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use (default: 10)')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    parser.add_argument('-a', '--user-agent', help='Custom User-Agent string')
    parser.add_argument('-c', '--cookies', help='Cookies to include with requests (format: name1=value1; name2=value2)')
    parser.add_argument('-k', '--insecure', action='store_true', help='Allow insecure SSL connections')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] Error: URL must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create scanner and start scanning
    scanner = WebScanner(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        cookies=args.cookies,
        verify_ssl=not args.insecure,
        max_depth=args.depth,
        verbose=args.verbose
    )
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
