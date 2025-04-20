#!/usr/bin/env python3
"""
Hash Cracker - A tool to crack password hashes using dictionary or brute force attacks
"""

import argparse
import sys
import time
import hashlib
import itertools
import string
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import init, Fore, Style

# Initialize colorama
init()

def print_banner():
    """Print the tool banner"""
    banner = f"""
{Fore.MAGENTA}╔═══════════════════════════════════════════════╗
║ {Fore.GREEN}Python Hash Cracker {Fore.YELLOW}v1.0{Fore.MAGENTA}                  ║
║ {Fore.BLUE}A tool to crack password hashes{Fore.MAGENTA}             ║
╚═══════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def hash_password(password, hash_type):
    """Hash a password using the specified algorithm"""
    password_bytes = password.encode('utf-8')
    
    if hash_type == 'md5':
        return hashlib.md5(password_bytes).hexdigest()
    elif hash_type == 'sha1':
        return hashlib.sha1(password_bytes).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(password_bytes).hexdigest()
    elif hash_type == 'sha512':
        return hashlib.sha512(password_bytes).hexdigest()
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")

def dictionary_attack(target_hash, wordlist_file, hash_type, num_threads=4):
    """Perform a dictionary attack on the target hash"""
    print(f"{Fore.BLUE}[*] Starting dictionary attack...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Target hash: {target_hash}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Hash type: {hash_type}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Wordlist: {wordlist_file}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Threads: {num_threads}{Style.RESET_ALL}")
    
    try:
        # Count lines in wordlist for progress bar
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            total_words = sum(1 for _ in f)
        
        print(f"{Fore.BLUE}[*] Loaded wordlist with {total_words} entries{Style.RESET_ALL}")
        
        # Process wordlist in chunks for threading
        def process_chunk(word_chunk):
            for word in word_chunk:
                word = word.strip()
                if not word:
                    continue
                    
                hashed = hash_password(word, hash_type)
                if hashed == target_hash:
                    return word
            return None
        
        # Read wordlist and split into chunks
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            wordlist = [line.strip() for line in f if line.strip()]
        
        chunk_size = max(1, len(wordlist) // num_threads)
        chunks = [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            results = list(tqdm(
                executor.map(process_chunk, chunks),
                total=len(chunks),
                desc="Progress",
                unit="chunk"
            ))
        
        # Check results
        for result in results:
            if result:
                end_time = time.time()
                duration = end_time - start_time
                print(f"\n{Fore.GREEN}[+] Password found: {result}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Time taken: {duration:.2f} seconds{Style.RESET_ALL}")
                return result
        
        end_time = time.time()
        duration = end_time - start_time
        print(f"\n{Fore.RED}[-] Password not found in wordlist{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Time taken: {duration:.2f} seconds{Style.RESET_ALL}")
        return None
        
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Wordlist file not found: {wordlist_file}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error during dictionary attack: {e}{Style.RESET_ALL}")
        sys.exit(1)

def brute_force_attack(target_hash, hash_type, charset, min_length, max_length, num_threads=4):
    """Perform a brute force attack on the target hash"""
    print(f"{Fore.BLUE}[*] Starting brute force attack...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Target hash: {target_hash}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Hash type: {hash_type}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Character set: {charset}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Length range: {min_length}-{max_length}{Style.RESET_ALL}")
    
    # Define character sets
    charsets = {
        'lowercase': string.ascii_lowercase,
        'uppercase': string.ascii_uppercase,
        'digits': string.digits,
        'special': string.punctuation,
        'all': string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    }
    
    # Get the actual character set to use
    if charset in charsets:
        chars = charsets[charset]
    else:
        chars = charset
    
    print(f"{Fore.BLUE}[*] Using character set: {chars}{Style.RESET_ALL}")
    
    # Function to check a range of combinations
    def check_combinations(length, start_idx, end_idx):
        combinations = itertools.product(chars, repeat=length)
        # Skip to start_idx
        for _ in range(start_idx):
            next(combinations, None)
        
        # Check combinations from start_idx to end_idx
        count = 0
        for combo in combinations:
            if count >= (end_idx - start_idx):
                break
                
            password = ''.join(combo)
            hashed = hash_password(password, hash_type)
            
            if hashed == target_hash:
                return password
                
            count += 1
        
        return None
    
    start_time = time.time()
    
    # Try each length
    for length in range(min_length, max_length + 1):
        print(f"{Fore.BLUE}[*] Trying length: {length}{Style.RESET_ALL}")
        
        # Calculate total combinations for this length
        total_combinations = len(chars) ** length
        
        # If total combinations is small, don't use threading
        if total_combinations < 1000:
            for combo in itertools.product(chars, repeat=length):
                password = ''.join(combo)
                hashed = hash_password(password, hash_type)
                
                if hashed == target_hash:
                    end_time = time.time()
                    duration = end_time - start_time
                    print(f"\n{Fore.GREEN}[+] Password found: {password}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Time taken: {duration:.2f} seconds{Style.RESET_ALL}")
                    return password
        else:
            # Split work among threads
            chunk_size = total_combinations // num_threads
            chunks = [(i * chunk_size, min((i + 1) * chunk_size, total_combinations)) for i in range(num_threads)]
            
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(check_combinations, length, start, end) for start, end in chunks]
                
                # Use tqdm for a progress bar
                for future in tqdm(futures, total=len(futures), desc=f"Length {length}", unit="chunk"):
                    result = future.result()
                    if result:
                        end_time = time.time()
                        duration = end_time - start_time
                        print(f"\n{Fore.GREEN}[+] Password found: {result}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Time taken: {duration:.2f} seconds{Style.RESET_ALL}")
                        return result
    
    end_time = time.time()
    duration = end_time - start_time
    print(f"\n{Fore.RED}[-] Password not found with brute force attack{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Time taken: {duration:.2f} seconds{Style.RESET_ALL}")
    return None

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Python Hash Cracker')
    parser.add_argument('hash', help='The hash to crack')
    parser.add_argument('-t', '--type', choices=['md5', 'sha1', 'sha256', 'sha512'], default='md5',
                        help='Hash type (default: md5)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file for dictionary attack')
    parser.add_argument('-b', '--brute-force', action='store_true', help='Use brute force attack')
    parser.add_argument('-c', '--charset', default='lowercase',
                        choices=['lowercase', 'uppercase', 'digits', 'special', 'all'],
                        help='Character set for brute force attack (default: lowercase)')
    parser.add_argument('-m', '--min-length', type=int, default=1,
                        help='Minimum password length for brute force (default: 1)')
    parser.add_argument('-M', '--max-length', type=int, default=8,
                        help='Maximum password length for brute force (default: 8)')
    parser.add_argument('-j', '--threads', type=int, default=4,
                        help='Number of threads to use (default: 4)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Validate hash format based on type
    expected_length = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
        'sha512': 128
    }
    
    if len(args.hash) != expected_length[args.type]:
        print(f"{Fore.RED}[!] Warning: Hash length ({len(args.hash)}) doesn't match expected length for {args.type} ({expected_length[args.type]}){Style.RESET_ALL}")
        response = input(f"{Fore.YELLOW}[?] Continue anyway? (y/n): {Style.RESET_ALL}")
        if response.lower() != 'y':
            sys.exit(0)
    
    # Perform attack based on arguments
    if args.wordlist:
        result = dictionary_attack(args.hash, args.wordlist, args.type, args.threads)
    elif args.brute_force:
        result = brute_force_attack(args.hash, args.type, args.charset, args.min_length, args.max_length, args.threads)
    else:
        print(f"{Fore.RED}[!] Error: Must specify either --wordlist or --brute-force{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)
    
    # Final result
    if result:
        print(f"\n{Fore.GREEN}[+] Cracking successful!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Hash: {args.hash}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Type: {args.type}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Password: {result}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}[-] Cracking failed. Password not found.{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Hash cracking interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
