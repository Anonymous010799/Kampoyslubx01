#!/usr/bin/env python3
"""
Hash Cracker - A tool to crack password hashes
Author: Codegen
"""

import argparse
import hashlib
import sys
import time
from concurrent.futures import ThreadPoolExecutor

def calculate_hash(password, hash_type):
    """Calculate hash for a password using specified algorithm"""
    password_bytes = password.encode('utf-8')
    
    if hash_type == "md5":
        return hashlib.md5(password_bytes).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password_bytes).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password_bytes).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(password_bytes).hexdigest()
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")

def crack_single_hash(target_hash, wordlist_file, hash_type, max_threads=10):
    """Crack a single hash using a wordlist"""
    print(f"[+] Starting to crack {hash_type.upper()} hash: {target_hash}")
    print(f"[+] Using wordlist: {wordlist_file}")
    
    try:
        with open(wordlist_file, 'r', encoding='latin-1') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading wordlist: {str(e)}")
        return None
    
    print(f"[+] Loaded {len(passwords)} passwords from wordlist")
    
    start_time = time.time()
    found = False
    result = None
    attempts = 0
    
    def check_password(password):
        nonlocal found
        if found:
            return None
        
        hashed = calculate_hash(password, hash_type)
        if hashed == target_hash.lower():
            return password
        return None
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        
        for password in passwords:
            if found:
                break
            
            future = executor.submit(check_password, password)
            futures.append(future)
            attempts += 1
        
        for future in futures:
            password_match = future.result()
            if password_match:
                found = True
                result = password_match
                break
    
    elapsed_time = time.time() - start_time
    
    if result:
        print(f"\n[+] Hash cracked in {elapsed_time:.2f} seconds!")
        print(f"[+] Password: {result}")
    else:
        print(f"\n[!] Hash not cracked after trying {attempts} passwords ({elapsed_time:.2f} seconds)")
    
    return result

def crack_hash_file(hash_file, wordlist_file, hash_type, max_threads=10):
    """Crack multiple hashes from a file"""
    try:
        with open(hash_file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading hash file: {str(e)}")
        return {}
    
    print(f"[+] Loaded {len(hashes)} hashes from {hash_file}")
    
    results = {}
    for i, target_hash in enumerate(hashes):
        print(f"\n[+] Cracking hash {i+1}/{len(hashes)}: {target_hash}")
        password = crack_single_hash(target_hash, wordlist_file, hash_type, max_threads)
        if password:
            results[target_hash] = password
    
    return results

def generate_hash_table(wordlist_file, hash_type, output_file):
    """Generate a hash table from a wordlist"""
    try:
        with open(wordlist_file, 'r', encoding='latin-1') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading wordlist: {str(e)}")
        return False
    
    print(f"[+] Generating {hash_type.upper()} hashes for {len(passwords)} passwords")
    
    try:
        with open(output_file, 'w') as f:
            for password in passwords:
                hashed = calculate_hash(password, hash_type)
                f.write(f"{hashed}:{password}\n")
    except Exception as e:
        print(f"[!] Error writing to output file: {str(e)}")
        return False
    
    print(f"[+] Hash table written to {output_file}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Hash Cracker Tool")
    
    # Main arguments
    parser.add_argument("-m", "--mode", choices=["crack", "generate"], required=True,
                        help="Mode: crack a hash or generate a hash table")
    parser.add_argument("-t", "--hash-type", choices=["md5", "sha1", "sha256", "sha512"],
                        default="md5", help="Hash algorithm (default: md5)")
    
    # Crack mode arguments
    parser.add_argument("-H", "--hash", help="Single hash to crack")
    parser.add_argument("-f", "--hash-file", help="File containing hashes to crack (one per line)")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for cracking")
    parser.add_argument("-T", "--threads", type=int, default=10,
                        help="Maximum number of threads (default: 10)")
    
    # Generate mode arguments
    parser.add_argument("-o", "--output", help="Output file for hash table generation")
    
    args = parser.parse_args()
    
    if args.mode == "crack":
        if not args.wordlist:
            parser.error("Crack mode requires a wordlist (-w/--wordlist)")
        
        if args.hash:
            crack_single_hash(args.hash, args.wordlist, args.hash_type, args.threads)
        elif args.hash_file:
            results = crack_hash_file(args.hash_file, args.wordlist, args.hash_type, args.threads)
            
            if results:
                print("\n[+] Cracking summary:")
                print(f"[+] Cracked {len(results)}/{len(open(args.hash_file).readlines())} hashes")
                
                for hash_val, password in results.items():
                    print(f"[+] {hash_val}: {password}")
        else:
            parser.error("Crack mode requires either a hash (-H/--hash) or a hash file (-f/--hash-file)")
    
    elif args.mode == "generate":
        if not args.wordlist:
            parser.error("Generate mode requires a wordlist (-w/--wordlist)")
        
        if not args.output:
            parser.error("Generate mode requires an output file (-o/--output)")
        
        generate_hash_table(args.wordlist, args.hash_type, args.output)


if __name__ == "__main__":
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║   Hash Cracker                                ║
    ║   A tool to crack password hashes             ║
    ║                                               ║
    ║   Use responsibly and only on systems you     ║
    ║   have permission to test!                    ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)
    main()

