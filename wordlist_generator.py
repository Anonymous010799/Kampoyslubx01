#!/usr/bin/env python3
"""
Wordlist Generator - A tool to generate custom wordlists for password attacks
Author: Codegen
"""

import argparse
import itertools
import string
import sys
import random
from datetime import datetime

def generate_combinations(charset, min_length, max_length, output_file, limit=None):
    """Generate all possible combinations of characters"""
    count = 0
    
    with open(output_file, 'w') as f:
        for length in range(min_length, max_length + 1):
            print(f"Generating passwords of length {length}...")
            for combo in itertools.product(charset, repeat=length):
                password = ''.join(combo)
                f.write(f"{password}\n")
                count += 1
                
                if count % 100000 == 0:
                    print(f"Generated {count} passwords so far...")
                
                if limit and count >= limit:
                    print(f"Reached limit of {limit} passwords")
                    return count
    
    return count

def generate_mutations(base_words, output_file):
    """Generate common mutations of base words"""
    count = 0
    mutations = []
    
    # Common substitutions
    substitutions = {
        'a': ['@', '4'],
        'b': ['8'],
        'e': ['3'],
        'i': ['1', '!'],
        'l': ['1'],
        'o': ['0'],
        's': ['$', '5'],
        't': ['7'],
    }
    
    # Common additions
    common_suffixes = ['123', '1234', '12345', '2020', '2021', '2022', '2023', '2024', '!', '@', '#', '$', '%']
    
    with open(output_file, 'w') as f:
        for word in base_words:
            # Original word
            f.write(f"{word}\n")
            mutations.append(word)
            count += 1
            
            # Capitalized
            capitalized = word.capitalize()
            if capitalized not in mutations:
                f.write(f"{capitalized}\n")
                mutations.append(capitalized)
                count += 1
            
            # Uppercase
            uppercase = word.upper()
            if uppercase not in mutations:
                f.write(f"{uppercase}\n")
                mutations.append(uppercase)
                count += 1
            
            # Common suffixes
            for suffix in common_suffixes:
                mutation = word + suffix
                if mutation not in mutations:
                    f.write(f"{mutation}\n")
                    mutations.append(mutation)
                    count += 1
                
                # Capitalized with suffix
                cap_mutation = word.capitalize() + suffix
                if cap_mutation not in mutations:
                    f.write(f"{cap_mutation}\n")
                    mutations.append(cap_mutation)
                    count += 1
            
            # Character substitutions
            for i, char in enumerate(word):
                if char.lower() in substitutions:
                    for sub in substitutions[char.lower()]:
                        mutation = word[:i] + sub + word[i+1:]
                        if mutation not in mutations:
                            f.write(f"{mutation}\n")
                            mutations.append(mutation)
                            count += 1
    
    return count

def generate_from_personal_info(info, output_file):
    """Generate passwords based on personal information"""
    if not info:
        return 0
    
    base_words = []
    for item in info:
        # Add the item itself
        base_words.append(item)
        
        # Add without spaces
        if ' ' in item:
            base_words.append(item.replace(' ', ''))
        
        # Add initials if it's a name
        if ' ' in item:
            parts = item.split()
            initials = ''.join(part[0] for part in parts)
            base_words.append(initials)
    
    return generate_mutations(base_words, output_file)

def generate_from_keywords(keywords, output_file):
    """Generate passwords based on keywords"""
    if not keywords:
        return 0
    
    return generate_mutations(keywords, output_file)

def generate_dates(start_year, end_year, output_file):
    """Generate common date formats as passwords"""
    count = 0
    dates = []
    
    with open(output_file, 'w') as f:
        # Generate years
        for year in range(start_year, end_year + 1):
            dates.append(str(year))
            
            # Generate month-year combinations
            for month in range(1, 13):
                # MMYYYY
                dates.append(f"{month:02d}{year}")
                
                # MM-YYYY
                dates.append(f"{month:02d}-{year}")
                
                # YYYY-MM
                dates.append(f"{year}-{month:02d}")
                
                # Generate day-month-year combinations
                for day in range(1, 29):  # Using 28 as a safe maximum
                    # DDMMYYYY
                    dates.append(f"{day:02d}{month:02d}{year}")
                    
                    # DD-MM-YYYY
                    dates.append(f"{day:02d}-{month:02d}-{year}")
                    
                    # YYYY-MM-DD
                    dates.append(f"{year}-{month:02d}-{day:02d}")
        
        # Write unique dates to file
        unique_dates = list(set(dates))
        for date in unique_dates:
            f.write(f"{date}\n")
            count += 1
    
    return count

def generate_random(length, count, charset, output_file):
    """Generate random passwords"""
    passwords = set()
    
    with open(output_file, 'w') as f:
        while len(passwords) < count:
            password = ''.join(random.choice(charset) for _ in range(length))
            if password not in passwords:
                passwords.add(password)
                f.write(f"{password}\n")
    
    return len(passwords)

def main():
    parser = argparse.ArgumentParser(description="Wordlist Generator for Password Attacks")
    
    # Main arguments
    parser.add_argument("-o", "--output", required=True, help="Output wordlist file")
    parser.add_argument("-m", "--mode", choices=["combinations", "mutations", "personal", "dates", "random"],
                        required=True, help="Generation mode")
    
    # Combinations mode arguments
    parser.add_argument("--min-length", type=int, default=4, help="Minimum password length (default: 4)")
    parser.add_argument("--max-length", type=int, default=8, help="Maximum password length (default: 8)")
    parser.add_argument("--charset", default=None, help="Character set (default: lowercase + digits)")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of passwords to generate")
    
    # Mutations mode arguments
    parser.add_argument("--keywords", nargs='+', help="Keywords to mutate")
    parser.add_argument("--keywords-file", help="File containing keywords to mutate (one per line)")
    
    # Personal info mode arguments
    parser.add_argument("--personal-info", nargs='+', help="Personal information (names, birthdays, etc.)")
    
    # Dates mode arguments
    parser.add_argument("--start-year", type=int, default=1970, help="Start year for date generation (default: 1970)")
    parser.add_argument("--end-year", type=int, default=datetime.now().year, 
                        help=f"End year for date generation (default: current year)")
    
    # Random mode arguments
    parser.add_argument("--random-length", type=int, default=8, help="Length of random passwords (default: 8)")
    parser.add_argument("--random-count", type=int, default=1000, help="Number of random passwords (default: 1000)")
    
    args = parser.parse_args()
    
    # Set default charset if not provided
    if not args.charset:
        if args.mode == "combinations":
            args.charset = string.ascii_lowercase + string.digits
        elif args.mode == "random":
            args.charset = string.ascii_letters + string.digits + string.punctuation
    
    # Process based on mode
    if args.mode == "combinations":
        print(f"Generating all combinations with charset: {args.charset}")
        print(f"Length range: {args.min_length} to {args.max_length}")
        count = generate_combinations(args.charset, args.min_length, args.max_length, args.output, args.limit)
        print(f"Generated {count} passwords")
    
    elif args.mode == "mutations":
        keywords = []
        
        if args.keywords:
            keywords.extend(args.keywords)
        
        if args.keywords_file:
            try:
                with open(args.keywords_file, 'r') as f:
                    file_keywords = [line.strip() for line in f if line.strip()]
                    keywords.extend(file_keywords)
            except Exception as e:
                print(f"Error reading keywords file: {str(e)}")
                return
        
        if not keywords:
            print("Error: No keywords provided. Use --keywords or --keywords-file")
            return
        
        print(f"Generating mutations for {len(keywords)} keywords")
        count = generate_mutations(keywords, args.output)
        print(f"Generated {count} password mutations")
    
    elif args.mode == "personal":
        if not args.personal_info:
            print("Error: No personal information provided. Use --personal-info")
            return
        
        print(f"Generating passwords from personal information")
        count = generate_from_personal_info(args.personal_info, args.output)
        print(f"Generated {count} passwords from personal information")
    
    elif args.mode == "dates":
        print(f"Generating date-based passwords from {args.start_year} to {args.end_year}")
        count = generate_dates(args.start_year, args.end_year, args.output)
        print(f"Generated {count} date-based passwords")
    
    elif args.mode == "random":
        print(f"Generating {args.random_count} random passwords of length {args.random_length}")
        count = generate_random(args.random_length, args.random_count, args.charset, args.output)
        print(f"Generated {count} random passwords")


if __name__ == "__main__":
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║   Wordlist Generator                          ║
    ║   A tool to generate custom wordlists         ║
    ║                                               ║
    ║   Use responsibly and only on systems you     ║
    ║   have permission to test!                    ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)
    main()

