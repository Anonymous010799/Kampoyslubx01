#!/usr/bin/env python3
"""
Wordlist Generator - A tool to generate custom wordlists for password cracking
"""

import argparse
import sys
import string
import itertools
import random
import re
from datetime import datetime
from tqdm import tqdm
from colorama import init, Fore, Style

# Initialize colorama
init()

def print_banner():
    """Print the tool banner"""
    banner = f"""
{Fore.BLUE}╔═══════════════════════════════════════════════╗
║ {Fore.GREEN}Python Wordlist Generator {Fore.YELLOW}v1.0{Fore.BLUE}            ║
║ {Fore.CYAN}A tool to generate custom wordlists{Fore.BLUE}           ║
╚═══════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def generate_combinations(charset, min_length, max_length, output_file, limit=None):
    """Generate all possible combinations of characters"""
    print(f"{Fore.BLUE}[*] Generating combinations with charset: {charset}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Length range: {min_length} to {max_length}{Style.RESET_ALL}")
    
    count = 0
    with open(output_file, 'w') as f:
        for length in range(min_length, max_length + 1):
            print(f"{Fore.BLUE}[*] Generating words of length {length}...{Style.RESET_ALL}")
            
            # Calculate total combinations for this length for progress bar
            total_combinations = len(charset) ** length
            if limit and total_combinations > limit:
                total_combinations = limit
            
            # Use tqdm for progress bar
            with tqdm(total=total_combinations, desc=f"Length {length}", unit="word") as pbar:
                for combo in itertools.product(charset, repeat=length):
                    word = ''.join(combo)
                    f.write(word + '\n')
                    count += 1
                    pbar.update(1)
                    
                    if limit and count >= limit:
                        print(f"{Fore.YELLOW}[!] Reached limit of {limit} words{Style.RESET_ALL}")
                        return count
    
    return count

def generate_from_pattern(pattern, output_file, limit=None):
    """Generate words based on a pattern"""
    print(f"{Fore.BLUE}[*] Generating words from pattern: {pattern}{Style.RESET_ALL}")
    
    # Define character sets for pattern
    charsets = {
        'a': string.ascii_lowercase,
        'A': string.ascii_uppercase,
        '0': string.digits,
        '!': string.punctuation,
        '?': string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    }
    
    # Calculate total combinations
    total_combinations = 1
    for char in pattern:
        if char in charsets:
            total_combinations *= len(charsets[char])
    
    if limit and total_combinations > limit:
        total_combinations = limit
    
    print(f"{Fore.BLUE}[*] Estimated combinations: {total_combinations}{Style.RESET_ALL}")
    
    count = 0
    with open(output_file, 'w') as f:
        # Create a list of character sets based on the pattern
        pattern_charsets = [charsets[char] if char in charsets else [char] for char in pattern]
        
        # Generate combinations
        with tqdm(total=total_combinations, desc="Progress", unit="word") as pbar:
            for combo in itertools.product(*pattern_charsets):
                word = ''.join(combo)
                f.write(word + '\n')
                count += 1
                pbar.update(1)
                
                if limit and count >= limit:
                    print(f"{Fore.YELLOW}[!] Reached limit of {limit} words{Style.RESET_ALL}")
                    break
    
    return count

def generate_from_keywords(keywords, mutations, output_file, limit=None):
    """Generate words based on keywords with mutations"""
    print(f"{Fore.BLUE}[*] Generating words from {len(keywords)} keywords with mutations{Style.RESET_ALL}")
    
    # Common mutations
    mutation_functions = [
        lambda s: s.lower(),                                # lowercase
        lambda s: s.upper(),                                # UPPERCASE
        lambda s: s.capitalize(),                           # Capitalize
        lambda s: s[::-1],                                  # reverse
        lambda s: s + s,                                    # repeat
        lambda s: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s)),  # AlTeRnAtInG
        lambda s: s + '123',                                # append 123
        lambda s: s + '!',                                  # append !
        lambda s: s + '@',                                  # append @
        lambda s: s + '#',                                  # append #
        lambda s: s + '1',                                  # append 1
        lambda s: s + '12',                                 # append 12
        lambda s: '123' + s,                                # prepend 123
        lambda s: '!' + s,                                  # prepend !
        lambda s: '@' + s,                                  # prepend @
        lambda s: s.replace('a', '@'),                      # a -> @
        lambda s: s.replace('e', '3'),                      # e -> 3
        lambda s: s.replace('i', '1'),                      # i -> 1
        lambda s: s.replace('o', '0'),                      # o -> 0
        lambda s: s.replace('s', '$'),                      # s -> $
        lambda s: s.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$'),  # l33t
    ]
    
    # Year mutations
    current_year = datetime.now().year
    for year in range(current_year - 10, current_year + 1):
        mutation_functions.append(lambda s, y=year: s + str(y))
    
    # Select mutations based on the mutation level
    if mutations == 'basic':
        selected_mutations = mutation_functions[:5]
    elif mutations == 'medium':
        selected_mutations = mutation_functions[:10]
    else:  # advanced
        selected_mutations = mutation_functions
    
    # Calculate total words
    total_words = len(keywords) * (len(selected_mutations) + 1)  # +1 for original keywords
    if limit and total_words > limit:
        total_words = limit
    
    print(f"{Fore.BLUE}[*] Using {len(selected_mutations)} mutation functions{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Estimated words: {total_words}{Style.RESET_ALL}")
    
    count = 0
    with open(output_file, 'w') as f:
        # First write the original keywords
        for keyword in keywords:
            f.write(keyword + '\n')
            count += 1
            
            if limit and count >= limit:
                break
        
        # Then apply mutations
        with tqdm(total=total_words, initial=count, desc="Progress", unit="word") as pbar:
            for keyword in keywords:
                for mutation_func in selected_mutations:
                    try:
                        mutated = mutation_func(keyword)
                        if mutated != keyword:  # Avoid duplicates
                            f.write(mutated + '\n')
                            count += 1
                            pbar.update(1)
                            
                            if limit and count >= limit:
                                print(f"{Fore.YELLOW}[!] Reached limit of {limit} words{Style.RESET_ALL}")
                                return count
                    except:
                        # Skip mutations that fail
                        continue
    
    return count

def generate_from_rules(input_file, rules, output_file, limit=None):
    """Generate words by applying rules to an existing wordlist"""
    print(f"{Fore.BLUE}[*] Applying rules to wordlist: {input_file}{Style.RESET_ALL}")
    
    # Load input wordlist
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Input file not found: {input_file}{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.BLUE}[*] Loaded {len(words)} words from input file{Style.RESET_ALL}")
    
    # Parse rules
    rule_functions = []
    for rule in rules:
        if rule == 'capitalize':
            rule_functions.append(lambda s: s.capitalize())
        elif rule == 'uppercase':
            rule_functions.append(lambda s: s.upper())
        elif rule == 'lowercase':
            rule_functions.append(lambda s: s.lower())
        elif rule == 'reverse':
            rule_functions.append(lambda s: s[::-1])
        elif rule.startswith('append:'):
            suffix = rule.split(':', 1)[1]
            rule_functions.append(lambda s, suffix=suffix: s + suffix)
        elif rule.startswith('prepend:'):
            prefix = rule.split(':', 1)[1]
            rule_functions.append(lambda s, prefix=prefix: prefix + s)
        elif rule == 'leetspeak':
            rule_functions.append(lambda s: s.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$'))
        elif rule == 'duplicate':
            rule_functions.append(lambda s: s + s)
        elif rule.startswith('replace:'):
            old, new = rule.split(':', 1)[1].split(',')
            rule_functions.append(lambda s, old=old, new=new: s.replace(old, new))
    
    print(f"{Fore.BLUE}[*] Applying {len(rule_functions)} rules{Style.RESET_ALL}")
    
    # Calculate total words
    total_words = len(words) * (len(rule_functions) + 1)  # +1 for original words
    if limit and total_words > limit:
        total_words = limit
    
    count = 0
    with open(output_file, 'w') as f:
        # First write the original words
        for word in words:
            f.write(word + '\n')
            count += 1
            
            if limit and count >= limit:
                break
        
        # Then apply rules
        with tqdm(total=total_words, initial=count, desc="Progress", unit="word") as pbar:
            for word in words:
                for rule_func in rule_functions:
                    try:
                        transformed = rule_func(word)
                        if transformed != word:  # Avoid duplicates
                            f.write(transformed + '\n')
                            count += 1
                            pbar.update(1)
                            
                            if limit and count >= limit:
                                print(f"{Fore.YELLOW}[!] Reached limit of {limit} words{Style.RESET_ALL}")
                                return count
                    except:
                        # Skip rules that fail
                        continue
    
    return count

def generate_random(charset, min_length, max_length, output_file, count):
    """Generate random words"""
    print(f"{Fore.BLUE}[*] Generating {count} random words{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Character set: {charset}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Length range: {min_length} to {max_length}{Style.RESET_ALL}")
    
    with open(output_file, 'w') as f:
        for _ in tqdm(range(count), desc="Progress", unit="word"):
            # Choose a random length
            length = random.randint(min_length, max_length)
            
            # Generate a random word
            word = ''.join(random.choice(charset) for _ in range(length))
            
            f.write(word + '\n')
    
    return count

def extract_from_text(input_file, output_file, min_length=3, regex=None):
    """Extract words from a text file"""
    print(f"{Fore.BLUE}[*] Extracting words from: {input_file}{Style.RESET_ALL}")
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Input file not found: {input_file}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Extract words
    if regex:
        try:
            pattern = re.compile(regex)
            words = set(pattern.findall(text))
        except re.error as e:
            print(f"{Fore.RED}[!] Error in regex pattern: {e}{Style.RESET_ALL}")
            sys.exit(1)
    else:
        # Default: extract words with letters, numbers, and some special chars
        pattern = re.compile(r'[a-zA-Z0-9_\-\.]{' + str(min_length) + r',}')
        words = set(pattern.findall(text))
    
    print(f"{Fore.BLUE}[*] Extracted {len(words)} unique words{Style.RESET_ALL}")
    
    # Write to output file
    with open(output_file, 'w') as f:
        for word in sorted(words):
            f.write(word + '\n')
    
    return len(words)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Python Wordlist Generator')
    
    # Main arguments
    parser.add_argument('-o', '--output', required=True, help='Output file path')
    parser.add_argument('-l', '--limit', type=int, help='Limit the number of words generated')
    
    # Create subparsers for different generation methods
    subparsers = parser.add_subparsers(dest='method', help='Generation method')
    
    # Combinations method
    combo_parser = subparsers.add_parser('combinations', help='Generate all possible combinations')
    combo_parser.add_argument('-c', '--charset', default='abcdefghijklmnopqrstuvwxyz', help='Character set to use')
    combo_parser.add_argument('-m', '--min-length', type=int, default=1, help='Minimum word length')
    combo_parser.add_argument('-M', '--max-length', type=int, default=3, help='Maximum word length')
    
    # Pattern method
    pattern_parser = subparsers.add_parser('pattern', help='Generate words based on a pattern')
    pattern_parser.add_argument('-p', '--pattern', required=True, help='Pattern to use (a=lowercase, A=uppercase, 0=digit, !=special, ?=all)')
    
    # Keywords method
    keywords_parser = subparsers.add_parser('keywords', help='Generate words based on keywords with mutations')
    keywords_parser.add_argument('-k', '--keywords', required=True, help='Comma-separated list of keywords')
    keywords_parser.add_argument('-m', '--mutations', choices=['basic', 'medium', 'advanced'], default='medium', help='Mutation level')
    
    # Rules method
    rules_parser = subparsers.add_parser('rules', help='Apply rules to an existing wordlist')
    rules_parser.add_argument('-i', '--input', required=True, help='Input wordlist file')
    rules_parser.add_argument('-r', '--rules', required=True, nargs='+', help='Rules to apply (e.g., capitalize, uppercase, lowercase, reverse, append:123, prepend:!, leetspeak, duplicate, replace:a,@)')
    
    # Random method
    random_parser = subparsers.add_parser('random', help='Generate random words')
    random_parser.add_argument('-c', '--charset', default='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', help='Character set to use')
    random_parser.add_argument('-m', '--min-length', type=int, default=6, help='Minimum word length')
    random_parser.add_argument('-M', '--max-length', type=int, default=12, help='Maximum word length')
    random_parser.add_argument('-n', '--count', type=int, default=1000, help='Number of words to generate')
    
    # Extract method
    extract_parser = subparsers.add_parser('extract', help='Extract words from a text file')
    extract_parser.add_argument('-i', '--input', required=True, help='Input text file')
    extract_parser.add_argument('-m', '--min-length', type=int, default=3, help='Minimum word length')
    extract_parser.add_argument('-r', '--regex', help='Regular expression pattern to extract words')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check if a method was specified
    if not args.method:
        parser.print_help()
        sys.exit(1)
    
    start_time = datetime.now()
    
    # Generate wordlist based on the selected method
    if args.method == 'combinations':
        count = generate_combinations(args.charset, args.min_length, args.max_length, args.output, args.limit)
    elif args.method == 'pattern':
        count = generate_from_pattern(args.pattern, args.output, args.limit)
    elif args.method == 'keywords':
        keywords = [k.strip() for k in args.keywords.split(',')]
        count = generate_from_keywords(keywords, args.mutations, args.output, args.limit)
    elif args.method == 'rules':
        count = generate_from_rules(args.input, args.rules, args.output, args.limit)
    elif args.method == 'random':
        count = generate_random(args.charset, args.min_length, args.max_length, args.output, args.count)
    elif args.method == 'extract':
        count = extract_from_text(args.input, args.output, args.min_length, args.regex)
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\n{Fore.GREEN}[+] Wordlist generation completed!{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Generated {count} words{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Output file: {args.output}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Time taken: {duration:.2f} seconds{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Wordlist generation interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
