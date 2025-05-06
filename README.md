# Password Attack Toolkit

A collection of tools for password attacks and security testing. This toolkit includes:

1. **Password Attacker** - A tool for dictionary and brute force attacks against various services
2. **Wordlist Generator** - A tool to create custom wordlists for password attacks
3. **Hash Cracker** - A tool to crack password hashes using dictionary attacks

## ⚠️ DISCLAIMER ⚠️

These tools are provided for educational purposes and legitimate security testing ONLY. Unauthorized use of these tools against systems you do not own or have explicit permission to test is illegal and unethical.

## Installation

1. Clone this repository:
```
git clone https://github.com/Anonymous010799/Kampoyslubx01.git
cd Kampoyslubx01
```

2. Install required dependencies:
```
pip install requests paramiko
```

## Tools Usage

### 1. Password Attacker

This tool attempts to find valid credentials by trying multiple passwords against a target service.

**Features:**
- Dictionary attacks using wordlists
- Brute force attacks with customizable character sets
- Support for SSH, FTP, and HTTP/HTTPS services
- Multi-threaded for faster attacks

**Usage Examples:**

Dictionary attack against SSH:
```
python password_attack.py -t 192.168.1.100 -u admin -s ssh -m dictionary -w wordlist.txt
```

Brute force attack against FTP:
```
python password_attack.py -t 192.168.1.100 -u admin -s ftp -m brute --min-length 4 --max-length 6
```

### 2. Wordlist Generator

This tool generates custom wordlists for password attacks.

**Features:**
- Generate all possible combinations of characters
- Create mutations of keywords (capitalization, number suffixes, character substitutions)
- Generate passwords based on personal information
- Create date-based passwords
- Generate random passwords

**Usage Examples:**

Generate all combinations:
```
python wordlist_generator.py -m combinations -o wordlist.txt --min-length 3 --max-length 5
```

Generate mutations from keywords:
```
python wordlist_generator.py -m mutations -o wordlist.txt --keywords password admin user
```

Generate date-based passwords:
```
python wordlist_generator.py -m dates -o dates.txt --start-year 2000 --end-year 2023
```

### 3. Hash Cracker

This tool attempts to crack password hashes using dictionary attacks.

**Features:**
- Support for MD5, SHA1, SHA256, and SHA512 hashes
- Crack single hashes or multiple hashes from a file
- Generate hash tables for faster cracking
- Multi-threaded for faster performance

**Usage Examples:**

Crack a single MD5 hash:
```
python hash_cracker.py -m crack -t md5 -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
```

Crack multiple SHA1 hashes from a file:
```
python hash_cracker.py -m crack -t sha1 -f hashes.txt -w wordlist.txt
```

Generate a hash table:
```
python hash_cracker.py -m generate -t md5 -w wordlist.txt -o hash_table.txt
```

## Best Practices for Security Testing

1. **Always get permission** before testing any system
2. **Document your scope** and stick to it
3. **Use controlled environments** when possible
4. **Report vulnerabilities responsibly**
5. **Never use these tools for malicious purposes**

## License

This project is for educational purposes only. Use at your own risk.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

