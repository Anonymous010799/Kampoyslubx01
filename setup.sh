#!/bin/bash

# Make the Python scripts executable
chmod +x password_attack.py
chmod +x wordlist_generator.py
chmod +x hash_cracker.py

# Install required dependencies
echo "Installing required dependencies..."
pip install requests paramiko

echo "Setup complete! The password attack tools are now ready to use."
echo ""
echo "Usage examples:"
echo "  ./password_attack.py -t 192.168.1.100 -u admin -s ssh -m dictionary -w wordlist.txt"
echo "  ./wordlist_generator.py -m combinations -o wordlist.txt --min-length 3 --max-length 5"
echo "  ./hash_cracker.py -m crack -t md5 -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt"
echo ""
echo "Remember to use these tools responsibly and only on systems you have permission to test!"

