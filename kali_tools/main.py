#!/usr/bin/env python3
"""
Main script for Kali Linux Tools in Python
"""

import os
import sys
import argparse
from colorama import init, Fore, Style

# Initialize colorama
init()

def print_banner():
    """Print the main banner"""
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════════════╗
║ {Fore.GREEN}Kali Linux Tools in Python {Fore.YELLOW}v1.0{Fore.RED}                                ║
║ {Fore.BLUE}A collection of security tools written in Python{Fore.RED}                ║
╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def list_tools():
    """List all available tools"""
    tools = {
        "Network Tools": [
            {"name": "port_scanner", "description": "Scan for open ports on a target host"},
            {"name": "packet_sniffer", "description": "Capture and analyze network packets"}
        ],
        "Password Tools": [
            {"name": "hash_cracker", "description": "Crack password hashes using dictionary or brute force attacks"}
        ],
        "Web Tools": [
            {"name": "web_scanner", "description": "Scan websites for common vulnerabilities"}
        ],
        "Utility Tools": [
            {"name": "wordlist_generator", "description": "Generate custom wordlists for password cracking"}
        ]
    }
    
    print(f"\n{Fore.YELLOW}Available Tools:{Style.RESET_ALL}\n")
    
    for category, category_tools in tools.items():
        print(f"{Fore.CYAN}[{category}]{Style.RESET_ALL}")
        for tool in category_tools:
            print(f"  {Fore.GREEN}{tool['name']}{Style.RESET_ALL} - {tool['description']}")
        print()
    
    print(f"{Fore.YELLOW}Usage:{Style.RESET_ALL}")
    print(f"  python main.py <tool_name> [arguments]")
    print(f"  python main.py <tool_name> --help (for tool-specific help)")
    print()

def run_tool(tool_name, args):
    """Run the specified tool with arguments"""
    # Define the mapping of tool names to their modules
    tool_modules = {
        "port_scanner": "network_tools.port_scanner",
        "packet_sniffer": "network_tools.packet_sniffer",
        "hash_cracker": "password_tools.hash_cracker",
        "web_scanner": "web_tools.web_scanner",
        "wordlist_generator": "utility_tools.wordlist_generator"
    }
    
    if tool_name not in tool_modules:
        print(f"{Fore.RED}[!] Error: Unknown tool '{tool_name}'{Style.RESET_ALL}")
        list_tools()
        return 1
    
    # Import the tool module
    try:
        module_name = tool_modules[tool_name]
        module_path = f"kali_tools.{module_name}"
        
        # Add the parent directory to sys.path to allow importing the module
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        
        # Import the module
        module = __import__(module_path, fromlist=["main"])
        
        # Run the tool's main function
        sys.argv = [f"python {module_name.replace('.', '/')}.py"] + args
        module.main()
        return 0
    except ImportError as e:
        print(f"{Fore.RED}[!] Error importing tool module: {e}{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"{Fore.RED}[!] Error running tool: {e}{Style.RESET_ALL}")
        return 1

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Kali Linux Tools in Python')
    parser.add_argument('tool', nargs='?', help='Tool to run')
    parser.add_argument('args', nargs=argparse.REMAINDER, help='Arguments to pass to the tool')
    
    args = parser.parse_args()
    
    print_banner()
    
    if not args.tool:
        list_tools()
        return 0
    
    return run_tool(args.tool, args.args)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Operation interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
