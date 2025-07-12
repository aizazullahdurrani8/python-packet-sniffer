# HTTP Packet Sniffer using Scapy

A Python-based HTTP packet sniffer that captures and analyzes HTTP traffic from a specified network interface. It displays visited URLs and detects potential login credentials by scanning for common patterns in the HTTP payload.

## ⚙️ Features

- Captures HTTP requests in real time
- Displays full requested URLs
- Detects possible login credentials in HTTP data
- Highlights sensitive information using `colorama`

## 🛠️ Requirements

- Python 3
- Must be run with root privileges
- Install dependencies with:

```bash
pip install scapy colorama
```

## 🚀 Usage

Run the script with sudo and specify your network interface:

    sudo python3 sniffer.py -i <interface>

Example:

    sudo python3 sniffer.py -i wlan0

## 📌 Example Output

```
[+] Sniffing started on interface wlan0
[+] HTTP Request ---> www.example.com/login
[+] Possible Login Credentials ---> username=admin&password=12345
```
