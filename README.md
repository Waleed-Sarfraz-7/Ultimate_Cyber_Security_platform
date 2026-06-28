# Ultimate Cybersecurity Platform

A collection of Python-based network and security tools with a unified desktop launcher. It includes a packet sniffer, network scanner, VPN traffic detector, file locker, image steganography tool, and a secure messaging client — each demonstrating a distinct domain of cybersecurity and networking.

## Overview

The repository is organized around a simple desktop launcher in `Main.py`, which lets you open all tools from a single menu.

## Features

- Main launcher GUI to run different scripts
- Packet sniffer with protocol filtering for TCP, UDP, and ICMP
- Network scanner using ARP and ping-based detection
- VPN traffic detector for suspicious VPN-related traffic
- File and folder locker with password-based encryption
- Image steganography tool to hide and reveal text inside images
- Secure message/file sender over TCP
- Browser extension folder for basic extension-based experimentation

## Project Structure

- `Main.py` — launcher interface for selecting the available scripts
- `FiltersProtocol.py` — packet sniffer with GUI and protocol filtering
- `network_scanner.py` — network device scanner using ARP and ICMP
- `vpn.py` — VPN traffic detection tool
- `FileLocker.py` — file/folder encryption and decryption utility
- `imageencoding.py` — hide/reveal text inside image files
- `SendMessageToSelectedIP.py` — encrypted client for sending messages/files
- `extension/` — basic browser extension files
- `packet_data.csv` — sample output from packet capture
- `packet_log.txt` — sample logging output

## Requirements

Make sure you have Python 3.8+ installed.

Install the required packages:

```bash
pip install scapy psutil cryptography pillow
```

## How to Run

### 1. Start the launcher

```bash
python Main.py
```

This opens a window where you can choose which script to run.

### 2. Run individual tools directly

```bash
python FiltersProtocol.py
python network_scanner.py
python vpn.py
python FileLocker.py
python imageencoding.py
python SendMessageToSelectedIP.py
```

## Usage Notes

- Packet sniffing tools may require administrator/root privileges depending on your operating system.
- On Windows, having Npcap or WinPcap installed can improve packet capture support.
- The secure messaging client uses a pre-defined encryption key and is intended for learning purposes rather than production use.

## Notes for Packet Sniffing

The packet sniffer uses Scapy to capture and inspect network traffic. It can filter traffic by protocol and save captured data into `packet_data.csv`.

## Notes for File Locker

The file locker encrypts files and folders using Fernet and saves them as `.locked` files. To unlock, select the `.locked` file and provide the correct password.

## Notes for Steganography Tool

The image steganography script hides text inside the least significant bits of image pixels. It is a simple demonstration and should not be treated as a secure hiding method.

## Disclaimer

This project is intended for educational purposes, networking labs, and security demonstrations. Use responsibly and only on networks or systems you own or are authorized to test.

---

## Author

**Waleed Sarfraz** — CS, UET Lahore
