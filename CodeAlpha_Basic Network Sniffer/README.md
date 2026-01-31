# Simple Network Packet Sniffer

## Overview

A lightweight Python-based network packet sniffer built using `scapy`. This tool captures network traffic in real-time, displays source/destination IPs, protocols, and provides smart **payload previews** (text snippets for readable data, size summaries for binary data). It also supports saving captured traffic to `.pcap` files for analysis in tools like Wireshark.

> [!CAUTION]
> **Disclaimer**: This tool is for **educational purposes only**. analyzing network traffic without permission is illegal in many jurisdictions. Ensure you have authorization to sniff traffic on the network you are testing.

## Features

- **Real-time Sniffing**: View Source IP, Destination IP, and Protocol (TCP/UDP/ICMP).
- **Smart Payload Preview**:
  - Automatically decodes and previews readable text (e.g., HTTP requests).
  - Summarizes binary data blocks to avoid console clutter.
- **PCAP Logging**: Save captured packets to standard `.pcap` files.
- **Customizable**: Set packet count limits or filter by specific network interfaces.

## Requirements

- Python 3.x
- `scapy`

## Installation

1. Clone this repository.
2. Cd into cloned copy.
3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

    *OR*

    ```bash
    pip3 install -r requirements.txt
    ```

    *(Note: You may need to run as Administrator/Root to install scapy properly on some systems)*

## Usage

### Basic Capture

Capture packets indefinitely (Press `Ctrl+C` to stop):

```bash
python sniffer.py
```

### Save logging to PCAP

Capture 20 packets and save them to `capture.pcap`:

```bash
python sniffer.py -c 20 -o capture.pcap
```

### Select Interface

Sniff on a specific network interface (useful for Wi-Fi or multihomed machines):

```bash
python sniffer.py -i "WiFi 2"
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-c`, `--count` | Number of packets to capture (0 for infinite) | 0 |
| `-i`, `--interface` | Specific network interface to bind to | Scapy Default |
| `-o`, `--output` | Output `.pcap` filename to save packets | None |

## Troubleshooting

- **PermissionError**: Network sniffing requires low-level access.
  - **Windows**: Run your terminal (Command Prompt/PowerShell) as **Administrator**.
  - **Linux/macOS**: Run with `sudo python sniffer.py`.

- **"Raw" Payloads**: If you see `[Binary Data]`, the packet contains encrypted (HTTPS) or non-text data. This is normal behavior.

- **"No interface specified"**: If you see `No interface specified`, you need to specify an interface to sniff on. Use the `-i` flag to specify an interface. For example, `python sniffer.py -i "WiFi 2"`.

- **"Program can't start after using the python command"**: If program refuses to start after using the python command, e.g (`python sniffer.py -i "WiFi 2"`), try using `python3 sniffer.py -i "WiFi 2"` instead.
