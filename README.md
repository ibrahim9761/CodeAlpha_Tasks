<p align="center">
  <img src="logo.svg" width="120" height="120" alt="TrafficTap logo">
</p>

<h1 align="center">TrafficTap — Basic Network Sniffer</h1>

<p align="center">
  <em>Internship Task 1: capture and analyze live network traffic to understand protocol structure.</em>
</p>

<p align="center">
  <img alt="python" src="https://img.shields.io/badge/python-3.8%2B-blue">
  <img alt="platform" src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey">
  <img alt="license" src="https://img.shields.io/badge/use-educational-orange">
</p>

---

## Overview

TrafficTap captures live network packets and breaks down their structure in
real time: source/destination MAC & IP addresses, transport-layer protocol
(TCP/UDP/ICMP/ARP), ports, TCP flags, DNS queries/answers, and a safe preview
of the payload — plus a session summary with protocol breakdowns and top
talkers.

Two implementations are included so the project demonstrates understanding
at two levels:

| File | Approach | Platform | Notes |
|---|---|---|---|
| `sniffer_scapy.py` | Built on the `scapy` library | Windows / macOS / Linux | Recommended — cross-platform, feature-complete |
| `sniffer_socket.py` | Pure Python `socket` + `struct`, no third-party libraries | Linux only | Shows exactly how headers are parsed byte-by-byte |

## Features

- Live capture with optional BPF filters (`tcp port 80`, `udp port 53`, ...)
- Ethernet, IPv4, **IPv6**, TCP, UDP, ICMP, and ARP parsing
- TCP flag decoding (SYN, ACK, PSH, RST, FIN, URG)
- DNS query/answer extraction
- Safe, truncated payload preview (non-printable bytes shown as `.`)
- Colorized, icon-based terminal output (auto-disables gracefully if
  `colorama` isn't installed or the terminal doesn't support ANSI colors)
- Live session statistics: duration, packet/byte totals, packets/sec,
  protocol breakdown, top talkers
- Save captures to `.pcap` (viewable in Wireshark) and/or mirror output to
  a plain-text log file
- Robust error handling: permission errors, missing interfaces, malformed
  packets are all caught and reported instead of crashing

## Requirements

```bash
pip install scapy colorama
```

`sniffer_socket.py` needs no extra libraries — colorama is used only if
already installed, and the script still works fine without it.

You must run both scripts with **administrator/root privileges**, since raw
packet capture requires elevated permission:

- **Linux/macOS:** `sudo python3 sniffer_scapy.py`
- **Windows:** install [Npcap](https://npcap.com/) first, then run your
  terminal as Administrator.

## Usage

```bash
# Capture everything on the default interface (Ctrl+C to stop)
sudo python3 sniffer_scapy.py

# Capture exactly 20 packets
sudo python3 sniffer_scapy.py -c 20

# Capture on a specific interface
sudo python3 sniffer_scapy.py -i eth0

# Only capture HTTP traffic (BPF filter syntax)
sudo python3 sniffer_scapy.py -f "tcp port 80"

# Capture DNS traffic, save to a Wireshark-readable pcap, and log to a file
sudo python3 sniffer_scapy.py -f "udp port 53" --save dns_capture.pcap --log session.log

# List available interfaces
sudo python3 sniffer_scapy.py --list-interfaces

# Disable colors/icons (useful when redirecting output to a file)
sudo python3 sniffer_scapy.py --no-color
```

```bash
# Raw socket version (Linux only)
sudo python3 sniffer_socket.py
sudo python3 sniffer_socket.py -i eth0 -c 30
```

## Sample Output

```
[3] ------------------------------------------------------------
Time: 14:32:10.482   Size: 583 bytes
🔗 Ethernet | Src MAC: 02:fc:00:00:00:01  ->  Dst MAC: 02:fc:00:00:00:05
🌐 IPv4     | 192.168.1.5  ->  142.250.190.14  | TTL=64  | IP-proto=6
🔵 TCP      | 192.168.1.5:52344  ->  142.250.190.14:443  | Flags=PA  | App-layer guess: HTTPS
📦 Payload  | (517 bytes) ......\x16\x03\x01..........

🛑  Capture stopped.
📊  Session Summary
========================================
Duration          : 4.2 s
Total packets     : 6
Total data        : 997 bytes
Avg packets/sec   : 1.43
Protocol breakdown:
    TCP       :      4  ( 66.7%)
    UDP       :      2  ( 33.3%)
Top talkers (by IP/host):
    192.168.1.5           : 6 packets
    142.250.190.14        : 4 packets
```

## What This Demonstrates

1. **Packet structure & encapsulation** — every packet is layered: Ethernet
   frame → IP packet → TCP/UDP segment → application data. Each layer adds
   its own header before the one below hands off the payload.
2. **Protocol identification** — the Ethernet `EtherType` field tells you
   whether the payload is IPv4/IPv6/ARP; the IP header's `protocol` field
   identifies TCP (6), UDP (17), or ICMP (1); port numbers hint at the
   application protocol (80/443 = web, 53 = DNS, 22 = SSH, etc).
3. **TCP flags** (SYN, ACK, FIN, RST, PSH, URG) reveal connection state —
   a SYN starts the handshake, SYN-ACK responds, FIN/ACK closes it gracefully.
4. **Payload inspection** — for unencrypted protocols (plain HTTP, DNS) you
   can read readable text directly. For HTTPS/TLS, the payload is encrypted
   binary — a practical illustration of why encryption matters for privacy.
5. **Raw socket vs. library approach** — the `struct`-based parser in
   `sniffer_socket.py` shows exactly how a library like scapy reconstructs
   headers from a byte stream (bit-shifting, network byte order, variable
   header lengths, etc), which deepened my understanding of what scapy
   abstracts away.

## Project Structure

```
.
├── sniffer_scapy.py    # Main tool (recommended) — scapy-based, cross-platform
├── sniffer_socket.py   # Educational raw-socket version — Linux only
├── logo.svg            # Project icon
└── README.md
```

## ⚠️ Ethical & Legal Notice

Only run this sniffer on networks and devices you **own** or have **explicit
permission** to monitor (e.g., your own home lab or a VM you control).
Capturing traffic on networks you don't have permission for is illegal in
most jurisdictions and violates most Terms of Service / Acceptable Use
Policies. This project is intended strictly for educational purposes.
