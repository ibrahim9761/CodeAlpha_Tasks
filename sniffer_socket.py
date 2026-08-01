#!/usr/bin/env python3
"""
================================================================================
  TrafficTap — Basic Network Sniffer (Raw Socket Edition, Linux only)
================================================================================
This version uses only Python's built-in `socket` module (no third-party
libraries) to show how packet capture works "under the hood": manually
unpacking the Ethernet, IP, and TCP/UDP/ICMP headers from raw bytes.

Why this exists alongside sniffer_scapy.py:
    sniffer_scapy.py   -> production-style tool, cross-platform, easy to read.
    sniffer_socket.py  -> educational deep-dive showing exactly what a library
                          like scapy does internally (bit-shifting, network
                          byte order, header lengths, etc).

Requirements:
    None beyond the Python standard library. colorama is used only if already
    installed; the script degrades to plain text otherwise.

Platform support:
    Linux only. AF_PACKET raw sockets are a Linux-specific API. On
    Windows/macOS, use sniffer_scapy.py instead.

Usage:
    sudo python3 sniffer_socket.py                # capture everything
    sudo python3 sniffer_socket.py -c 50           # stop after 50 packets
    sudo python3 sniffer_socket.py -i eth0         # bind to a specific interface
    sudo python3 sniffer_socket.py --no-color      # disable colored/icon output

Ethical & Legal Notice:
    Only run this on networks/devices you own or have explicit written
    permission to monitor. Unauthorized packet capture is illegal in most
    jurisdictions and violates most acceptable-use policies.
================================================================================
"""

import argparse
import datetime
import socket
import struct
import sys
import time
from collections import Counter

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    _COLOR_AVAILABLE = True
except ImportError:
    _COLOR_AVAILABLE = False


ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD

ICONS = {
    "eth": "\U0001F517", "ip": "\U0001F310", "tcp": "\U0001F535", "udp": "\U0001F7E2",
    "icmp": "\U0001F534", "arp": "\U0001F4E1", "payload": "\U0001F4E6",
    "start": "\U0001F6F0", "stop": "\U0001F6D1", "stats": "\U0001F4CA", "warn": "\u26A0",
}

BANNER = r"""
 _____           __  __ _     _____
|_   _| __ __ _ / _|/ _(_) __|_   _|_ _ _ __
  | || '__/ _` | |_| |_| |/ __|| |/ _` | '_ \
  | || | | (_| |  _|  _| | (__ | | (_| | |_) |
  |_||_|  \__,_|_| |_| |_|\___||_|\__,_| .__/
                                        |_|
        Raw Socket Edition (Linux only)
"""


class Theme:
    def __init__(self, enabled: bool):
        self.enabled = enabled and _COLOR_AVAILABLE

    def _wrap(self, text, color):
        return f"{color}{text}{Style.RESET_ALL}" if self.enabled else text

    def header(self, t): return self._wrap(t, Fore.CYAN + Style.BRIGHT)
    def eth(self, t):    return self._wrap(t, Fore.WHITE)
    def ip(self, t):     return self._wrap(t, Fore.YELLOW)
    def tcp(self, t):    return self._wrap(t, Fore.BLUE + Style.BRIGHT)
    def udp(self, t):    return self._wrap(t, Fore.GREEN + Style.BRIGHT)
    def icmp(self, t):   return self._wrap(t, Fore.RED + Style.BRIGHT)
    def arp(self, t):    return self._wrap(t, Fore.LIGHTYELLOW_EX)
    def payload(self, t):return self._wrap(t, Fore.LIGHTBLACK_EX)
    def warn(self, t):   return self._wrap(t, Fore.RED + Style.BRIGHT)
    def info(self, t):   return self._wrap(t, Fore.CYAN)


class SnifferStats:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counter = Counter()
        self.top_talkers = Counter()
        self.start_time = time.time()

    def update(self, size, proto_label, src=None, dst=None):
        self.total_packets += 1
        self.total_bytes += size
        self.protocol_counter[proto_label] += 1
        if src:
            self.top_talkers[src] += 1
        if dst:
            self.top_talkers[dst] += 1

    def elapsed(self):
        return max(time.time() - self.start_time, 1e-6)

    def summary(self):
        pps = self.total_packets / self.elapsed()
        lines = [
            f"Duration          : {self.elapsed():.1f} s",
            f"Total packets     : {self.total_packets}",
            f"Total data        : {self.total_bytes:,} bytes",
            f"Avg packets/sec   : {pps:.2f}",
        ]
        if self.total_packets:
            lines.append("Protocol breakdown:")
            for proto, count in self.protocol_counter.most_common():
                pct = count / self.total_packets * 100
                lines.append(f"    {proto:<10}: {count:>6}  ({pct:5.1f}%)")
        if self.top_talkers:
            lines.append("Top talkers (by IP):")
            for addr, count in self.top_talkers.most_common(5):
                lines.append(f"    {addr:<22}: {count} packets")
        return "\n".join(lines)


def mac_addr(raw6: bytes) -> str:
    """Convert 6 raw bytes into a human readable MAC address string."""
    return ":".join(f"{b:02x}" for b in raw6)


def parse_ethernet_header(raw_data):
    if len(raw_data) < 14:
        raise ValueError("Frame too short to contain an Ethernet header")
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", raw_data[:14])
    return mac_addr(dest_mac), mac_addr(src_mac), proto, raw_data[14:]


def parse_ip_header(raw_data):
    if len(raw_data) < 20:
        raise ValueError("Payload too short to contain an IPv4 header")
    version_ihl = raw_data[0]
    version = version_ihl >> 4
    header_length = (version_ihl & 0x0F) * 4  # IHL is in 32-bit words
    ttl, proto, src, dst = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    return version, header_length, ttl, proto, src_ip, dst_ip, raw_data[header_length:]


def parse_ipv6_header(raw_data):
    if len(raw_data) < 40:
        raise ValueError("Payload too short to contain an IPv6 header")
    # First 4 bytes: version(4) + traffic class(8) + flow label(20)
    payload_len, next_header, hop_limit = struct.unpack("! H B B", raw_data[4:8])
    src = socket.inet_ntop(socket.AF_INET6, raw_data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, raw_data[24:40])
    return next_header, hop_limit, src, dst, raw_data[40:]


def parse_tcp_header(raw_data):
    if len(raw_data) < 14:
        raise ValueError("Segment too short to contain a TCP header")
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack(
        "! H H L L H", raw_data[:14]
    )
    data_offset = (offset_reserved_flags >> 12) * 4  # header length in bytes
    # Ordered to match conventional tcpdump/Wireshark-style flag strings,
    # e.g. a SYN-ACK prints as "SA" rather than "AS".
    flag_order = [
        ("S", (offset_reserved_flags >> 1) & 1),   # SYN
        ("A", (offset_reserved_flags >> 4) & 1),   # ACK
        ("P", (offset_reserved_flags >> 3) & 1),   # PSH
        ("R", (offset_reserved_flags >> 2) & 1),   # RST
        ("F", offset_reserved_flags & 1),          # FIN
        ("U", (offset_reserved_flags >> 5) & 1),   # URG
    ]
    flags_str = "".join(letter for letter, val in flag_order if val) or "-"
    payload = raw_data[data_offset:] if data_offset <= len(raw_data) else b""
    return src_port, dst_port, seq, ack, flags_str, payload


def parse_udp_header(raw_data):
    if len(raw_data) < 8:
        raise ValueError("Segment too short to contain a UDP header")
    # UDP header layout: src_port(2) dst_port(2) length(2) checksum(2)
    src_port, dst_port, length = struct.unpack("! H H H 2x", raw_data[:8])
    return src_port, dst_port, length, raw_data[8:]


def parse_arp_packet(raw_data):
    if len(raw_data) < 28:
        raise ValueError("Frame too short to contain a standard ARP packet")
    (htype, ptype, hlen, plen, opcode) = struct.unpack("! H H B B H", raw_data[:8])
    offset = 8
    sender_mac = mac_addr(raw_data[offset:offset + hlen]); offset += hlen
    sender_ip = socket.inet_ntoa(raw_data[offset:offset + plen]); offset += plen
    target_mac = mac_addr(raw_data[offset:offset + hlen]); offset += hlen
    target_ip = socket.inet_ntoa(raw_data[offset:offset + plen])
    op_name = {1: "request", 2: "reply"}.get(opcode, str(opcode))
    return op_name, sender_mac, sender_ip, target_mac, target_ip


def parse_icmp_header(raw_data):
    if len(raw_data) < 4:
        raise ValueError("Segment too short to contain an ICMP header")
    icmp_type, code = struct.unpack("! B B 2x", raw_data[:4])
    return icmp_type, code


def format_payload(data: bytes, max_bytes: int = 64):
    """Return a printable ASCII preview of the payload (first max_bytes bytes)."""
    preview = data[:max_bytes]
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
    return printable, len(data)


def analyze_frame(raw_data, theme: Theme, stats: SnifferStats):
    seq_no = stats.total_packets + 1
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    size = len(raw_data)
    src_addr = dst_addr = None
    proto_label = "Other"

    try:
        dest_mac, src_mac, eth_proto, eth_payload = parse_ethernet_header(raw_data)
    except ValueError as exc:
        print(theme.warn(f"[!] Skipped malformed frame: {exc}"))
        return

    print(f"\n{theme.header(f'[{seq_no}] ' + '-' * 60)}")
    print(f"Time: {timestamp}   Size: {size} bytes")
    print(theme.eth(
        f"{ICONS['eth']} Ethernet | Src MAC: {src_mac}  ->  Dst MAC: {dest_mac}  "
        f"| EtherType: {hex(eth_proto)}"
    ))

    try:
        if eth_proto == ETH_P_IP:
            version, header_len, ttl, proto, src_ip, dst_ip, ip_payload = parse_ip_header(eth_payload)
            src_addr, dst_addr = src_ip, dst_ip
            print(theme.ip(f"{ICONS['ip']} IPv4     | {src_ip}  ->  {dst_ip}  | TTL={ttl}  | Protocol={proto}"))

            if proto == 6:  # TCP
                proto_label = "TCP"
                src_port, dst_port, seq, ack, flags, tcp_payload = parse_tcp_header(ip_payload)
                print(theme.tcp(f"{ICONS['tcp']} TCP      | {src_ip}:{src_port}  ->  {dst_ip}:{dst_port}  | Flags={flags}"))
                if tcp_payload:
                    text, n = format_payload(tcp_payload)
                    print(theme.payload(f"{ICONS['payload']} Payload  | ({n} bytes) {text}"))

            elif proto == 17:  # UDP
                proto_label = "UDP"
                src_port, dst_port, length, udp_payload = parse_udp_header(ip_payload)
                print(theme.udp(f"{ICONS['udp']} UDP      | {src_ip}:{src_port}  ->  {dst_ip}:{dst_port}  | Length={length}"))
                if udp_payload:
                    text, n = format_payload(udp_payload)
                    print(theme.payload(f"{ICONS['payload']} Payload  | ({n} bytes) {text}"))

            elif proto == 1:  # ICMP
                proto_label = "ICMP"
                icmp_type, code = parse_icmp_header(ip_payload)
                print(theme.icmp(f"{ICONS['icmp']} ICMP     | Type={icmp_type}  Code={code}"))

            else:
                proto_label = f"IP-proto-{proto}"
                print(f"Transport| Other protocol (number {proto})")

        elif eth_proto == ETH_P_IPV6:
            next_header, hop_limit, src_ip6, dst_ip6, ip6_payload = parse_ipv6_header(eth_payload)
            src_addr, dst_addr = src_ip6, dst_ip6
            proto_label = "IPv6"
            print(theme.ip(f"{ICONS['ip']} IPv6     | {src_ip6}  ->  {dst_ip6}  | Hop-limit={hop_limit}  | Next-hdr={next_header}"))

            if next_header == 6:
                proto_label = "TCPv6"
                src_port, dst_port, seq, ack, flags, tcp_payload = parse_tcp_header(ip6_payload)
                print(theme.tcp(f"{ICONS['tcp']} TCP      | [{src_ip6}]:{src_port}  ->  [{dst_ip6}]:{dst_port}  | Flags={flags}"))
            elif next_header == 17:
                proto_label = "UDPv6"
                src_port, dst_port, length, udp_payload = parse_udp_header(ip6_payload)
                print(theme.udp(f"{ICONS['udp']} UDP      | [{src_ip6}]:{src_port}  ->  [{dst_ip6}]:{dst_port}  | Length={length}"))

        elif eth_proto == ETH_P_ARP:
            proto_label = "ARP"
            op_name, sender_mac, sender_ip, target_mac, target_ip = parse_arp_packet(eth_payload)
            src_addr, dst_addr = sender_ip, target_ip
            print(theme.arp(
                f"{ICONS['arp']} ARP      | {sender_ip} ({sender_mac})  ->  {target_ip} ({target_mac})  | Op: {op_name}"
            ))

        else:
            print(f"Non-IP frame (EtherType {hex(eth_proto)}). Skipping detailed parse.")

    except ValueError as exc:
        print(theme.warn(f"[!] Could not fully parse packet: {exc}"))

    stats.update(size, proto_label, src_addr, dst_addr)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="TrafficTap (raw-socket edition) - educational Linux packet sniffer using only the standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--iface", default=None,
                         help="Bind capture to a specific interface name (e.g. eth0). Default: all interfaces.")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite, stop with Ctrl+C)")
    parser.add_argument("--no-color", action="store_true",
                         help="Disable colored/icon output (plain text only)")
    return parser


def main():
    args = build_arg_parser().parse_args()
    theme = Theme(enabled=not args.no_color)
    stats = SnifferStats()

    if not hasattr(socket, "AF_PACKET"):
        print(theme.warn(f"{ICONS['warn']}  AF_PACKET is not available on this OS (Linux only)."))
        print(theme.info("Use sniffer_scapy.py instead on Windows/macOS."))
        sys.exit(1)

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if args.iface:
            conn.bind((args.iface, 0))
    except PermissionError:
        print(theme.warn(f"{ICONS['warn']}  Permission denied. Run this script with sudo."))
        sys.exit(1)
    except OSError as exc:
        print(theme.warn(f"{ICONS['warn']}  Could not open interface: {exc}"))
        sys.exit(1)

    print(theme.header(BANNER))
    print(theme.info(f"{ICONS['start']}  Starting capture... Press Ctrl+C to stop.\n"))
    if args.iface:
        print(theme.info(f"Interface : {args.iface}"))
    print()

    try:
        while args.count == 0 or stats.total_packets < args.count:
            try:
                raw_data, _addr = conn.recvfrom(65536)
            except OSError as exc:
                print(theme.warn(f"[!] Socket read error: {exc}"))
                break
            analyze_frame(raw_data, theme, stats)
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        print(theme.header(f"\n{ICONS['stop']}  Capture stopped."))
        print(theme.header(f"{ICONS['stats']}  Session Summary"))
        print(theme.header("=" * 40))
        print(stats.summary())


if __name__ == "__main__":
    main()
