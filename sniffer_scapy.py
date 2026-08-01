#!/usr/bin/env python3
"""
================================================================================
  TrafficTap — Basic Network Sniffer (Scapy Edition)
================================================================================
Internship Task: Capture and analyze live network packets to understand
protocol structure and how data flows across a network.

Requirements:
    pip install scapy colorama

Run with administrator/root privileges (raw packet capture requires it):
    Linux/macOS : sudo python3 sniffer_scapy.py
    Windows     : install Npcap (https://npcap.com), run terminal as Administrator

Usage examples:
    sudo python3 sniffer_scapy.py                      # sniff all traffic, default interface
    sudo python3 sniffer_scapy.py -i eth0               # sniff a specific interface
    sudo python3 sniffer_scapy.py -c 50                 # stop after 50 packets
    sudo python3 sniffer_scapy.py -f "tcp port 80"      # BPF filter (HTTP only)
    sudo python3 sniffer_scapy.py --save capture.pcap   # save capture to a .pcap file
    sudo python3 sniffer_scapy.py --log session.log     # also write output to a log file
    sudo python3 sniffer_scapy.py --no-color            # disable colored/icon output
    sudo python3 sniffer_scapy.py --list-interfaces      # list available interfaces and exit

Ethical & Legal Notice:
    Only run this on networks/devices you own or have explicit written
    permission to monitor. Unauthorized packet capture is illegal in most
    jurisdictions and violates most acceptable-use policies.
================================================================================
"""

import argparse
import datetime
import re
import sys
import time
from collections import Counter

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    _COLOR_AVAILABLE = True
except ImportError:
    _COLOR_AVAILABLE = False

try:
    from scapy.all import sniff, wrpcap, get_if_list, Raw
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    print("ERROR: scapy is not installed. Install it with:\n    pip install scapy")
    sys.exit(1)


# --------------------------------------------------------------------------
# Visual theme: icons + colors. Falls back to plain text safely if colorama
# isn't installed or the terminal doesn't support ANSI colors.
# --------------------------------------------------------------------------
class Theme:
    def __init__(self, enabled: bool):
        self.enabled = enabled and _COLOR_AVAILABLE

    def _wrap(self, text, color):
        if not self.enabled:
            return text
        return f"{color}{text}{Style.RESET_ALL}"

    def header(self, text):
        return self._wrap(text, Fore.CYAN + Style.BRIGHT)

    def eth(self, text):
        return self._wrap(text, Fore.WHITE)

    def ip(self, text):
        return self._wrap(text, Fore.YELLOW)

    def tcp(self, text):
        return self._wrap(text, Fore.BLUE + Style.BRIGHT)

    def udp(self, text):
        return self._wrap(text, Fore.GREEN + Style.BRIGHT)

    def icmp(self, text):
        return self._wrap(text, Fore.RED + Style.BRIGHT)

    def dns(self, text):
        return self._wrap(text, Fore.MAGENTA + Style.BRIGHT)

    def arp(self, text):
        return self._wrap(text, Fore.LIGHTYELLOW_EX)

    def payload(self, text):
        return self._wrap(text, Fore.LIGHTBLACK_EX)

    def warn(self, text):
        return self._wrap(text, Fore.RED + Style.BRIGHT)

    def info(self, text):
        return self._wrap(text, Fore.CYAN)

    def ok(self, text):
        return self._wrap(text, Fore.GREEN)


ICONS = {
    "eth": "\U0001F517", "ip": "\U0001F310", "ipv6": "\U0001F310", "tcp": "\U0001F535",
    "udp": "\U0001F7E2", "icmp": "\U0001F534", "dns": "\U0001F4DB", "arp": "\U0001F4E1",
    "payload": "\U0001F4E6", "start": "\U0001F6F0", "stop": "\U0001F6D1",
    "stats": "\U0001F4CA", "save": "\U0001F4BE", "warn": "\u26A0", "ok": "\u2705",
}

# Well-known ports -> human-readable protocol name
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    5353: "mDNS", 8080: "HTTP-ALT",
}

BANNER = r"""
 _____           __  __ _     _____
|_   _| __ __ _ / _|/ _(_) __|_   _|_ _ _ __
  | || '__/ _` | |_| |_| |/ __|| |/ _` | '_ \
  | || | | (_| |  _|  _| | (__ | | (_| | |_) |
  |_||_|  \__,_|_| |_| |_|\___||_|\__,_| .__/
                                        |_|
              Network Packet Sniffer
"""


class SnifferStats:
    """Tracks running statistics for the capture session."""

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
        lines = []
        lines.append(f"Duration          : {self.elapsed():.1f} s")
        lines.append(f"Total packets     : {self.total_packets}")
        lines.append(f"Total data        : {self.total_bytes:,} bytes")
        lines.append(f"Avg packets/sec   : {pps:.2f}")
        if self.total_packets:
            lines.append("Protocol breakdown:")
            for proto, count in self.protocol_counter.most_common():
                pct = (count / self.total_packets * 100)
                lines.append(f"    {proto:<10}: {count:>6}  ({pct:5.1f}%)")
        if self.top_talkers:
            lines.append("Top talkers (by IP/host):")
            for addr, count in self.top_talkers.most_common(5):
                lines.append(f"    {addr:<22}: {count} packets")
        return "\n".join(lines)


class Logger:
    """Prints to stdout and optionally mirrors (uncolored) output to a log file."""

    _ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

    def __init__(self, log_path=None):
        self.fh = open(log_path, "a", encoding="utf-8") if log_path else None

    def write(self, colored_text, plain_text=None):
        print(colored_text)
        if self.fh:
            self.fh.write((plain_text if plain_text is not None else self._ANSI_RE.sub("", colored_text)) + "\n")
            self.fh.flush()

    def close(self):
        if self.fh:
            self.fh.close()


def guess_app_protocol(sport, dport):
    """Best-effort guess of the application-layer protocol from port numbers."""
    return COMMON_PORTS.get(sport) or COMMON_PORTS.get(dport) or "Unknown"


def clean_payload_preview(raw_bytes, max_bytes=64):
    """Return a safe, printable ASCII preview of raw payload bytes."""
    preview = raw_bytes[:max_bytes]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in preview)


def analyze_packet(packet, theme: Theme, stats: SnifferStats, logger: Logger):
    seq_no = stats.total_packets + 1
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    lines = [f"\n{theme.header(f'[{seq_no}] ' + '-' * 60)}"]
    lines.append(f"Time: {timestamp}   Size: {len(packet)} bytes")

    size = len(packet)
    src_addr = dst_addr = None
    proto_label = "Other"

    # ---- Layer 2: Ethernet ----
    if packet.haslayer(Ether):
        eth = packet[Ether]
        lines.append(theme.eth(f"{ICONS['eth']} Ethernet | Src MAC: {eth.src}  ->  Dst MAC: {eth.dst}"))

    # ---- ARP (no IP layer present) ----
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op = {1: "request", 2: "reply"}.get(arp.op, str(arp.op))
        lines.append(theme.arp(f"{ICONS['arp']} ARP      | {arp.psrc} -> {arp.pdst}  | Op: {op}"))
        proto_label = "ARP"
        src_addr, dst_addr = arp.psrc, arp.pdst

    # ---- Layer 3: IPv4 ----
    elif packet.haslayer(IP):
        ip = packet[IP]
        src_addr, dst_addr = ip.src, ip.dst
        lines.append(theme.ip(
            f"{ICONS['ip']} IPv4     | {ip.src}  ->  {ip.dst}  | TTL={ip.ttl}  | IP-proto={ip.proto}"
        ))

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            proto_label = "TCP"
            app_proto = guess_app_protocol(tcp.sport, tcp.dport)
            flags = tcp.sprintf("%TCP.flags%")
            lines.append(theme.tcp(
                f"{ICONS['tcp']} TCP      | {ip.src}:{tcp.sport}  ->  {ip.dst}:{tcp.dport}  "
                f"| Flags={flags}  | App-layer guess: {app_proto}"
            ))

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            proto_label = "UDP"
            app_proto = guess_app_protocol(udp.sport, udp.dport)
            lines.append(theme.udp(
                f"{ICONS['udp']} UDP      | {ip.src}:{udp.sport}  ->  {ip.dst}:{udp.dport}  "
                f"| App-layer guess: {app_proto}"
            ))

            if packet.haslayer(DNS):
                dns = packet[DNS]
                try:
                    if dns.qr == 0 and packet.haslayer(DNSQR) and dns.qd is not None:
                        qname = dns.qd.qname.decode(errors="replace")
                        lines.append(theme.dns(f"{ICONS['dns']} DNS Query | {qname}"))
                    elif dns.qr == 1 and packet.haslayer(DNSRR) and dns.ancount:
                        # dns.an holds a linked chain of DNSRR layers (each record's
                        # .payload is the next record), not a plain Python list, so
                        # it can't be indexed with dns.an[i]. Depending on the scapy
                        # version it may come back as the chain head directly, or
                        # wrapped in a list-like container holding that chain head
                        # as its single element -- handle both.
                        rr = dns.an
                        if not isinstance(rr, DNSRR):
                            try:
                                rr = list(rr)[0]
                            except (TypeError, IndexError):
                                rr = None
                        answers = []
                        for _ in range(dns.ancount):
                            if not isinstance(rr, DNSRR):
                                break
                            answers.append(str(rr.rdata))
                            rr = rr.payload
                        if answers:
                            lines.append(theme.dns(f"{ICONS['dns']} DNS Answer| {', '.join(answers)}"))
                except Exception:
                    # DNS parsing can fail on malformed/truncated packets; skip gracefully
                    pass

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            proto_label = "ICMP"
            lines.append(theme.icmp(f"{ICONS['icmp']} ICMP     | Type={icmp.type}  Code={icmp.code}"))

        else:
            proto_label = f"IP-proto-{ip.proto}"
            lines.append(theme.ip(f"Transport| Other IP protocol (proto number {ip.proto})"))

    # ---- Layer 3: IPv6 ----
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        src_addr, dst_addr = ip6.src, ip6.dst
        proto_label = "IPv6"
        lines.append(theme.ip(
            f"{ICONS['ipv6']} IPv6     | {ip6.src}  ->  {ip6.dst}  | Hop-limit={ip6.hlim}  | Next-header={ip6.nh}"
        ))
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            proto_label = "TCPv6"
            flags = tcp.sprintf("%TCP.flags%")
            lines.append(theme.tcp(
                f"{ICONS['tcp']} TCP      | [{ip6.src}]:{tcp.sport}  ->  [{ip6.dst}]:{tcp.dport}  | Flags={flags}"
            ))
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            proto_label = "UDPv6"
            lines.append(theme.udp(
                f"{ICONS['udp']} UDP      | [{ip6.src}]:{udp.sport}  ->  [{ip6.dst}]:{udp.dport}"
            ))
        else:
            proto_label = "IPv6-other"

    else:
        lines.append(f"Non-IP/ARP packet. Summary: {packet.summary()}")

    # ---- Payload preview ----
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        preview = clean_payload_preview(raw_bytes)
        lines.append(theme.payload(f"{ICONS['payload']} Payload  | ({len(raw_bytes)} bytes) {preview}"))

    text_block = "\n".join(lines)
    logger.write(text_block)
    stats.update(size, proto_label, src_addr, dst_addr)


def list_interfaces():
    print("Available network interfaces:")
    try:
        for iface in get_if_list():
            print(f"  - {iface}")
    except Exception as exc:
        print(f"Could not list interfaces: {exc}")


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="TrafficTap - an educational network packet sniffer built on Scapy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--iface", default=None,
                         help="Network interface to sniff on (default: scapy auto-selects)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite, stop with Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                         help='BPF filter string, e.g. "tcp port 80" or "udp port 53"')
    parser.add_argument("--save", default=None,
                         help="Path to save captured packets as a .pcap file")
    parser.add_argument("--log", default=None,
                         help="Path to a text file where output will also be logged (plain text)")
    parser.add_argument("--no-color", action="store_true",
                         help="Disable colored/icon output (plain text only)")
    parser.add_argument("--list-interfaces", action="store_true",
                         help="List available network interfaces and exit")
    return parser


def main():
    args = build_arg_parser().parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    if args.count < 0:
        print("ERROR: --count must be >= 0")
        sys.exit(1)

    theme = Theme(enabled=not args.no_color)
    stats = SnifferStats()
    logger = Logger(args.log)

    print(theme.header(BANNER))
    print(theme.info(f"{ICONS['start']}  Starting capture... Press Ctrl+C to stop.\n"))

    if args.iface:
        print(theme.info(f"Interface : {args.iface}"))
    if args.filter:
        print(theme.info(f"Filter    : {args.filter}"))
    print()

    captured_packets = []

    def _handle(packet):
        analyze_packet(packet, theme, stats, logger)
        if args.save:
            captured_packets.append(packet)

    try:
        sniff(
            iface=args.iface,
            filter=args.filter if args.filter else None,
            prn=_handle,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print(theme.warn(f"\n{ICONS['warn']}  Permission denied. Run this script as root/Administrator."))
        logger.close()
        sys.exit(1)
    except (OSError, ValueError) as exc:
        # OSError covers "No such device", Npcap missing on Windows, invalid BPF filter, etc.
        # ValueError covers scapy raising "Interface 'X' not found !" for a bad -i value.
        print(theme.warn(f"\n{ICONS['warn']}  Network error: {exc}"))
        print(theme.info("Tip: run with --list-interfaces to see valid interface names. "
                          "On Windows, make sure Npcap is installed (https://npcap.com)."))
        logger.close()
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print(theme.header(f"\n{ICONS['stop']}  Capture stopped."))
        print(theme.header(f"{ICONS['stats']}  Session Summary"))
        print(theme.header("=" * 40))
        print(stats.summary())

        if args.save:
            if captured_packets:
                wrpcap(args.save, captured_packets)
                print(theme.ok(f"\n{ICONS['save']}  Saved {len(captured_packets)} packets to {args.save}"))
            else:
                print(theme.warn(f"\n{ICONS['warn']}  No packets captured; nothing saved."))
        logger.close()


if __name__ == "__main__":
    main()
