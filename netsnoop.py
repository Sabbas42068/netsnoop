#!/usr/bin/env python3
"""
netsnoop.py - Network Traffic Security Analyser
Author: Sebastian Abbas
GitHub: github.com/Sabbas42068

Analyses .pcap files and produces a security-focused report flagging:
  - Top talkers (most active IPs)
  - Protocol breakdown
  - Cleartext credentials (HTTP Basic Auth, FTP, Telnet)
  - Port scan detection
  - Suspicious DNS queries
  - ARP spoofing indicators
"""

import argparse
import sys
from collections import defaultdict, Counter
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ARP, Raw
from scapy.layers import http
import re

# ── ANSI colours for terminal output ──────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}
 _   _      _   ____                        
| \\ | | ___| |_/ ___| _ __   ___   ___  _ __  
|  \\| |/ _ \\ __\\___ \\| '_ \\ / _ \\ / _ \\| '_ \\ 
| |\\  |  __/ |_ ___) | | | | (_) | (_) | |_) |
|_| \\_|\\___|\\__|____/|_| |_|\\___/ \\___/| .__/ 
                                        |_|    
{RESET}{CYAN}  Network Traffic Security Analyser — github.com/Sabbas42068{RESET}
""")

def severity(label):
    colours = {"HIGH": RED, "MED": YELLOW, "INFO": GREEN}
    return f"{colours.get(label, RESET)}[{label}]{RESET}"

# ── Load pcap ─────────────────────────────────────────────────────────────────

def load_pcap(path):
    print(f"{BOLD}[*] Loading capture file: {path}{RESET}")
    try:
        packets = rdpcap(path)
        print(f"{GREEN}[+] Loaded {len(packets)} packets{RESET}\n")
        return packets
    except FileNotFoundError:
        print(f"{RED}[-] File not found: {path}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[-] Failed to read pcap: {e}{RESET}")
        sys.exit(1)

# ── Analysis modules ──────────────────────────────────────────────────────────

def top_talkers(packets, top_n=10):
    """Most active source IPs by packet count."""
    counts = Counter()
    for pkt in packets:
        if pkt.haslayer(IP):
            counts[pkt[IP].src] += 1
    print(f"{BOLD}{'─'*55}")
    print(f"  TOP TALKERS (by packet count){RESET}")
    print(f"{BOLD}{'─'*55}{RESET}")
    for ip, count in counts.most_common(top_n):
        print(f"  {ip:<20} {count} packets")
    print()

def protocol_breakdown(packets):
    """Count packets per transport protocol."""
    protos = Counter()
    for pkt in packets:
        if pkt.haslayer(IP):
            proto = pkt[IP].proto
            if proto == 6:
                protos["TCP"] += 1
            elif proto == 17:
                protos["UDP"] += 1
            elif proto == 1:
                protos["ICMP"] += 1
            else:
                protos[f"OTHER({proto})"] += 1
        elif pkt.haslayer(ARP):
            protos["ARP"] += 1

    print(f"{BOLD}{'─'*55}")
    print(f"  PROTOCOL BREAKDOWN{RESET}")
    print(f"{BOLD}{'─'*55}{RESET}")
    for proto, count in protos.most_common():
        print(f"  {proto:<10} {count} packets")
    print()

def detect_port_scan(packets, threshold=15):
    """
    Flag IPs that connect to many unique destination ports — classic port scan pattern.
    Threshold: source IP hitting >threshold unique dst ports = suspicious.
    """
    # src_ip -> set of destination ports
    src_ports = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src_ports[pkt[IP].src].add(pkt[TCP].dport)

    findings = [(ip, ports) for ip, ports in src_ports.items() if len(ports) >= threshold]

    print(f"{BOLD}{'─'*55}")
    print(f"  PORT SCAN DETECTION (threshold: {threshold} unique ports){RESET}")
    print(f"{BOLD}{'─'*55}{RESET}")
    if not findings:
        print(f"  {GREEN}No port scans detected{RESET}")
    else:
        for ip, ports in sorted(findings, key=lambda x: -len(x[1])):
            sorted_ports = sorted(ports)
            preview = ", ".join(map(str, sorted_ports[:10]))
            if len(sorted_ports) > 10:
                preview += f"... (+{len(sorted_ports)-10} more)"
            print(f"  {severity('HIGH')} {ip} scanned {len(ports)} ports: {preview}")
    print()

def detect_cleartext_creds(packets):
    """
    Hunt for cleartext credentials in HTTP Basic Auth, FTP, and Telnet.
    """
    findings = []

    for pkt in packets:
        # HTTP Basic Auth
        if pkt.haslayer(http.HTTPRequest):
            req = pkt[http.HTTPRequest]
            if hasattr(req, "Authorization") and req.Authorization:
                auth = req.Authorization.decode(errors="replace")
                if auth.lower().startswith("basic "):
                    findings.append(("HTTP Basic Auth", pkt[IP].src if pkt.haslayer(IP) else "?", auth))

        # FTP USER / PASS commands
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="replace")
            if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                if payload.upper().startswith("USER ") or payload.upper().startswith("PASS "):
                    src = pkt[IP].src if pkt.haslayer(IP) else "?"
                    findings.append(("FTP", src, payload.strip()))

            # Telnet (port 23) — log any printable payload chunks
            if (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
                printable = re.sub(r'[^\x20-\x7e]', '', payload)
                if len(printable) > 3:
                    src = pkt[IP].src if pkt.haslayer(IP) else "?"
                    findings.append(("Telnet", src, printable[:80]))

    print(f"{BOLD}{'─'*55}")
    print(f"  CLEARTEXT CREDENTIAL DETECTION{RESET}")
    print(f"{BOLD}{'─'*55}{RESET}")
    if not findings:
        print(f"  {GREEN}No cleartext credentials detected{RESET}")
    else:
        for proto, src, data in findings:
            print(f"  {severity('HIGH')} [{proto}] from {src}: {data}")
    print()

def detect_suspicious_dns(packets):
    """
    Flag DNS queries that look unusual:
    - Very long subdomains (possible DNS tunnelling)
    - Queries for known malicious TLDs (.onion, .bit)
    - High query volume from a single host (possible exfiltration)
    """
    dns_queries = []
    query_counts = Counter()

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            src   = pkt[IP].src if pkt.haslayer(IP) else "?"
            dns_queries.append((src, qname))
            query_counts[src] += 1

    print(f"{BOLD}{'─'*55}")
    print(f"  SUSPICIOUS DNS ANALYSIS{RESET}")
    print(f"{BOLD}{'─'*55}{RESET}")

    found = False

    for src, qname in dns_queries:
        flags = []

        # Long subdomain — potential DNS tunnelling
        subdomain = qname.split(".")[0]
        if len(subdomain) > 40:
            flags.append("long subdomain (possible tunnelling)")

        # Suspicious TLDs
        if any(qname.endswith(tld) for tld in [".onion", ".bit", ".bazar", ".coin"]):
            flags.append("suspicious TLD")

        # Excessive entropy in subdomain (base64/hex encoded data)
        non_alpha = sum(1 for c in subdomain if not c.isalpha())
        if len(subdomain) > 20 and non_alpha / max(len(subdomain), 1) > 0.4:
            flags.append("high entropy (possible encoded data)")

        if flags:
            print(f"  {severity('MED')} {src} queried: {qname}")
            print(f"         Reason: {', '.join(flags)}")
            found = True

    # High DNS query volume
    for src, count in query_counts.most_common(3):
        if count > 50:
            print(f"  {severity('MED')} {src} made {count} DNS queries (possible exfiltration)")
            found = True

    if not found:
        print(f"  {GREEN}No suspicious DNS activity detected{RESET}")

    # Show top queried domains regardless
    print(f"\n  {BOLD}Top queried domains:{RESET}")
    domain_counts = Counter(q for _, q in dns_queries)
    for domain, count in domain_counts.most_common(5):
        print(f"    {domain:<45} {count}x")
    print()

def detect_arp_spoofing(packets):
    """
    Detect ARP spoofing: flag if the same IP is claimed by multiple MACs,
    or if a MAC is claiming many IPs (gratuitous ARP storm).
    """
    ip_to_mac  = defaultdict(set)
    mac_to_ips = defaultdict(set)

    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ip_to_mac[ip].add(mac)
            mac_to_ips[mac].add(ip)

    print(f"{BOLD}{'─'*55}")
    print(f"  ARP SPOOFING DETECTION{RESET}")
    print(f"{BOLD}{'─'*55}{RESET}")
    found = False

    for ip, macs in ip_to_mac.items():
        if len(macs) > 1:
            print(f"  {severity('HIGH')} IP {ip} claimed by multiple MACs: {', '.join(macs)}")
            found = True

    for mac, ips in mac_to_ips.items():
        if len(ips) > 5:
            print(f"  {severity('MED')} MAC {mac} is claiming {len(ips)} IPs (possible ARP storm)")
            found = True

    if not found:
        print(f"  {GREEN}No ARP spoofing indicators detected{RESET}")
    print()

def summary(packets):
    """Quick stats header."""
    ip_pkts = sum(1 for p in packets if p.haslayer(IP))
    print(f"{BOLD}{'─'*55}")
    print(f"  CAPTURE SUMMARY{RESET}")
    print(f"{BOLD}{'─'*55}{RESET}")
    print(f"  Total packets   : {len(packets)}")
    print(f"  IP packets      : {ip_pkts}")
    # Time range
    if len(packets) > 1:
        duration = packets[-1].time - packets[0].time
        print(f"  Capture duration: {duration:.2f}s")
    print()

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetSnoop — Security-focused pcap analyser",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("pcap", help="Path to .pcap or .pcapng file")
    parser.add_argument("--top", type=int, default=10, help="Number of top talkers to show (default: 10)")
    parser.add_argument("--scan-threshold", type=int, default=15,
                        help="Unique ports before flagging as port scan (default: 15)")
    parser.add_argument("--no-colour", action="store_true", help="Disable coloured output")
    args = parser.parse_args()

    if args.no_colour:
        global RED, YELLOW, GREEN, CYAN, BOLD, RESET
        RED = YELLOW = GREEN = CYAN = BOLD = RESET = ""

    banner()
    packets = load_pcap(args.pcap)

    summary(packets)
    top_talkers(packets, top_n=args.top)
    protocol_breakdown(packets)
    detect_port_scan(packets, threshold=args.scan_threshold)
    detect_cleartext_creds(packets)
    detect_suspicious_dns(packets)
    detect_arp_spoofing(packets)

    print(f"{CYAN}{BOLD}[✓] Analysis complete.{RESET}\n")

if __name__ == "__main__":
    main()
