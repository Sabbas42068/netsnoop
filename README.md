# 🔍 NetSnoop — Network Traffic Security Analyser

A command-line tool that analyses `.pcap` / `.pcapng` capture files and produces a security-focused report, flagging common threats and anomalies.

Built with Python and Scapy. Inspired by coursework in FIT3165 Computer Networks and FIT3168 IT Forensics at Monash University.

---

## Features

| Module | What it detects |
|---|---|
| **Top Talkers** | Most active IPs by packet count |
| **Protocol Breakdown** | TCP / UDP / ICMP / ARP distribution |
| **Port Scan Detection** | IPs probing many unique destination ports |
| **Cleartext Credentials** | HTTP Basic Auth, FTP USER/PASS, Telnet payloads |
| **Suspicious DNS** | Long subdomains (tunnelling), high entropy queries, suspicious TLDs, exfiltration volume |
| **ARP Spoofing** | IPs claimed by multiple MACs, gratuitous ARP storms |

---

## Installation

```bash
git clone https://github.com/Sabbas42068/netsnoop.git
cd netsnoop
pip install -r requirements.txt
```

> Requires Python 3.8+

---

## Usage

```bash
# Basic analysis
python netsnoop.py capture.pcap

# Show top 20 talkers, lower port scan threshold
python netsnoop.py capture.pcap --top 20 --scan-threshold 10

# Disable colour output (for piping to file)
python netsnoop.py capture.pcap --no-colour > report.txt
```

---

## Sample Output

```
 _   _      _   ____                        
| \ | | ___| |_/ ___| _ __   ___   ___  _ __  
|  \| |/ _ \ __\___ \| '_ \ / _ \ / _ \| '_ \ 
| |\  |  __/ |_ ___) | | | | (_) | (_) | |_) |
|_| \_|\___|\__|____/|_| |_|\___/ \___/| .__/ 
                                        |_|    

  Network Traffic Security Analyser — github.com/Sabbas42068

[*] Loading capture file: capture.pcap
[+] Loaded 4823 packets

───────────────────────────────────────────────────────
  CAPTURE SUMMARY
───────────────────────────────────────────────────────
  Total packets   : 4823
  IP packets      : 4761
  Capture duration: 143.22s

───────────────────────────────────────────────────────
  PORT SCAN DETECTION (threshold: 15 unique ports)
───────────────────────────────────────────────────────
  [HIGH] 192.168.1.105 scanned 1024 ports: 22, 23, 25, 80, 443, 445 ... (+1018 more)

───────────────────────────────────────────────────────
  CLEARTEXT CREDENTIAL DETECTION
───────────────────────────────────────────────────────
  [HIGH] [FTP] from 192.168.1.42: USER admin
  [HIGH] [FTP] from 192.168.1.42: PASS password123

───────────────────────────────────────────────────────
  ARP SPOOFING DETECTION
───────────────────────────────────────────────────────
  [HIGH] IP 192.168.1.1 claimed by multiple MACs: aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66

[✓] Analysis complete.
```

---

## Good Test Captures

Grab free sample pcaps to test with:

- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- Your own captures: `tcpdump -i eth0 -w capture.pcap`

---

## Project Structure

```
netsnoop/
├── netsnoop.py        # Main analyser
├── requirements.txt   # Dependencies
└── README.md
```

---

## Skills Demonstrated

- Python scripting with Scapy for packet-level analysis
- Detection of common network attack patterns (port scanning, ARP spoofing, credential sniffing)
- DNS anomaly detection including tunnelling indicators
- CLI tool design with argparse and coloured terminal output

---

## Author

**Sebastian Abbas** — Cybersecurity student at Monash University  
[linkedin.com/in/sebastian-abbas-67100638b](https://www.linkedin.com/in/sebastian-abbas-67100638b/) | [github.com/Sabbas42068](https://github.com/Sabbas42068)
