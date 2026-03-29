# NetSnoop — Analysis Writeup

**Tool:** NetSnoop v1.0  
**Author:** Sebastian Abbas  
**Date:** March 2026  
**Capture source:** [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)

---

## Objective

To demonstrate how NetSnoop analyses a real-world packet capture and surfaces security-relevant findings that would otherwise require manual triage in Wireshark.

---

## Methodology

1. Downloaded a sample `.pcap` from the Wireshark community capture library
2. Ran NetSnoop against the file: `python netsnoop.py capture.pcap`
3. Documented each detection module's findings and cross-validated findings manually in Wireshark

---

## Findings

### 1. Port Scan Detected — `192.168.1.105`

NetSnoop flagged a host probing over 1,000 unique destination ports within the capture window. The scan pattern — sequential ports with SYN packets and no completed handshakes — is consistent with a **TCP SYN (half-open) scan**, the default behaviour of tools like `nmap`.

**Wireshark validation:**  
Filtering on `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 192.168.1.105` confirmed the pattern. The majority of ports received a RST/ACK response (closed), with a handful returning SYN/ACK (open).

**Risk:** An attacker performing reconnaissance on the internal network. Indicates a compromised host or an insider threat.

---

### 2. Cleartext FTP Credentials

NetSnoop detected FTP `USER` and `PASS` commands transmitted in plaintext over TCP port 21.

```
[HIGH] [FTP] from 192.168.1.42: USER admin
[HIGH] [FTP] from 192.168.1.42: PASS password123
```

**Wireshark validation:**  
Filtering `ftp` and following the TCP stream confirmed the full authentication exchange. Credentials were fully visible with no encryption.

**Risk:** Any host on the network (or a passive tap) could capture these credentials. FTP should be replaced with SFTP or FTPS. This finding is a clear violation of data-in-transit security.

---

### 3. ARP Spoofing Indicator

Two distinct MAC addresses were observed claiming the same IP (`192.168.1.1` — the default gateway). This is the hallmark of an **ARP spoofing / man-in-the-middle attack**, where an attacker poisons the ARP cache to redirect traffic through their machine.

**Wireshark validation:**  
Filtering `arp` and sorting by sender IP confirmed two different hardware addresses broadcasting ARP replies for the gateway IP at overlapping times.

**Risk:** If successful, the attacker intercepts all traffic destined for the gateway — enabling credential theft, session hijacking, or SSL stripping.

---

### 4. Suspicious DNS Query

A host was observed querying a domain with an unusually long subdomain label (53 characters of high-entropy base64-like data), consistent with **DNS tunnelling** — a technique used to exfiltrate data or establish C2 communication through DNS, often bypassing firewalls that only filter TCP/UDP.

**Risk:** Data exfiltration or command-and-control channel. DNS tunnelling tools like `iodine` and `dnscat2` use this exact pattern.

---

## Conclusions

NetSnoop successfully surfaced four distinct security findings from a single capture file without any manual Wireshark filtering. Each finding was validated manually, confirming the tool's accuracy.

| Finding | Severity | Validated |
|---|---|---|
| Port scan from 192.168.1.105 | HIGH | ✓ |
| Cleartext FTP credentials | HIGH | ✓ |
| ARP spoofing on gateway | HIGH | ✓ |
| DNS tunnelling indicator | MEDIUM | ✓ |

---

## Recommendations

- Replace FTP with SFTP immediately
- Deploy Dynamic ARP Inspection (DAI) on managed switches
- Implement DNS monitoring / RPZ to block tunnelling domains
- Investigate the scanning host for compromise

---

## Reflection

This project reinforced concepts from FIT3165 (Computer Networks) and FIT3168 (IT Forensics), particularly around passive traffic analysis, protocol-level anomaly detection, and the gap between encrypted and unencrypted services. Building the detection logic from scratch (rather than relying on a GUI) deepened my understanding of how these attacks manifest at the packet level.
