# 🛡️ Alien Hunter: Defensive Roadmap & TODO

This document catalogs proposed advanced defensive subsystems, intrusion detection capabilities, and deceptive traps planned for future releases of Alien Hunter. All proposed modules adhere to Alien Hunter's core software engineering principles: **zero third-party dependencies** (Python standard library only), modular design under `alien_hunter/defenses/`, and deterministic attribution.

---

## 📋 Backlog: Advanced Defensive Capabilities

### 1. Active Deception & Canary Traps

- [ ] **mDNS / Bonjour Poisoning Canary Trap (`MdnsCanaryTrap`)**
  - **Attack Vector**: Local Name Resolution Poisoning (MITRE ATT&CK T1557.001). Attackers (*Responder*, *Inveigh*) poison `.local` mDNS queries when clients search for printers, smart TVs, or AirPlay services.
  - **Design**: Broadcast periodic canary PTR/SRV queries for non-existent hostnames (`canary-srv-[uuid].local`) on UDP 5353 (`224.0.0.251`).
  - **Attribution**: 100% deterministic true-positive. Any response flags an active mDNS poisoner attempting credential theft.
  - **Module Target**: `alien_hunter/defenses/mdns_canary.py`

- [ ] **Decoy Honey-Share & Authentication Canary (`HoneyAuthTrap`)**
  - **Attack Vector**: Internal Lateral Reconnaissance & Credential Guessing (MITRE ATT&CK T1046, T1110). Attackers look for open SMB/HTTP shares to attempt anonymous access or dictionary attacks.
  - **Design**: Upgrade `HoneyPortListener` from basic TCP SYN logging to capture protocol pre-authentication handshakes (SMB `Negprot` dialect requests, HTTP `Authorization` headers) to extract the attacker's source IP, tooling user-agent, and attempted usernames.
  - **Module Target**: `alien_hunter/defenses/honey_auth.py`

---

### 2. Network Protocol Abuse & Denial-of-Service Guards

- [ ] **DHCP Starvation & Pool Exhaustion Detector (`DhcpStarvationGuard`)**
  - **Attack Vector**: Endpoint Denial of Service (MITRE ATT&CK T1499). Attackers (*Yersinia*, *dhcpstarv*) flood DHCP Discover requests with spoofed MACs to deplete the router's IP pool, forcing clients to disconnect and accept rogue DHCP servers.
  - **Design**: Passively monitor UDP 67/68 traffic. Track the burst rate of DHCP Discover packets from distinct MAC addresses. Trigger an alert if burst rate exceeds threshold (e.g. >5 requests/sec).
  - **Module Target**: `alien_hunter/defenses/dhcp_starvation.py`

- [ ] **ICMP Redirect Route Hijacking Detector (`IcmpRedirectGuard`)**
  - **Attack Vector**: Adversary-in-the-Middle Route Manipulation (MITRE ATT&CK T1557). Attackers send ICMP Type 5 (Redirect) packets claiming their machine is the preferred gateway for outbound traffic.
  - **Design**: Open a raw `AF_INET` socket listening for ICMP Type 5 messages. Since legitimate modern routers almost never emit ICMP Redirects on flat subnets, any observed redirect triggers a MitM route manipulation alert.
  - **Module Target**: `alien_hunter/defenses/icmp_redirect.py`

- [ ] **Broadcast Storm & MAC Table Overflow Detector (`StormGuard`)**
  - **Attack Vector**: Switch CAM Table Flooding (*macof*) & Layer-2 Loops (MITRE ATT&CK T1499). Floods the local switch with random MACs to force hub fallback mode so the attacker can sniff all unicast frames.
  - **Design**: Measure packets-per-second (pps) and ratio of broadcast/multicast frames vs. unicast frames in `PassiveFrameSniffer`. Alert if broadcast rate exceeds 150 pps or unexpected MAC address churning occurs.
  - **Module Target**: `alien_hunter/defenses/storm_guard.py`

---

### 3. Traffic Anomaly & C2 Exfiltration Detection

- [ ] **High-Entropy DNS Tunneling & C2 Exfiltration Detector (`DnsTunnelingDetector`)**
  - **Attack Vector**: Protocol Tunneling / Non-Application Layer Protocol Exfiltration (MITRE ATT&CK T1048.003, T1071.004). Malware or compromised IoT devices encode exfiltrated data into DNS query subdomains (e.g. `a8f9c2d1e0b.c2.attacker.com` via UDP 53).
  - **Design**: Passively inspect DNS queries across the link. Calculate Shannon entropy ($-\sum p(x) \log_2 p(x)$) and label length of queried subdomains. Queries with entropy > 3.8 and label length > 32 characters are flagged as potential DNS tunnels or DGA malware.
  - **Module Target**: `alien_hunter/defenses/dns_tunneling.py`

- [ ] **Stealth TCP Half-Open / SYN Port Scan Detector (`SynScanDetector`)**
  - **Attack Vector**: Network Service Discovery (*Nmap -sS*, *masscan*) (MITRE ATT&CK T1046). Scanners send SYN packets across ports without completing the 3-way handshake to avoid connection logging.
  - **Design**: In `SentinelWatchdog`, inspect raw TCP flags. If an internal IP sends SYN packets to > 10 closed/unopened ports within a 5-second window, flag that internal host for port scanning.
  - **Module Target**: `alien_hunter/defenses/syn_scan.py`

---

### 4. Low Priority Enhancements

- [ ] **Native Pure-Python Layer-2 ARP Sweeper (`NativeArpSweeper`)**
  - **Objective**: Eliminate any reliance on the external `arp-scan` binary.
  - **Design**: Implement an active ARP broadcast sweep directly inside `alien_hunter/scanners/arp.py` using Python's built-in `socket(AF_PACKET, SOCK_RAW, htons(0x0806))` and `struct.pack`. Transmit Ethernet/ARP request frames across the subnet and gather unicast replies natively, rendering `arp-scan` completely optional and keeping Alien Hunter 100% self-contained.
  - **Module Target**: `alien_hunter/scanners/arp.py`

---

## 🛠️ Implementation Guidelines

1. **Standard Library Only**: All network interactions must use native `socket`, `struct`, `ipaddress`, `urllib.request`, and `json`.
2. **Modular GoF Facade**: Every new defense must be placed under `alien_hunter/defenses/<name>.py` and exposed cleanly through the unified `ThreatDetector` facade (`alien_hunter/threats.py`).
3. **Subnet-Aware Topology**: Always use `ipaddress.ip_network` and `ipaddress.ip_address` for IP validation and link boundaries; avoid hardcoded magic strings.
4. **Structured Testing**: Every new module must include dedicated unit tests with mock sockets/packets in `tests/`.
