# Alien Hunter (`alien-hunter`)

LAN security auditor and network discovery tool for Linux. Discovers hosts across local subnets and evaluates active Layer-2/3 network posture.

---

## Overview

Standard ICMP ping sweeps often miss active devices on local networks due to:
1. **Power Management:** Mobile operating systems (iOS and Android) power down Wi-Fi interfaces during sleep and drop ICMP echo requests.
2. **Host Firewalls:** Default firewall profiles (e.g., Windows Defender, macOS firewall) drop unsolicited incoming ICMP packets.
3. **MAC Randomization:** Randomized MAC addresses obscure hardware vendors.
4. **Out-of-Subnet Static IPs:** Statically addressed devices outside the DHCP subnet range do not respond to standard subnet sweeps.

---

## Capabilities

### Network Discovery
* **Layer-2 ARP Probing:** Emits ARP requests via native `AF_PACKET` raw sockets (with fallback to `arp-scan` and `/proc/net/arp`) to map IP addresses to physical MAC addresses directly at the data link layer.
* **Reverse DNS Lookups:** Queries the gateway DNS resolver (`UDP 53`) for PTR records to discover DHCP-assigned hostnames.
* **Multicast DNS (mDNS):** Queries `224.0.0.251:5353` for service advertisements (AirPlay, Cast, HTTP, etc.).
* **WS-Discovery:** Probes UDP 3702 (`239.255.255.250`) to locate Windows endpoints and ONVIF-compatible devices.
* **NetBIOS & SSDP:** Queries NetBIOS Name Service (`UDP 137`) and UPnP M-SEARCH (`UDP 1900`).
* **Device Identification:** Correlates OUI vendor tables, mDNS records, and DHCP hostnames to classify hardware types.
* **Passive Traffic Sniffing:** Captures Ethernet frames on the local interface to identify unprompted traffic and hosts with out-of-subnet IP addresses.

### Intrusion Detection & Defenses
* **Name Resolution Poisoning Canary:** Broadcasts canary queries for non-existent hostnames across LLMNR (`UDP 5355`), NetBIOS-NS (`UDP 137`), and mDNS (`UDP 5353`). Any affirmative response detects active poisoners (e.g., Responder, Inveigh).
* **Rogue IPv6 Router Detection:** Monitors `ff02::1` for rogue ICMPv6 Router Advertisements (Type 134) and unauthorized RDNSS assignments (e.g., `mitm6`).
* **DNS Integrity Verification:** Compares gateway DNS resolution against upstream resolvers (Cloudflare `1.1.1.1`, Quad9 `9.9.9.9`) to identify spoofed private IPs or NXDOMAIN hijacking.
* **Decoy Honey-Ports & Auth Traps:** Binds non-blocking TCP listeners and service banner emulators (HTTP, FTP, Telnet) to configurable decoy ports (e.g., 2323, 5555, 8888) to detect internal port scans and capture brute-force credentials.
* **Stealth TCP SYN Scan Detection:** Captures raw IPv4 TCP frames to detect half-open SYN port sweeps across closed or unallocated ports (e.g., `nmap -sS`, `masscan`).
* **High-Entropy DNS Tunneling Detection:** Analyzes DNS queries on the local interface for high Shannon entropy, oversized subdomains, and TXT query anomalies characteristic of C2 tunneling tools (e.g., `iodine`, `dnscat2`).
* **Port Drift Tracking:** Compares open TCP ports against baseline records in `known_devices.json` to flag newly exposed services.
* **Promiscuous Mode Detection:** Sends non-broadcast unicast ARP probes to identify interfaces operating in promiscuous capture mode.
* **DHCP Verification:** Probes UDP 67/68 to verify active DHCP servers and detect unauthorized gateway offers.
* **Inventory Classification:** Evaluates discovered hosts against a local whitelist (`known_devices.json`) and flags unknown devices as untrusted.
* **Zero External Dependencies:** Built strictly using Python standard library modules (`socket`, `struct`, `ipaddress`, `urllib`).
* **Daemon Mode:** Supports continuous background execution with configurable polling intervals and alert dispatch to Telegram, Discord, Slack, or generic webhooks.

---

## Requirements & Installation

### Requirements
* Linux operating system (kernel with raw socket support)
* Python 3.7+ (standard library only)
* Optional: `arp-scan` (fallback Layer-2 sweeper)

### Automated Setup
```bash
git clone https://github.com/jekyll86/alien-hunter.git
cd alien-hunter
sudo ./install.sh
```

### Manual Setup
```bash
git clone https://github.com/jekyll86/alien-hunter.git
cd alien-hunter
chmod +x alien_hunter.py

# Run directly
sudo ./alien_hunter.py
```

---

## Codebase Architecture

```text
alien_hunter/
├── models.py             # Domain dataclasses (Device, NetworkInfo, AuditResult)
├── config.py             # ConfigManager (path resolution, inventory persistence)
├── threats.py            # ThreatDetector (facade delegating to defense modules)
├── cli.py                # Command-line argument parsing and execution flow
├── core/
│   ├── engine.py         # DiscoveryEngine (scanner orchestration)
│   └── sentinel.py       # SentinelWatchdog (background audit loop and honey-ports)
├── defenses/             # Dedicated defensive modules
│   ├── llmnr_canary.py   # LLMNR & NetBIOS canary trap
│   ├── mdns_canary.py    # mDNS / Bonjour canary trap
│   ├── ipv6_guard.py     # ICMPv6 RA and RDNSS inspector
│   ├── dns_integrity.py  # DNS integrity and cache poisoning auditor
│   ├── honey_port.py     # TCP decoy listener
│   ├── honey_auth.py     # Emulated authentication traps (HTTP, FTP, Telnet)
│   ├── syn_scan.py       # Raw socket TCP SYN port scan detector
│   ├── dns_tunneling.py  # Shannon entropy and DNS exfiltration detector
│   ├── port_drift.py     # Baseline port comparison
│   └── anti_sniff.py     # Promiscuous interface detection
├── scanners/             # Active and passive network discovery modules
│   ├── arp.py            # Layer-2 ARP sweeper (AF_PACKET raw sockets & fallback)
│   ├── mdns.py           # mDNS discovery scanner
│   ├── ws_discovery.py   # WS-Discovery probe scanner
│   ├── netbios.py        # NetBIOS Name Service scanner
│   ├── ssdp.py           # SSDP / UPnP M-SEARCH scanner
│   ├── router.py         # Gateway DNS PTR lookup
│   ├── sniffer.py        # Raw socket Ethernet frame sniffer
│   ├── ports.py          # TCP port scanner and service signatures
│   └── net_utils.py      # Low-level socket creation helpers
├── identifiers/          # Vendor and device resolution
│   ├── apple.py          # Apple device identification
│   └── vendor.py         # IEEE OUI MAC database lookup
├── ai/                   # AI security analysis adapter
│   ├── engine.py         # AiAnalysisEngine
│   ├── base.py           # BaseAIProvider and prompt formatting
│   ├── models.py         # Dataclasses and Enums for risk and posture
│   └── providers/        # Adapters (Ollama, OpenAI-compatible, Anthropic, Gemini)
├── reporting/
│   └── console.py        # Terminal formatting and output rendering
└── notifications/
    ├── template.py       # AlertMessage formatting
    ├── base.py           # BaseNotificationHook interface
    ├── engine.py         # NotificationEngine dispatcher
    └── hooks/            # Webhook integrations (Telegram, Discord, Slack, Generic)
```

---

## CLI Usage

```bash
# Standard network audit
sudo ./alien_hunter.py

# Deep scan (port inspection and anti-sniff verification)
sudo ./alien_hunter.py --deep

# Interactive whitelisting
sudo ./alien_hunter.py --whitelist

# Output in JSON format
sudo ./alien_hunter.py --json

# Run as background daemon (5-minute polling interval)
sudo ./alien_hunter.py --watch --interval 300
```

---

## Options

| Flag | Description |
| :--- | :--- |
| `-i, --interface <dev>` | Network interface to scan (default: auto-detected from route table). |
| `--deep` | Enables extended port scanning and promiscuous node detection. |
| `--whitelist` | Interactive prompt to label and trust unrecognized devices. |
| `-w, --watch` | Runs continuously in daemon mode with honey-port listeners. |
| `--interval <sec>` | Polling interval in seconds for daemon mode (default: `300`). |
| `--sync-db` | Updates `known_devices.json` with observed ports and services (default: enabled). |
| `--no-sync-db` | Disables automated database updates. |
| `--notify` | Dispatches notifications to configured hooks regardless of findings. |
| `--whitelist-file <path>` | Path to the `known_devices.json` database. |
| `--config-file <path>` | Path to `config.json`. |
| `--test-notify` | Sends a test notification through configured hooks. |
| `--ai` | Enables AI risk profiling. |
| `--no-ai` | Disables AI risk profiling. |
| `--test-ai` | Runs a test query against the configured AI provider. |
| `--json` | Outputs results in machine-readable JSON format. |

---

## Configuration

### 1. Trusted Whitelist (`known_devices.json`)
```bash
cp known_devices.json.example known_devices.json
```

Example schema:
```json
{
  "00:11:22:33:44:55": {
    "name": "Gateway Router",
    "owner": "Network Admin",
    "trusted": true,
    "primary_ip": "192.168.1.1",
    "aliases": [],
    "vendor": "Example Corp",
    "discovery_methods": ["Layer-2 ARP Scan", "mDNS (Multicast DNS)"],
    "services": ["_http._tcp.local"],
    "ports": ["80/HTTP", "443/HTTPS"],
    "last_seen": "2026-09-20T12:00:00Z"
  }
}
```

### 2. Daemon Configuration (`config.json`)
```bash
cp config.json.example config.json
```

Example schema:
```json
{
  "poll_interval_seconds": 300,
  "deep_scan_on_alert": true,
  "auto_sync_database": true,
  "defenses": {
    "llmnr_canary_enabled": true,
    "dns_integrity_enabled": true,
    "ipv6_guard_enabled": true,
    "port_drift_enabled": true,
    "honey_port_enabled": true,
    "honey_ports": [5555, 2323, 8888],
    "syn_scan_enabled": true,
    "dns_tunneling_enabled": true
  },
  "notifications": {
    "telegram": {
      "enabled": true,
      "bot_token": "TOKEN",
      "chat_id": "CHAT_ID"
    },
    "discord": {
      "enabled": false,
      "webhook_url": ""
    },
    "slack": {
      "enabled": false,
      "webhook_url": ""
    },
    "generic_webhook": {
      "enabled": false,
      "url": ""
    }
  },
  "ai_analysis": {
    "enabled": false,
    "provider": "ollama",
    "endpoint": "http://localhost:11434",
    "model": "qwen2.5:0.5b",
    "api_key": "",
    "timeout_seconds": 90,
    "analyze_on": "alien_only",
    "cache_results": true
  }
}
```

### 3. AI Providers
Supported values for `"provider"`:
* `ollama`: Local inference (e.g., `qwen2.5:0.5b`, `llama3.2:1b`). No API key required.
* `openai_compatible`: OpenAI-compatible endpoints (Groq, OpenAI, OpenRouter, DeepSeek, LM Studio). Set `"api_key"` if authentication is required.
* `anthropic`: Anthropic Messages API. Requires `"api_key"`.
* `gemini`: Google Gemini REST API. Requires `"api_key"`.

---

## Systemd Service

To run as a systemd service:

1. Install the service unit file:
   ```bash
   sudo cp systemd/alien-hunter.service.example /etc/systemd/system/alien-hunter.service
   ```
2. Set `WorkingDirectory` and `ExecStart` in `/etc/systemd/system/alien-hunter.service`.
3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now alien-hunter.service
   ```
4. View logs:
   ```bash
   journalctl -u alien-hunter.service -f
   ```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
