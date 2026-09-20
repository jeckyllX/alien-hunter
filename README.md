# 🛸 Alien Hunter (`alien-hunter`)

> **Comprehensive LAN Security Auditor & Stealth Device Hunter**  
> Uncover hidden, sleeping, and unauthorized devices on your local network that bypass standard ping sweeps.

---

## 🔍 The Problem With Standard Network Scanners

Most common network discovery tools (and simple `ping` sweep scripts) fail to see active devices on modern local networks:
1. **Aggressive Mobile Power Management:** Modern smartphones (**iPhones & Android**) put their Wi-Fi chips into deep sleep when the screen is locked to save battery, silently dropping all ICMP ping requests.
2. **Built-in Firewalls:** Windows Defender and macOS default firewalls drop unsolicited incoming echo requests.
3. **Randomized MAC Addresses:** Modern operating systems randomize their hardware MAC addresses for privacy, masking device manufacturers.
4. **Stealth Out-of-Subnet Transmitters:** Rogue hardware or misconfigured devices configured with static IPs outside your subnet are invisible to standard IP sweeps.

---

## 🛡️ How Alien Hunter Solves This

Alien Hunter combines multi-layered active reconnaissance and real-time intrusion defenses to achieve near-100% network visibility:

### Multi-Protocol Device Discovery
* **Layer-2 ARP Hardware Sweeps:** Bypasses OS-level host firewalls and probes the physical data link layer using raw ARP frames.
* **Gateway DHCP & DNS Reverse Lease Audit:** Directly interrogates your router's DNS server (`gateway:53`) for reverse pointer records (`PTR`), unmasking registered hostnames even when the device is asleep or firewalled.
* **Multicast DNS (mDNS / DNS-SD / Bonjour):** Audits UDP 5353 (`224.0.0.251`) to discover Apple devices, Google Cast/Nest, smart TVs, IoT peripherals, and TR-369 router agents.
* **WS-Discovery (SOAP Probes):** Discovers modern Windows 10/11 endpoints, ONVIF surveillance cameras, and NAS appliances over UDP 3702 (`239.255.255.250`).
* **NetBIOS & SSDP / UPnP Scanning:** Queries Windows/Samba workstations (`UDP 137`) and UPnP media renderers (`UDP 1900`).
* **Specialized Apple Device Identifier:** Combines Bonjour records, OUI databases, and DHCP Option 12 client identifiers to extract human-readable names for **Apple Macs, iPhones, Apple Watches, and iPads** (e.g. *Apple iPhone "Alex's iPhone"*).
* **Passive Promiscuous Frame Sniffer:** Listens for raw Layer-2 Ethernet frames to catch silent transmitters or rogue hosts with out-of-subnet static IPs.

### Active Defenses & Intrusion Detection (IDS)
* **LLMNR / NBT-NS Poisoning Canary Trap ("Anti-Responder"):** Emits canary broadcast queries for randomized, non-existent hostnames. Any incoming reply deterministically catches active credential harvesters (*Responder*, *Inveigh*) with 100% true-positive accuracy.
* **Rogue IPv6 Router Advertisement & `mitm6` Guard:** Listens on `ff02::1` for rogue ICMPv6 Type 134 Router Advertisements and spoofed DNS assignments that silently hijack LAN traffic.
* **DNS Integrity & Cache Poisoning Auditor:** Cross-verifies gateway DNS resolution against cryptographic upstreams (Cloudflare `1.1.1.1` & Quad9 `9.9.9.9`) to flag cache poisoning, rogue relays, and RFC 1918 private leaks.
* **Decoy Honey-Port Canary Listener:** Binds lightweight non-blocking decoy listeners (e.g. TCP 23, 5555) in 24/7 watch mode to immediately trap internal port scans and worm propagation.
* **Port Drift & Compromise Tracker:** Detects post-compromise behavior by comparing open ports against the historical baseline in `known_devices.json` (e.g. smart bulbs suddenly exposing SSH or Telnet).
* **Remote Promiscuous Node Detection (Anti-Sniff):** Sends hardware MAC filter bypass ARP probes to detect silent unauthorized sniffing taps on the LAN.
* **Rogue DHCP Server & Gateway Hijacking Guard:** Probes UDP 67/68 to catch unauthorized DHCP servers or malicious gateway route offerings.
* **Whitelist & Alien Alerting:** Compares discovered devices against a trusted whitelist (`known_devices.json`). Any unrecognized hardware is immediately flagged as **`ALIEN`**.
* **Ultra-Lightweight & Zero Third-Party Dependencies:** Built strictly with the Python Standard Library and native Linux networking tools. Starts instantly with a tiny memory footprint (<15 MB RAM), ideal for 24/7 background monitoring on low-power hardware like a Raspberry Pi.
* **24/7 Sentinel Watch Mode with Webhooks:** Continuously monitors your LAN in the background and dispatches instant alert notifications to **Discord, Telegram, Slack, or generic webhooks** the moment an unauthorized device joins or an active threat is detected.

---

## 🚀 Installation & Prerequisites

### Prerequisites
* Linux OS (Debian, Ubuntu, Raspberry Pi OS, Arch, etc.)
* Python 3.7+ (**Pure Standard Library** — no third-party pip dependencies required)
* `arp-scan` (optional Layer-2 hardware scanner):
  ```bash
  # Debian / Ubuntu / Raspberry Pi OS
  sudo apt-get install -y arp-scan
  ```

### Quick Installation (Automated)
```bash
git clone https://github.com/jekyll86/alien-hunter.git
cd alien-hunter
sudo ./install.sh
```
The installer checks for `arp-scan`, symlinks `/usr/local/bin/alien-hunter`, initializes config templates, and configures the `alien-hunter.service` systemd daemon pointing to your directory.

### Manual / Developer Setup
```bash
git clone https://github.com/jekyll86/alien-hunter.git
cd alien-hunter
chmod +x alien_hunter.py

# Option 1: Run directly
./alien_hunter.py

# Option 2: Run as Python module
python3 -m alien_hunter

# Option 3: Install as editable pip package
pip install -e .
```

---

## 🏗️ Architecture

Alien Hunter follows clean, modular software engineering principles with strong separation of concerns:

```text
alien_hunter/
├── models.py             # Strongly-typed domain models (Device, NetworkInfo, AuditResult)
├── config.py             # ConfigManager (generic path resolution, whitelist persistence)
├── threats.py            # ThreatDetector (unified GoF facade delegating to modular defenses)
├── cli.py                # Command-line interface parser & audit execution flow
├── core/
│   ├── engine.py         # DiscoveryEngine (orchestrates multi-protocol discovery)
│   └── sentinel.py       # SentinelWatchdog (24/7 background polling, honey-ports & alerting)
├── defenses/             # Dedicated defensive subsystems & IDS traps
│   ├── llmnr_canary.py   # Canary query generator for LLMNR & NetBIOS (Anti-Responder)
│   ├── ipv6_guard.py     # ICMPv6 RA & RDNSS inspector guarding against mitm6
│   ├── dns_integrity.py  # Gateway DNS cache poisoning & RFC 1918 private leak auditor
│   ├── honey_port.py     # Non-blocking decoy TCP listener trapping internal port scans
│   ├── port_drift.py     # Port drift & baseline anomaly tracker for trusted hosts
│   └── anti_sniff.py     # Non-broadcast group MAC ARP probe detecting promiscuous nodes
├── scanners/             # Multi-protocol active & passive network scanners
│   ├── arp.py            # Layer-2 hardware discovery via arp-scan & kernel tables
│   ├── mdns.py           # Multicast DNS (mDNS / DNS-SD / Bonjour) discovery scanner
│   ├── ws_discovery.py   # OASIS WS-Discovery SOAP probe scanner (Windows 10/11, ONVIF)
│   ├── netbios.py        # NetBIOS Name Service Node Status scanner (UDP 137)
│   ├── ssdp.py           # SSDP / UPnP M-SEARCH multicast discovery scanner (UDP 1900)
│   ├── router.py         # Gateway DNS/DHCP reverse PTR lease auditor (UDP 53)
│   ├── sniffer.py        # Subnet-aware passive raw Ethernet frame sniffer (promiscuous mode)
│   ├── ports.py          # Vulnerability inspector & security port signature scanner
│   └── net_utils.py      # Low-level cross-platform socket creation & broadcast helpers
├── identifiers/          # Hardware & vendor fingerprinting
│   ├── apple.py          # Specialized Apple device identifier (Bonjour + OUI + DHCP)
│   └── vendor.py         # IEEE OUI MAC vendor resolver with offline caching
├── ai/                   # Modular AI Risk & Security Posture Assessment
│   ├── engine.py         # AiAnalysisEngine (orchestrates device & posture analysis)
│   ├── base.py           # BaseAiProvider (abstract adapter class)
│   ├── models.py         # AiDeviceAssessment & AiNetworkPosture dataclasses
│   └── providers/        # Provider implementations (Ollama, OpenAI-compatible, Anthropic, Gemini)
├── reporting/
│   └── console.py        # ANSI terminal tables, summaries & interactive prompt
└── notifications/
    ├── template.py       # Reusable AlertMessage formatter with detector attribution
    ├── base.py           # BaseNotificationHook (abstract class)
    ├── engine.py         # NotificationEngine (registry-based dynamic hook dispatcher)
    └── hooks/
        ├── telegram.py   # TelegramHook (Official Telegram Bot API)
        ├── discord.py    # DiscordHook (Discord rich embeds)
        ├── slack.py      # SlackHook (Slack BlockKit)
        └── generic.py    # GenericWebhookHook (Raw HTTP POST JSON)
```

---

## 💻 Usage

Alien Hunter auto-elevates with `sudo` when needed for raw socket and Layer-2 operations.

```bash
# Standard comprehensive audit
./alien_hunter.py

# Deep security scan (inspects high-risk ports and exposed databases)
./alien_hunter.py --deep

# Interactive whitelisting mode (prompts you to trust and name newly discovered devices)
./alien_hunter.py --whitelist

# Output in JSON format (ideal for scripts or SIEM pipelines)
./alien_hunter.py --json

# Run in 24/7 Sentinel Watchdog mode (checks every 5 minutes)
./alien_hunter.py --watch --interval 300
```

---

## 📋 Command-Line Options

| Flag | Description |
| :--- | :--- |
| `-i, --interface <dev>` | Network interface to scan (default: auto-detected default route or active link). |
| `--deep` | Performs deep port scanning and enables remote promiscuous node detection (`AntiSniffDetector`). |
| `--whitelist` | Interactively prompts to add unrecognized alien devices to `known_devices.json`. |
| `--watch`, `-w` | Runs continuously in daemon / sentinel mode with active honey-port canary listeners. |
| `--interval <sec>` | Polling interval in seconds for watch mode (default: `300`). |
| `--sync-db` | Automatically enriches `known_devices.json` with observed aliases, services, ports, and timestamps. |
| `--no-sync-db` | Disables automated inventory synchronization to `known_devices.json`. |
| `--notify` | Dispatches alert notifications to active hooks even if all devices are trusted. |
| `--whitelist-file <path>` | Custom path to the trusted devices JSON database. |
| `--config-file <path>` | Custom path to the configuration JSON file. |
| `--test-notify` | Sends a simulated test alert through configured notification hooks. |
| `--ai` | Enables AI device profiling and network posture assessment. |
| `--no-ai` | Disables AI profiling (forces pure deterministic scanning). |
| `--test-ai` | Tests the configured AI provider with a simulated device and posture check. |
| `--json` | Outputs complete scan results in machine-readable JSON format. |

---

## ⚙️ Configuration

### 1. Trusted Whitelist & Device Database (`known_devices.json`)
Copy the provided template to create your local whitelist:
```bash
cp known_devices.json.example known_devices.json
```
Edit `known_devices.json` with your authorized devices. When `--sync-db` is active (default), Alien Hunter enriches each host with live observed telemetry without overwriting your custom `name` or `owner` attributes:
```json
{
  "AA:BB:CC:DD:EE:FF": {
    "name": "My Router",
    "owner": "Admin",
    "trusted": true,
    "primary_ip": "192.168.1.1",
    "aliases": ["192.168.1.254"],
    "vendor": "Example Gateway Corp",
    "discovery_methods": [
      "Layer-2 ARP Scan",
      "Passive Frame Sniffer (Promiscuous Mode)",
      "mDNS (Multicast DNS)"
    ],
    "services": ["_http._tcp.local"],
    "ports": ["80/HTTP", "443/HTTPS"],
    "last_seen": "2026-09-19T15:37:37Z"
  },
  "11:22:33:44:55:66": {
    "name": "Work Laptop",
    "owner": "Self",
    "trusted": true,
    "primary_ip": "192.168.1.50"
  }
}
```
*(Note: `known_devices.json` is ignored by `.gitignore` so your private hardware addresses are never committed).*

### 2. Notifications & Sentinel Defenses (`config.json`)
Alien Hunter features a modular notification engine and customizable canary decoy ports. You can enable any combination of hooks simultaneously (Telegram, Discord, Slack, or generic webhooks).

Copy `config.json.example` to `config.json`:
```bash
cp config.json.example config.json
```

```json
{
  "poll_interval_seconds": 300,
  "deep_scan_on_alert": true,
  "auto_sync_database": true,
  "honey_ports": [23, 5555],
  "notifications": {
    "telegram": {
      "enabled": true,
      "bot_token": "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ",
      "chat_id": "987654321"
    },
    "discord": {
      "enabled": false,
      "webhook_url": "https://discord.com/api/webhooks/YOUR_DISCORD_WEBHOOK_URL"
    },
    "slack": {
      "enabled": false,
      "webhook_url": "https://hooks.slack.com/services/YOUR_SLACK_WEBHOOK_URL"
    },
    "generic_webhook": {
      "enabled": false,
      "url": "https://example.com/api/lan-alerts"
    }
  },
  "ai_analysis": {
    "enabled": false,
    "provider": "ollama",
    "endpoint": "http://localhost:11434",
    "model": "qwen2.5:0.5b",
    "timeout_seconds": 90,
    "analyze_on": "alien_only",
    "cache_results": true
  }
}
```

### 3. AI Security Profiling & Network Posture Assessment
Alien Hunter features a modular AI provider adapter that automatically synthesizes device open ports, vendors, and network threats into human-readable risk assessments and whitelisting recommendations.

Supported AI providers (configured via `"provider"` in `config.json`):
* **`ollama`**: Local private inference (`qwen2.5:0.5b`, `llama3.2:1b`, etc.). Endpoint defaults to `http://localhost:11434`.
* **`openai_compatible`**: Universal standard for [Groq](https://groq.com) (free/ultra-fast), [OpenAI](https://openai.com), [OpenRouter](https://openrouter.ai), DeepSeek, or LM Studio.
* **`anthropic`**: Anthropic Claude API (`claude-3-5-haiku`).
* **`gemini`**: Google Gemini REST API (`gemini-1.5-flash`).

Test your AI configuration anytime:
```bash
python3 alien_hunter.py --test-ai
```

#### Setting up Free Telegram Alerts:
1. Message `@BotFather` on Telegram and send `/newbot` to create a free bot. Copy the generated **bot token**.
2. Message `@userinfobot` on Telegram to get your numerical **chat ID**.
3. Add your `bot_token` and `chat_id` under `notifications.telegram` in `config.json`.
4. Press **Start** on your new bot in Telegram. Alien Hunter will now send instant intrusion alerts to your phone!

---

## 🔄 Running as a 24/7 Background Service (Systemd)

To make Alien Hunter run automatically in the background on a Raspberry Pi or Linux server:

1. Copy the example service file:
   ```bash
   sudo cp systemd/alien-hunter.service.example /etc/systemd/system/alien-hunter.service
   ```
2. Edit `/etc/systemd/system/alien-hunter.service` to match your installation path.
3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now alien-hunter.service
   ```
4. View live intrusion logs:
   ```bash
   journalctl -u alien-hunter.service -f
   ```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
