"""
Layer-2 ARP Hardware Scanner.
Uses arp-scan or system neighbor tables to discover physical hosts on the local network link.
"""

import json
import re
import subprocess
from typing import Dict, Optional


class ArpScanner:
    """Discovers responsive hosts at Layer 2 (Data Link Layer) across the local subnet."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface

    def scan(self) -> Dict[str, str]:
        """
        Executes an ARP sweep across the local network link.
        Returns a mapping of {IP_ADDRESS: MAC_ADDRESS}.
        """
        devices: Dict[str, str] = {}

        # Primary approach: arp-scan
        try:
            cmd = ["arp-scan"]
            if self.interface:
                cmd.extend(["-I", self.interface])
            cmd.append("--localnet")

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    match = re.match(r"^([0-9.]+)\s+([0-9a-fA-F:]{17})", line)
                    if match:
                        devices[match.group(1)] = match.group(2).upper()
                if devices:
                    return devices
        except Exception:
            pass

        # Secondary fallback: Linux kernel neighbor table (ip neigh)
        try:
            cmd_neigh = ["ip", "-json", "neigh", "show"]
            if self.interface:
                cmd_neigh.extend(["dev", self.interface])

            res = subprocess.run(
                cmd_neigh,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.stdout:
                entries = json.loads(res.stdout)
                for entry in entries:
                    ip = entry.get("dst")
                    mac = entry.get("lladdr")
                    state = entry.get("state", [])
                    if ip and mac and "FAILED" not in state:
                        devices[ip] = mac.upper()
        except Exception:
            pass

        # Tertiary fallback: /proc/net/arp
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip, hw_type, flags, mac, mask, dev = parts[:6]
                        if dev == self.interface and mac != "00:00:00:00:00:00":
                            devices[ip] = mac.upper()
        except Exception:
            pass

        return devices
