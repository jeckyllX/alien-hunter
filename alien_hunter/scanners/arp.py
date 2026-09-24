"""
Layer-2 ARP Hardware Scanner.
Discovers physical hosts on the local network link using native raw sockets (AF_PACKET),
falling back to arp-scan and Linux kernel neighbor tables.
"""

import ipaddress
import json
import os
import re
import select
import socket
import struct
import subprocess
import time
from typing import Dict, Optional


class NativeArpSweeper:
    """
    Pure standard-library Layer-2 ARP broadcast scanner using Linux raw sockets.
    Requires root or CAP_NET_RAW capability.
    """

    @staticmethod
    def sweep(
        interface: str,
        local_mac: str,
        local_ip: str,
        subnet_cidr: str,
        timeout: float = 1.2,
        candidate_targets: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Broadcasts ARP requests across subnet_cidr and unicasts ARP to candidate_targets.
        Gathers unicast replies and returns a mapping of {IP_ADDRESS: MAC_ADDRESS}.
        """
        devices: Dict[str, str] = {}
        sock = None
        try:
            net = ipaddress.ip_network(subnet_cidr, strict=False)
            mac_clean = local_mac.replace(":", "").replace("-", "")
            if len(mac_clean) != 12:
                return devices
            local_mac_bytes = bytes.fromhex(mac_clean)
            sender_ip_bytes = socket.inet_aton(local_ip)

            # Open Linux raw socket bound to ARP protocol (0x0806)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            sock.bind((interface, 0))
            sock.setblocking(False)

            eth_header = b"\xff\xff\xff\xff\xff\xff" + local_mac_bytes + struct.pack("!H", 0x0806)

            # 1. Unicast ARP probes to candidate targets (bypasses Wi-Fi AP broadcast suppression)
            if candidate_targets:
                for cand_ip, cand_mac in candidate_targets.items():
                    if cand_ip == local_ip:
                        continue
                    try:
                        clean_cmac = cand_mac.replace(":", "").replace("-", "")
                        if len(clean_cmac) != 12:
                            continue
                        target_mac_bytes = bytes.fromhex(clean_cmac)
                        u_eth = target_mac_bytes + local_mac_bytes + struct.pack("!H", 0x0806)
                        u_arp = struct.pack(
                            "!HHBBH6s4s6s4s",
                            1,
                            0x0800,
                            6,
                            4,
                            1,
                            local_mac_bytes,
                            sender_ip_bytes,
                            target_mac_bytes,
                            socket.inet_aton(cand_ip),
                        )
                        sock.send(u_eth + u_arp)
                    except Exception:
                        pass

            # 2. Broadcast ARP requests across subnet
            host_count = 0
            for host in net.hosts():
                target_ip = str(host)
                if target_ip == local_ip:
                    continue

                # ARP Request packet (RFC 826): HTYPE=1, PTYPE=0x0800, HLEN=6, PLEN=4, OPER=1
                arp_packet = struct.pack(
                    "!HHBBH6s4s6s4s",
                    1,
                    0x0800,
                    6,
                    4,
                    1,
                    local_mac_bytes,
                    sender_ip_bytes,
                    b"\x00" * 6,
                    socket.inet_aton(target_ip),
                )
                try:
                    sock.send(eth_header + arp_packet)
                except Exception:
                    pass

                host_count += 1
                if host_count >= 512:
                    break

            # Listen for ARP replies
            deadline = time.time() + timeout
            while time.time() < deadline:
                remaining = max(0.0, deadline - time.time())
                readable, _, _ = select.select([sock], [], [], min(remaining, 0.2))
                if not readable:
                    continue

                while True:
                    try:
                        data, _ = sock.recvfrom(2048)
                        if len(data) >= 42:
                            eth_type = struct.unpack("!H", data[12:14])[0]
                            opcode = struct.unpack("!H", data[20:22])[0]
                            if eth_type == 0x0806 and opcode == 2:  # ARP Reply
                                sender_ip = socket.inet_ntoa(data[28:32])
                                sender_mac = ":".join(f"{b:02X}" for b in data[22:28])
                                if sender_ip != local_ip and sender_mac != "00:00:00:00:00:00":
                                    devices[sender_ip] = sender_mac
                    except (BlockingIOError, socket.error):
                        break

        except (PermissionError, OSError):
            # Fall back to alternative discovery methods if raw sockets are unavailable
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return devices


class ArpScanner:
    """Discovers responsive hosts at Layer 2 (Data Link Layer) across the local subnet."""

    def __init__(
        self,
        interface: Optional[str] = None,
        local_mac: Optional[str] = None,
        local_ip: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
    ):
        self.interface = interface
        self.local_mac = local_mac or self._resolve_local_mac(interface)
        self.local_ip = local_ip or self._resolve_local_ip(interface)
        self.subnet_cidr = subnet_cidr

    @staticmethod
    def _resolve_local_mac(interface: Optional[str]) -> Optional[str]:
        if not interface:
            return None
        sys_path = f"/sys/class/net/{interface}/address"
        if os.path.exists(sys_path):
            try:
                with open(sys_path, "r", encoding="utf-8") as f:
                    val = f.read().strip().upper()
                    if val and val != "00:00:00:00:00:00":
                        return val
            except Exception:
                pass
        return None

    @staticmethod
    def _resolve_local_ip(interface: Optional[str]) -> Optional[str]:
        if not interface:
            return None
        try:
            import fcntl
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip = socket.inet_ntoa(
                fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack("256s", interface[:15].encode("utf-8")),
                )[20:24]
            )
            s.close()
            return ip
        except Exception:
            return None

    def scan(self, candidate_targets: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Executes an ARP sweep across the local network link.
        Returns a mapping of {IP_ADDRESS: MAC_ADDRESS}.
        """
        devices: Dict[str, str] = {}

        # 1. Native raw socket ARP sweep (Zero dependencies)
        if self.interface and self.local_mac and self.local_ip and self.subnet_cidr:
            merged_candidates = dict(candidate_targets or {})
            try:
                cmd_neigh = ["ip", "-json", "neigh", "show"]
                if self.interface:
                    cmd_neigh.extend(["dev", self.interface])
                res = subprocess.run(cmd_neigh, capture_output=True, text=True, timeout=3)
                if res.stdout:
                    for entry in json.loads(res.stdout):
                        ip = entry.get("dst")
                        mac = entry.get("lladdr")
                        state = entry.get("state", [])
                        if ip and mac and "FAILED" not in state and "INCOMPLETE" not in state:
                            if ip not in merged_candidates:
                                merged_candidates[ip] = mac.upper()
            except Exception:
                pass

            native_devices = NativeArpSweeper.sweep(
                interface=self.interface,
                local_mac=self.local_mac,
                local_ip=self.local_ip,
                subnet_cidr=self.subnet_cidr,
                timeout=1.2,
                candidate_targets=merged_candidates,
            )
            if native_devices:
                devices.update(native_devices)

        # 2. arp-scan fallback if available and native scan found few or no results
        if not devices:
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
            except Exception:
                pass

        # 3. Kernel neighbor table enrichment (only for REACHABLE / PERMANENT entries)
        try:
            cmd_neigh = ["ip", "-json", "neigh", "show"]
            if self.interface:
                cmd_neigh.extend(["dev", self.interface])

            res = subprocess.run(
                cmd_neigh,
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.stdout:
                entries = json.loads(res.stdout)
                for entry in entries:
                    ip = entry.get("dst")
                    mac = entry.get("lladdr")
                    state = entry.get("state", [])
                    if not ip or not mac:
                        continue
                    if "FAILED" in state or "INCOMPLETE" in state:
                        continue
                    # When active sweep ran, only accept explicitly confirmed REACHABLE or PERMANENT hosts
                    if devices:
                        if "REACHABLE" in state or "PERMANENT" in state:
                            if ip not in devices:
                                devices[ip] = mac.upper()
                    else:
                        # Fallback when raw sockets and arp-scan were unavailable
                        if ip not in devices:
                            devices[ip] = mac.upper()
        except Exception:
            pass

        # 4. /proc/net/arp fallback (only if devices is empty, requiring ATF_COM 0x2 flag)
        if not devices:
            try:
                with open("/proc/net/arp", "r", encoding="utf-8") as f:
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 6:
                            ip, hw_type, flags, mac, mask, dev = parts[:6]
                            try:
                                flags_int = int(flags, 16)
                            except ValueError:
                                continue
                            if not (flags_int & 0x02):  # ATF_COM (0x02) - Completed entry
                                continue
                            if (not self.interface or dev == self.interface) and mac != "00:00:00:00:00:00":
                                if ip not in devices:
                                    devices[ip] = mac.upper()
            except Exception:
                pass

        return devices
