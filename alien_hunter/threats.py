"""
Threat Detection and Anomaly Analyzer Facade.
Coordinates detection of ARP spoofing, rogue DHCP servers, LLMNR poisoning,
DNS hijacking, rogue IPv6 gateways, remote promiscuous sniffers, and port drift.
"""

import subprocess
from typing import Any, Dict, List, Optional

from .defenses.llmnr_canary import LlmnrCanaryTrap
from .defenses.dns_integrity import DnsIntegrityAuditor
from .defenses.ipv6_guard import Ipv6Guard
from .defenses.anti_sniff import AntiSniffDetector
from .defenses.port_drift import PortDriftTracker


class ThreatDetector:
    """
    Unified defensive facade evaluating network telemetry to detect active attacks,
    poisoning vectors, and device compromises.
    """

    @staticmethod
    def check_arp_spoofing(
        active_devices: Dict[str, str], gateway_ip: Optional[str], gateway_mac: Optional[str]
    ) -> List[str]:
        """
        Detects ARP Cache Poisoning or Rogue Gateways where another MAC address
        claims ownership of the default gateway IP.
        """
        threats: List[str] = []
        if not gateway_ip or not gateway_mac:
            return threats

        for ip, mac in active_devices.items():
            if ip == gateway_ip and mac.upper() != gateway_mac.upper():
                threats.append(
                    f"CRITICAL: ARP Spoofing / Rogue Gateway detected! "
                    f"Hardware MAC {mac} is masquerading as Gateway {gateway_ip} (Expected: {gateway_mac})!"
                )

        return threats

    @staticmethod
    def check_wifi_threats(current_ssid: Optional[str] = None) -> List[str]:
        """
        Audits nearby wireless airspace using nmcli to detect duplicate SSIDs
        or Rogue Access Points (Evil Twin attack).
        """
        threats: List[str] = []
        if not current_ssid:
            return threats

        try:
            res = subprocess.run(
                ["nmcli", "-f", "BSSID,SSID,CHAN,SECURITY,SIGNAL", "dev", "wifi", "list"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                lines = res.stdout.strip().splitlines()
                seen_bssids = []
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        bssid, ssid = parts[0], parts[1]
                        if ssid == current_ssid:
                            seen_bssids.append(bssid)

                # Standard dual-band routers broadcast on at most 2 BSSIDs (2.4GHz & 5GHz)
                if len(seen_bssids) > 2:
                    threats.append(
                        f"Potential Rogue AP / Evil Twin: Discovered {len(seen_bssids)} "
                        f"access points broadcasting '{current_ssid}'."
                    )
        except Exception:
            pass

        return threats

    @staticmethod
    def check_rogue_dhcp(
        interface: Optional[str] = None,
        local_mac: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        timeout: float = 2.0,
    ) -> List[str]:
        """
        Broadcasts a DHCP Discover probe (UDP 67/68) to discover active DHCP servers.
        Detects Rogue DHCP servers, unauthorized gateways, and DHCP hijacking attacks.
        """
        import os
        import socket
        import time
        from .scanners.net_utils import create_udp_socket

        threats: List[str] = []
        sock = None

        try:
            sock = create_udp_socket(interface=interface, timeout=0.5)
            sock.bind(("0.0.0.0", 68))

            mac_bytes = b"\x00" * 6
            if local_mac:
                try:
                    cleaned_mac = local_mac.replace(":", "").replace("-", "")
                    if len(cleaned_mac) == 12:
                        mac_bytes = bytes.fromhex(cleaned_mac)
                except Exception:
                    pass
            if mac_bytes == b"\x00" * 6:
                mac_bytes = b"\x02\x42" + os.urandom(4)

            xid = os.urandom(4)
            pkt = bytearray(240)
            pkt[0] = 1  # BOOTREQUEST
            pkt[1] = 1  # HTYPE: 10mb ethernet
            pkt[2] = 6  # HLEN: 6 bytes mac
            pkt[3] = 0  # HOPS
            pkt[4:8] = xid
            pkt[8:10] = b"\x00\x00"  # SECS
            pkt[10:12] = b"\x80\x00"  # FLAGS: Broadcast
            pkt[12:16] = b"\x00\x00\x00\x00"  # CIADDR
            pkt[16:20] = b"\x00\x00\x00\x00"  # YIADDR
            pkt[20:24] = b"\x00\x00\x00\x00"  # SIADDR
            pkt[24:28] = b"\x00\x00\x00\x00"  # GIADDR
            pkt[28 : 28 + len(mac_bytes)] = mac_bytes
            pkt[236:240] = b"\x63\x82\x53\x63"  # Magic cookie

            pkt.extend(b"\x35\x01\x01")  # Option 53: DHCP Discover
            pkt.extend(b"\x37\x04\x01\x03\x06\x36")  # Option 55: Parameter Request List
            pkt.extend(b"\xff")  # Option 255: End of options

            sock.sendto(pkt, ("255.255.255.255", 67))

            observed_servers: Dict[str, Dict[str, str]] = {}
            start = time.time()

            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(2048)
                    if len(data) < 240 or data[4:8] != xid:
                        continue

                    options = data[240:]
                    opt_dict: Dict[int, bytes] = {}
                    idx = 0
                    while idx < len(options):
                        opt = options[idx]
                        if opt == 255:
                            break
                        if opt == 0:
                            idx += 1
                            continue
                        if idx + 1 >= len(options):
                            break
                        opt_len = options[idx + 1]
                        opt_val = options[idx + 2 : idx + 2 + opt_len]
                        opt_dict[opt] = opt_val
                        idx += 2 + opt_len

                    msg_type = opt_dict.get(53)
                    if not msg_type or msg_type[0] != 2:
                        continue

                    server_ip = addr[0]
                    if 54 in opt_dict and len(opt_dict[54]) == 4:
                        server_ip = socket.inet_ntoa(opt_dict[54])

                    router_ip = ""
                    if 3 in opt_dict and len(opt_dict[3]) >= 4:
                        router_ip = socket.inet_ntoa(opt_dict[3][:4])

                    offered_ip = socket.inet_ntoa(data[16:20])

                    observed_servers[server_ip] = {
                        "offered_ip": offered_ip,
                        "router": router_ip,
                        "relay_or_source": addr[0],
                    }

                except socket.timeout:
                    continue
                except Exception:
                    break

            for srv_ip, srv_details in observed_servers.items():
                offered_router = srv_details.get("router", "")
                offered_ip = srv_details.get("offered_ip", "")

                if gateway_ip and srv_ip != gateway_ip and srv_details.get("relay_or_source") != gateway_ip:
                    threats.append(
                        f"CRITICAL: Rogue DHCP Server detected! Server at {srv_ip} offered lease {offered_ip} "
                        f"(Advertised Router: {offered_router or 'None'}, Legitimate Gateway: {gateway_ip})! "
                        f"Potential Man-in-the-Middle or rogue router on the network."
                    )
                elif gateway_ip and offered_router and offered_router != gateway_ip:
                    threats.append(
                        f"CRITICAL: DHCP Gateway Hijacking detected! DHCP Server {srv_ip} is offering default "
                        f"gateway {offered_router} (Expected legitimate Gateway: {gateway_ip})!"
                    )

            if len(observed_servers) > 1:
                server_list = ", ".join(sorted(observed_servers.keys()))
                threats.append(
                    f"WARNING: Multiple DHCP Servers active on the local link: {server_list}. "
                    f"Rogue or redundant DHCP services can cause IP address conflicts and session hijacking."
                )

        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return threats

    @staticmethod
    def check_llmnr_poisoning(
        interface: Optional[str] = None,
        subnet_broadcast: Optional[str] = None,
        timeout: float = 1.0,
    ) -> List[str]:
        """
        Emits canary queries over LLMNR and NetBIOS-NS to detect active
        credential harvesting and poisoners (Responder / Inveigh).
        """
        return LlmnrCanaryTrap.check_poisoning(
            interface=interface,
            subnet_broadcast=subnet_broadcast,
            timeout=timeout,
        )

    @staticmethod
    def check_dns_integrity(
        gateway_ip: Optional[str] = None,
        custom_resolver: Optional[str] = None,
    ) -> List[str]:
        """
        Audits local DNS resolution against trusted upstreams for cache poisoning
        and RFC 1918 private IP hijacking.
        """
        return DnsIntegrityAuditor.audit_dns(
            gateway_ip=gateway_ip,
            custom_resolver=custom_resolver,
        )

    @staticmethod
    def check_rogue_ipv6_ra(
        interface: Optional[str] = None,
        expected_gateway_ipv6: Optional[str] = None,
        timeout: float = 1.0,
    ) -> List[str]:
        """
        Audits local link for unauthorized IPv6 Router Advertisements and mitm6 attacks.
        """
        return Ipv6Guard.check_rogue_ra(
            interface=interface,
            expected_gateway_ipv6=expected_gateway_ipv6,
            timeout=timeout,
        )

    @staticmethod
    def check_promiscuous_hosts(
        interface: str,
        local_ip: str,
        local_mac: str,
        target_hosts: Dict[str, str],
        timeout_per_host: float = 0.3,
    ) -> List[str]:
        """
        Sends anti-sniff probes to detect remote network cards operating in promiscuous mode.
        """
        return AntiSniffDetector.check_promiscuous_hosts(
            interface=interface,
            local_ip=local_ip,
            local_mac=local_mac,
            target_hosts=target_hosts,
            timeout_per_host=timeout_per_host,
        )

    @staticmethod
    def check_port_drift(
        ip: str,
        mac: str,
        display_name: str,
        current_open_ports: List[str],
        whitelist_entry: Optional[Dict[str, Any]] = None,
        cached_baseline: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Evaluates device open ports against established baseline to flag post-compromise drift.
        """
        return PortDriftTracker.check_device_drift(
            ip=ip,
            mac=mac,
            display_name=display_name,
            current_open_ports=current_open_ports,
            whitelist_entry=whitelist_entry,
            cached_baseline=cached_baseline,
        )
