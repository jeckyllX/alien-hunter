"""
Threat Detection and Anomaly Analyzer Facade.
Coordinates detection of ARP spoofing, rogue DHCP servers, LLMNR poisoning,
DNS hijacking, rogue IPv6 gateways, remote promiscuous sniffers, and port drift.
"""

import subprocess
from typing import Any, Dict, List, Optional

from .defenses.llmnr_canary import LlmnrCanaryTrap
from .defenses.mdns_canary import MdnsCanaryTrap
from .defenses.dns_integrity import DnsIntegrityAuditor
from .defenses.ipv6_guard import Ipv6Guard
from .defenses.anti_sniff import AntiSniffDetector
from .defenses.port_drift import PortDriftTracker
from .defenses.syn_scan import SynScanDetector
from .defenses.dns_tunneling import DnsTunnelingDetector
from .defenses.dhcp_starvation import DhcpStarvationGuard
from .defenses.arp_poison import ArpPoisonGuard
from .defenses.rogue_dhcp import RogueDhcpGuard


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
        gateway_mac: Optional[str] = None,
        timeout: float = 2.0,
    ) -> List[str]:
        """
        Emits a canary DHCP Discover probe (UDP 67/68) and listens for rogue DHCP servers,
        unauthorized gateways, and DHCP hijacking attacks.
        """
        guard = RogueDhcpGuard(
            interface=interface,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
        )
        events = guard.probe_canary(timeout=timeout, canary_mac=local_mac)
        return [e.to_threat_string() for e in events]

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
    def check_mdns_poisoning(
        interface: Optional[str] = None,
        timeout: float = 1.0,
    ) -> List[str]:
        """
        Emits canary queries over Multicast DNS (mDNS UDP 5353) to detect active
        local name resolution poisoners (e.g. Responder / Inveigh).
        """
        return MdnsCanaryTrap.check_poisoning(
            interface=interface,
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

    @staticmethod
    def check_syn_scans(
        interface: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_mac: Optional[str] = None,
        duration: float = 1.0,
    ) -> List[str]:
        """
        Passively sniffs raw link frames to detect active stealth TCP SYN port scans.
        """
        detector = SynScanDetector(
            interface=interface,
            subnet_cidr=subnet_cidr,
            local_ip=local_ip,
            local_mac=local_mac,
        )
        events = detector.sniff(duration=duration)
        return [e.to_threat_string() for e in events]

    @staticmethod
    def check_dns_tunneling(
        interface: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_mac: Optional[str] = None,
        duration: float = 1.0,
    ) -> List[str]:
        """
        Passively sniffs UDP 53 DNS traffic to detect high-entropy tunneling and C2 exfiltration.
        """
        detector = DnsTunnelingDetector(
            interface=interface,
            subnet_cidr=subnet_cidr,
            local_ip=local_ip,
            local_mac=local_mac,
        )
        events = detector.sniff(duration=duration)
        return [e.to_threat_string() for e in events]

    @staticmethod
    def check_dhcp_starvation(
        interface: Optional[str] = None,
        duration: float = 1.0,
    ) -> List[str]:
        """
        Passively sniffs UDP 67/68 traffic to detect DHCP starvation and pool exhaustion attacks.
        """
        guard = DhcpStarvationGuard(interface=interface)
        events = guard.sniff(duration=duration)
        return [e.to_threat_string() for e in events]

    @staticmethod
    def check_realtime_arp_poisoning(
        interface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        trusted_ip_mac_map: Optional[Dict[str, str]] = None,
        duration: float = 1.0,
    ) -> List[str]:
        """
        Passively sniffs raw Layer-2 ARP traffic to detect active ARP cache poisoning and gateway spoofing.
        """
        guard = ArpPoisonGuard(
            interface=interface,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            trusted_ip_mac_map=trusted_ip_mac_map,
        )
        events = guard.sniff(duration=duration)
        return [e.to_threat_string() for e in events]


