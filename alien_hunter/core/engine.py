"""
Core Discovery and Audit Engine for Alien Hunter.
Coordinates network context resolution, multi-layered device discovery,
vendor resolution, Apple heuristics, port auditing, and threat detection.
"""

import json
import subprocess
import time
from typing import Dict, List, Optional, Set, Tuple, Any

from ..models import Device, NetworkInfo, AuditResult
from ..scanners.arp import ArpScanner
from ..scanners.router import RouterDnsAuditor
from ..scanners.sniffer import PassiveFrameSniffer
from ..scanners.ports import PortScanner
from ..scanners.ssdp import SsdpScanner
from ..scanners.netbios import NetbiosScanner
from ..scanners.mdns import MdnsScanner
from ..scanners.ws_discovery import WsDiscoveryScanner
from ..identifiers.vendor import MacVendorResolver
from ..identifiers.apple import AppleDeviceIdentifier
from ..threats import ThreatDetector



class DiscoveryEngine:
    """Orchestrates comprehensive discovery and vulnerability auditing across the local network."""

    def __init__(
        self,
        mac_api_url: Optional[str] = None,
        mac_api_timeout: Optional[float] = None,
    ):
        resolver_kwargs = {}
        if mac_api_url:
            resolver_kwargs["api_url"] = mac_api_url
        if mac_api_timeout:
            resolver_kwargs["timeout"] = mac_api_timeout

        self.vendor_resolver = MacVendorResolver(**resolver_kwargs)
        self.apple_identifier = AppleDeviceIdentifier()
        self.port_scanner = PortScanner()

    @staticmethod
    def _run_ip_json(*args: str) -> List[Dict[str, Any]]:
        """Safely invokes `ip -json <args>` and parses the resulting JSON array."""
        try:
            res = subprocess.run(["ip", "-json"] + list(args), capture_output=True, text=True)
            if res.returncode == 0 and res.stdout:
                parsed = json.loads(res.stdout)
                return parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            pass
        return []

    @classmethod
    def get_network_info(cls, interface: Optional[str] = None) -> NetworkInfo:
        """Determines active network interface, IP, MAC, gateway, and subnet."""
        routes = cls._run_ip_json("route")
        gateway_ip = None
        dev = interface.strip() if interface else None

        # 1. Look for default route
        for r in routes:
            if r.get("dst") == "default":
                if not dev:
                    dev = r.get("dev")
                if dev and r.get("dev") == dev:
                    gateway_ip = r.get("gateway")
                break

        # 2. If interface was specified or found, check routes again for its specific gateway
        if dev and not gateway_ip:
            for r in routes:
                if r.get("dev") == dev and r.get("gateway"):
                    gateway_ip = r.get("gateway")
                    break

        # 3. If still no interface, query active UP non-loopback links
        if not dev:
            links = cls._run_ip_json("link", "show", "up")
            for l in links:
                ifname = l.get("ifname", "")
                link_type = l.get("link_type", "")
                flags = l.get("flags", [])
                if ifname and ifname != "lo" and "NOARP" not in flags and link_type == "ether":
                    dev = ifname
                    break
            if not dev:
                for l in links:
                    ifname = l.get("ifname", "")
                    if ifname and ifname != "lo":
                        dev = ifname
                        break

        if not dev:
            dev = "eth0"

        addrs = cls._run_ip_json("addr", "show", "dev", dev)
        my_ip = ""
        my_mac = ""

        for a in addrs:
            my_mac = a.get("address", "").upper()
            for addr_info in a.get("addr_info", []):
                if addr_info.get("family") == "inet":
                    my_ip = addr_info.get("local", "")
                    break

        gateway_mac = None
        if gateway_ip:
            neighs = cls._run_ip_json("neigh", "show", gateway_ip)
            for n in neighs:
                if n.get("lladdr"):
                    gateway_mac = n.get("lladdr").upper()
                    break

        subnet_base = ".".join(my_ip.split(".")[:3]) if my_ip else ""

        return NetworkInfo(
            interface=dev,

            local_ip=my_ip,
            local_mac=my_mac,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            subnet_base=subnet_base,
        )

    def _correlate_device(
        self,
        ip: str,
        net_info: NetworkInfo,
        active_devices: Dict[str, str],
        dns_leases: Dict[str, str],
        ssdp_devices: Dict[str, Dict[str, Any]],
        netbios_devices: Dict[str, Dict[str, Any]],
        passive_transmitters: Dict[str, str],
        passive_only_ips: Set[str],
        whitelist: Dict[str, dict],
        deep_scan: bool = False,
        mdns_devices: Optional[Dict[str, Dict[str, Any]]] = None,
        ws_devices: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Tuple[Device, List[str]]:
        """Correlates multiple discovery signals into an enriched Device object and host threats."""
        mac = active_devices.get(ip)
        if not mac and ip == net_info.local_ip:
            mac = net_info.local_mac
        if not mac and ip == net_info.gateway_ip:
            mac = net_info.gateway_mac

        # If IP is a known alias of another host (e.g. gateway router alias), inherit parent MAC
        if not mac and mdns_devices:
            for parent_ip, pdata in mdns_devices.items():
                if ip in pdata.get("aliases", []):
                    mac = active_devices.get(parent_ip)
                    if not mac and parent_ip == net_info.gateway_ip:
                        mac = net_info.gateway_mac
                    elif not mac and parent_ip == net_info.local_ip:
                        mac = net_info.local_mac
                    break

        raw_hostname = dns_leases.get(ip, "")
        clean_host = RouterDnsAuditor.clean_hostname(raw_hostname) or "Unknown"
        vendor = "N/A"
        is_rand = False
        is_trusted = False
        friendly_name = None

        # Enrich from NetBIOS, SSDP, mDNS, and WS-Discovery
        nb_data = netbios_devices.get(ip)
        ssdp_data = ssdp_devices.get(ip)
        mdns_data = mdns_devices.get(ip) if mdns_devices else None
        ws_data = ws_devices.get(ip) if ws_devices else None

        if clean_host == "Unknown":
            if nb_data and nb_data.get("computer_name"):
                clean_host = nb_data["computer_name"]
            elif ssdp_data and ssdp_data.get("device_name"):
                clean_host = ssdp_data["device_name"]
            elif mdns_data and mdns_data.get("device_name"):
                clean_host = mdns_data["device_name"]
            elif ws_data and ws_data.get("device_name"):
                clean_host = ws_data["device_name"]

        if mac:
            mac = mac.upper()
            if mac in whitelist:
                is_trusted = True
                friendly_name = whitelist[mac].get("name")
            vendor, is_rand = self.vendor_resolver.resolve(mac)
        else:
            mac = "N/A (Asleep)"

        # Specialized Apple device identification
        is_apple, apple_type, resolved_name = self.apple_identifier.identify(
            ip, mac, raw_hostname, vendor
        )
        if resolved_name and clean_host == "Unknown":
            clean_host = resolved_name
        if is_apple:
            if not friendly_name:
                friendly_name = f"{apple_type} \"{resolved_name}\""
            vendor = f"Apple Inc. ({apple_type})"

        # Friendly name / vendor enrichment across all protocols
        if not friendly_name:
            if ssdp_data and ssdp_data.get("device_name"):
                friendly_name = ssdp_data["device_name"]
            elif nb_data and nb_data.get("computer_name"):
                friendly_name = nb_data["computer_name"]
            elif mdns_data and mdns_data.get("device_name"):
                friendly_name = mdns_data["device_name"]
            elif ws_data and ws_data.get("device_name"):
                friendly_name = ws_data["device_name"]

        if vendor == "N/A" or not vendor:
            if ssdp_data:
                mfg = ssdp_data.get("manufacturer")
                mdl = ssdp_data.get("model")
                if mfg and mdl:
                    vendor = f"{mfg} ({mdl})"
                elif mfg:
                    vendor = mfg
                elif mdl:
                    vendor = mdl
            elif mdns_data and mdns_data.get("model"):
                vendor = mdns_data["model"]

        # Fallback alias matching for sleeping devices without ARP response
        if not is_trusted and mac == "N/A (Asleep)":
            for w_mac, w_info in whitelist.items():
                w_name = w_info.get("name", "").lower()
                if (w_name in clean_host.lower()) or (
                    resolved_name and w_name in resolved_name.lower()
                ):
                    is_trusted = True
                    friendly_name = f"{w_info.get('name')} (DHCP Lease)"
                    break

        # Live State determination
        if ip == net_info.local_ip:
            status = "Local Machine"
            is_trusted = True
        elif (
            ip in active_devices
            or ip in ssdp_devices
            or ip in netbios_devices
            or (mdns_devices and ip in mdns_devices)
            or (ws_devices and ip in ws_devices)
            or ip in passive_transmitters
        ):
            status = "Online / Active"
        else:
            status = "Sleeping / Inactive Lease"

        if not mac:
            if status == "Sleeping / Inactive Lease":
                mac = "N/A (Asleep)"
            else:
                mac = "N/A (Virtual / Alias)"

        # Security Port Probing
        open_ports: List[str] = []
        host_threats: List[str] = []
        notes: List[str] = []

        # Add scanner metadata notes
        if nb_data and nb_data.get("workgroup"):
            notes.append(f"NetBIOS Workgroup: {nb_data['workgroup']}")
        if ssdp_data:
            if ssdp_data.get("model"):
                notes.append(f"UPnP Model: {ssdp_data['model']}")
            elif ssdp_data.get("server"):
                notes.append(f"UPnP Server: {ssdp_data['server']}")
        if mdns_data and mdns_data.get("services"):
            notes.append(f"mDNS: {', '.join(mdns_data['services'][:3])}")
        if ws_data:
            if ws_data.get("is_onvif"):
                notes.append("ONVIF Surveillance Camera")
            elif ws_data.get("types"):
                t_names = [t.split(":")[-1] for t in ws_data["types"][:2]]
                notes.append(f"WS-Discovery: {', '.join(t_names)}")
        if ip in passive_only_ips:
            notes.append("Passively Sniffed (Promiscuous Mode)")

        if status in ("Online / Active", "Local Machine"):
            open_ports, detected_threats, notes_ports = self.port_scanner.scan_host(
                ip, deep_scan=deep_scan
            )
            notes.extend(notes_ports)
            host_threats.extend([f"{ip} ({clean_host}): {t}" for t in detected_threats])

            # Port Drift & Baseline Anomaly Check
            if open_ports and mac != "N/A (Asleep)":
                drift_threats = ThreatDetector.check_port_drift(
                    ip=ip,
                    mac=mac,
                    display_name=friendly_name or clean_host or vendor,
                    current_open_ports=open_ports,
                    whitelist_entry=whitelist.get(mac),
                )
                host_threats.extend(drift_threats)

        is_alien = (not is_trusted) and (status == "Online / Active")

        # Determine how this device was discovered
        discovery_methods: List[str] = []
        if ip in active_devices and ip not in passive_only_ips:
            discovery_methods.append("Layer-2 ARP Scan")
        if ip in passive_only_ips:
            discovery_methods.append("Passive Frame Sniffer (Promiscuous Mode)")
        if mdns_data:
            discovery_methods.append("mDNS (Multicast DNS)")
        if ws_data:
            discovery_methods.append("WS-Discovery")
        if ssdp_data:
            discovery_methods.append("SSDP / UPnP")
        if nb_data:
            discovery_methods.append("NetBIOS Node Status")
        if ip in dns_leases and not discovery_methods:
            discovery_methods.append("Router DHCP Lease")

        discovery_str = ", ".join(discovery_methods) if discovery_methods else "Active ARP Sweep"

        aliases = mdns_data.get("aliases", []) if mdns_data else []
        if aliases:
            notes.append(f"Network Aliases: {', '.join(aliases)}")

        dev_obj = Device(
            ip=ip,
            mac=mac,
            hostname=clean_host,
            vendor=vendor,
            friendly_name=friendly_name,
            status=status,
            trusted=is_trusted,
            is_alien=is_alien,
            is_randomized=is_rand,
            is_apple=is_apple,
            open_ports=open_ports,
            threats=host_threats,
            notes=notes,
            mdns_services=mdns_data.get("services", []) if mdns_data else [],
            ws_types=ws_data.get("types", []) if ws_data else [],
            aliases=aliases,
            discovery_method=discovery_str,
        )

        return dev_obj, host_threats

    def run_audit(

        self,
        whitelist: Dict[str, dict],
        deep_scan: bool = False,
        passive_duration: int = 3,
        current_ssid: Optional[str] = None,
        interface: Optional[str] = None,
        ai_engine: Optional[Any] = None,
    ) -> AuditResult:
        """
        Executes a complete multi-layered network audit:
        1. Layer-2 ARP discovery
        2. Router DHCP/DNS lease interrogation
        3. Passive raw frame sniffing
        4. Device correlation & Apple identification
        5. Port & threat auditing
        """
        net_info = self.get_network_info(interface=interface)
        if not net_info.local_ip:
            return AuditResult(timestamp=time.time(), network=net_info)

        # 1. Active Layer-2 ARP scan
        arp_scanner = ArpScanner(
            interface=net_info.interface,
            local_mac=net_info.local_mac,
            local_ip=net_info.local_ip,
            subnet_cidr=net_info.subnet_cidr,
        )
        active_devices = arp_scanner.scan()

        # 2. Gateway DNS lease audit (sleeping & firewalled devices)
        router_auditor = RouterDnsAuditor(net_info.gateway_ip)
        dns_leases = router_auditor.audit_subnet(net_info.subnet_base)

        # 3. Passive frame sniffer (Hardware Promiscuous Mode)
        sniffer = PassiveFrameSniffer(net_info.interface, subnet_cidr=net_info.subnet_cidr)
        passive_transmitters = sniffer.sniff(duration=passive_duration)

        # Merge passive transmitters into active devices
        passive_only_ips = set()
        for pip, pmac in passive_transmitters.items():
            if pip not in active_devices:
                active_devices[pip] = pmac
                passive_only_ips.add(pip)

        # 4. Active SSDP / UPnP Discovery Scanner (Smart TVs, IoT, cameras)
        ssdp_scanner = SsdpScanner(local_ip=net_info.local_ip)
        ssdp_devices = ssdp_scanner.scan(timeout=1.5, fetch_details=True)

        # 5. Active NetBIOS Node Status Scanner (Windows / Samba / Domain members)
        netbios_scanner = NetbiosScanner(net_info.interface)
        subnet_bcast = net_info.broadcast_ip
        target_ips = list(set(active_devices.keys()) | set(dns_leases.keys()) | set(ssdp_devices.keys()))
        netbios_devices = netbios_scanner.scan(
            target_ips=target_ips, subnet_broadcast=subnet_bcast, timeout=1.2
        )

        # Merge NetBIOS MAC addresses if any active device was missing its MAC
        for nb_ip, nb_info in netbios_devices.items():
            nb_mac = nb_info.get("mac")
            if nb_mac and nb_ip not in active_devices:
                active_devices[nb_ip] = nb_mac

        # 6. Active mDNS / DNS-SD Discovery Scanner (IoT, Apple, Smart TVs)
        mdns_scanner = MdnsScanner(
            net_info.interface,
            subnet_base=net_info.subnet_base,
            subnet_cidr=net_info.subnet_cidr,
        )
        mdns_devices = mdns_scanner.scan(timeout=1.2)

        # 7. Active WS-Discovery Scanner (Modern Windows & ONVIF cameras)
        ws_scanner = WsDiscoveryScanner(net_info.interface)
        ws_devices = ws_scanner.scan(timeout=1.2)

        # Combine all discovered IPs
        all_ips: Set[str] = (
            set(active_devices.keys())
            | set(dns_leases.keys())
            | set(ssdp_devices.keys())
            | set(netbios_devices.keys())
            | set(mdns_devices.keys())
            | set(ws_devices.keys())
            | set(passive_transmitters.keys())
        )
        if net_info.gateway_ip:
            all_ips.add(net_info.gateway_ip)
        if net_info.local_ip:
            all_ips.add(net_info.local_ip)

        # Threat Detection & Active Defenses:
        # a) ARP Spoofing / Rogue Gateway
        threats: List[str] = ThreatDetector.check_arp_spoofing(
            active_devices, net_info.gateway_ip, net_info.gateway_mac
        )
        # b) Rogue DHCP Server / Rogue Gateway Probe
        threats.extend(
            ThreatDetector.check_rogue_dhcp(
                interface=net_info.interface,
                local_mac=net_info.local_mac,
                gateway_ip=net_info.gateway_ip,
            )
        )
        # c) Active LLMNR / NBT-NS Poisoning Canary Trap (Anti-Responder)
        threats.extend(
            ThreatDetector.check_llmnr_poisoning(
                interface=net_info.interface,
                subnet_broadcast=subnet_bcast,
                timeout=1.0,
            )
        )
        # d) Active mDNS / Bonjour Poisoning Canary Trap (Anti-Responder)
        threats.extend(
            ThreatDetector.check_mdns_poisoning(
                interface=net_info.interface,
                timeout=1.0,
            )
        )
        # e) DNS Integrity & Cache Poisoning Audit
        threats.extend(
            ThreatDetector.check_dns_integrity(
                gateway_ip=net_info.gateway_ip,
            )
        )
        # f) Rogue IPv6 Router Advertisement & mitm6 Guard
        threats.extend(
            ThreatDetector.check_rogue_ipv6_ra(
                interface=net_info.interface,
            )
        )
        # g) Remote Promiscuous Node Anti-Sniff Test (on deep scan)
        if deep_scan and active_devices:
            threats.extend(
                ThreatDetector.check_promiscuous_hosts(
                    interface=net_info.interface,
                    local_ip=net_info.local_ip,
                    local_mac=net_info.local_mac,
                    target_hosts=active_devices,
                )
            )
        # h) Wireless Airspace / Evil Twin AP
        if current_ssid:
            threats.extend(ThreatDetector.check_wifi_threats(current_ssid))

        # i) Stealth TCP Half-Open / SYN Port Scan Detector
        threats.extend(
            ThreatDetector.check_syn_scans(
                interface=net_info.interface,
                subnet_cidr=net_info.subnet_cidr,
                local_ip=net_info.local_ip,
                local_mac=net_info.local_mac,
                duration=1.0,
            )
        )

        # j) High-Entropy DNS Tunneling & Exfiltration Detector
        threats.extend(
            ThreatDetector.check_dns_tunneling(
                interface=net_info.interface,
                subnet_cidr=net_info.subnet_cidr,
                local_ip=net_info.local_ip,
                local_mac=net_info.local_mac,
                duration=1.0,
            )
        )

        # k) DHCP Starvation & Pool Exhaustion Guard
        threats.extend(
            ThreatDetector.check_dhcp_starvation(
                interface=net_info.interface,
                duration=1.0,
            )
        )

        # l) Real-Time ARP Cache Poisoning & Gateway Masquerade Guard
        trusted_map = {
            ip: mac for ip, mac in active_devices.items() if mac and mac in whitelist
        }
        threats.extend(
            ThreatDetector.check_realtime_arp_poisoning(
                interface=net_info.interface,
                gateway_ip=net_info.gateway_ip,
                gateway_mac=net_info.gateway_mac,
                trusted_ip_mac_map=trusted_map,
                duration=1.0,
            )
        )

        inventory: List[Device] = []
        alien_devices: List[Device] = []

        sorted_ips = sorted(
            list(all_ips),
            key=lambda x: [int(p) for p in x.split(".") if p.isdigit()]
            if "." in x
            else [999],
        )

        for ip in sorted_ips:
            dev_obj, host_threats = self._correlate_device(
                ip=ip,
                net_info=net_info,
                active_devices=active_devices,
                dns_leases=dns_leases,
                ssdp_devices=ssdp_devices,
                netbios_devices=netbios_devices,
                passive_transmitters=passive_transmitters,
                passive_only_ips=passive_only_ips,
                whitelist=whitelist,
                deep_scan=deep_scan,
                mdns_devices=mdns_devices,
                ws_devices=ws_devices,
            )
            inventory.append(dev_obj)
            if dev_obj.is_alien:
                alien_devices.append(dev_obj)
            threats.extend(host_threats)

        audit_result = AuditResult(

            timestamp=time.time(),
            network=net_info,
            devices=inventory,
            alien_devices=alien_devices,
            threats=threats,
        )

        # 5. AI Risk & Network Posture Assessment (Optional & Configurable)
        if ai_engine:
            targets = alien_devices if ai_engine.analyze_on == "alien_only" else inventory
            if targets:
                ai_engine.analyze_devices(targets, threats=threats)
            ai_engine.analyze_network(audit_result)

        return audit_result
