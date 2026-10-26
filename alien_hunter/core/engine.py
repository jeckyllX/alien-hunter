"""
Core Discovery and Audit Engine for Alien Hunter.
Coordinates network context resolution, multi-layered device discovery,
vendor resolution, Apple heuristics, port auditing, and threat detection.
"""

import ipaddress
import json
import re
import subprocess
import time
from typing import Dict, List, Optional, Set, Tuple, Any

from ..logging_setup import get_logger
from ..models import Device, NetworkInfo, AuditResult
from ..scanners.arp import ArpScanner
from ..scanners.router import RouterDnsAuditor
from ..scanners.sniffer import PassiveFrameSniffer
from ..scanners.ports import PortScanner, DEEP_PORTS, FAST_PORTS
from ..scanners.ssdp import SsdpScanner
from ..scanners.netbios import NetbiosScanner
from ..scanners.mdns import MdnsScanner
from ..scanners.ws_discovery import WsDiscoveryScanner
from ..scanners.ipv6_discovery import Ipv6DiscoveryScanner
from ..scanners.phantom import PhantomSweeper
from ..identifiers.vendor import MacVendorResolver
from ..identifiers.apple import AppleDeviceIdentifier
from ..identifiers.signatures import (
    SignatureManager,
    DhcpFingerprintStore,
    SsdpFingerprintStore,
    TcpSynFingerprintStore,
)
from ..threats import ThreatDetector

log = get_logger()



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
        self.signature_manager = SignatureManager()
        self.port_scanner = PortScanner()

    @staticmethod
    def _run_ip_json(*args: str) -> List[Dict[str, Any]]:
        """Safely invokes `ip -json <args>` and parses the resulting JSON array."""
        try:
            res = subprocess.run(["ip", "-json"] + list(args), capture_output=True, text=True)
            if res.returncode == 0 and res.stdout:
                parsed = json.loads(res.stdout)
                return parsed if isinstance(parsed, list) else [parsed]
            if res.returncode != 0:
                log.debug("`ip -json %s` exited %s: %s", " ".join(args), res.returncode, res.stderr.strip())
        except Exception as e:
            log.debug("`ip -json %s` invocation failed: %s", " ".join(args), e)
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
        prefix_len: Optional[int] = None

        for a in addrs:
            my_mac = a.get("address", "").upper()
            for addr_info in a.get("addr_info", []):
                if addr_info.get("family") == "inet":
                    my_ip = addr_info.get("local", "")
                    prefix_len = addr_info.get("prefixlen")
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
            prefix_len=prefix_len,
        )

    @staticmethod
    def _resolve_device_mac(
        ip: str,
        net_info: NetworkInfo,
        active_devices: Dict[str, str],
        ipv6_devices: Optional[Dict[str, str]],
        mdns_devices: Optional[Dict[str, Dict[str, Any]]],
        whitelist: Dict[str, dict],
    ) -> Optional[str]:
        """Resolves a device's hardware MAC address across ARP, IPv6, local/gateway, mDNS aliases, and whitelist."""
        mac = active_devices.get(ip)
        if not mac and ipv6_devices:
            mac = ipv6_devices.get(ip)
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

        # Check whitelist if IP belongs to a known device whose MAC was not active in Layer-2 ARP
        if not mac and whitelist:
            for w_mac, w_info in whitelist.items():
                if w_info.get("primary_ip") == ip or ip in w_info.get("aliases", []):
                    mac = w_mac
                    break

        return mac

    @staticmethod
    def _is_valid_hardware_mac(mac: Optional[str]) -> bool:
        if not mac or not isinstance(mac, str):
            return False
        clean = mac.strip().upper()
        if clean.startswith("N/A") or clean in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return False
        return bool(re.match(r"^([0-9A-FA-F]{2}[:-]){5}([0-9A-FA-F]{2})$", clean))

    @staticmethod
    def _ip_rank(
        ip_str: str,
        subnet_cidr: Optional[str] = None,
        configured_primary: Optional[str] = None,
    ) -> int:
        """Ranks candidate IPs so configured primary and local subnet IPv4 addresses are preferred."""
        if not ip_str or not isinstance(ip_str, str):
            return -1
        if configured_primary and ip_str == configured_primary:
            return 10
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.version == 4:
                if subnet_cidr:
                    try:
                        if addr in ipaddress.ip_network(subnet_cidr, strict=False):
                            return 5
                    except ValueError:
                        pass
                if addr.is_private:
                    return 4
                return 3
            elif addr.version == 6:
                if not addr.is_link_local:
                    return 2
                return 1
        except ValueError:
            pass
        return 0

    @classmethod
    def _merge_device_telemetry(
        cls,
        existing: Device,
        incoming: Device,
        subnet_cidr: Optional[str] = None,
        configured_primary: Optional[str] = None,
    ) -> None:
        """Merges telemetry from multiple discovery protocols/IPs for the same hardware MAC."""
        # 1. Primary IP vs Aliases resolution
        e_rank = cls._ip_rank(existing.ip, subnet_cidr, configured_primary)
        i_rank = cls._ip_rank(incoming.ip, subnet_cidr, configured_primary)
        if i_rank > e_rank:
            demoted_ip = existing.ip
            existing.ip = incoming.ip
            if demoted_ip and demoted_ip != existing.ip and demoted_ip not in existing.aliases:
                existing.aliases.append(demoted_ip)
        else:
            if incoming.ip and incoming.ip != existing.ip and incoming.ip not in existing.aliases:
                existing.aliases.append(incoming.ip)

        for alias in incoming.aliases:
            if alias and alias != existing.ip and alias not in existing.aliases:
                existing.aliases.append(alias)

        # 2. Status resolution (Local Machine > Online / Active > Sleeping / Inactive Lease)
        status_ranks = {"Local Machine": 3, "Online / Active": 2, "Sleeping / Inactive Lease": 1}
        if status_ranks.get(incoming.status, 0) > status_ranks.get(existing.status, 0):
            existing.status = incoming.status

        # 3. Trust and Alien status
        if incoming.trusted:
            existing.trusted = True
        existing.is_alien = (not existing.trusted) and (existing.status in ("Online / Active", "Local Machine"))

        # 4. Hostname / Friendly Name / Vendor
        if existing.hostname in ("Unknown", "", "N/A") and incoming.hostname not in ("Unknown", "", "N/A"):
            existing.hostname = incoming.hostname
        if not existing.friendly_name and incoming.friendly_name:
            existing.friendly_name = incoming.friendly_name
        if existing.vendor in ("N/A", "Unknown", "Unknown Vendor") and incoming.vendor not in ("N/A", "Unknown", "Unknown Vendor"):
            existing.vendor = incoming.vendor
        elif "Randomized" in existing.vendor and "Randomized" not in incoming.vendor and incoming.vendor not in ("N/A", "Unknown"):
            existing.vendor = incoming.vendor

        # 5. Discovery Methods
        e_methods = [m.strip() for m in existing.discovery_method.split(",") if m.strip()]
        i_methods = [m.strip() for m in incoming.discovery_method.split(",") if m.strip()]
        existing.discovery_method = ", ".join(list(dict.fromkeys(e_methods + i_methods)))

        # 6. Open Ports
        def _port_key(p: Any) -> int:
            try:
                return int(str(p).split("/")[0])
            except (ValueError, IndexError):
                return 99999
        merged_ports = list(dict.fromkeys(existing.open_ports + incoming.open_ports))
        merged_ports.sort(key=_port_key)
        existing.open_ports = merged_ports

        # 7. Metadata collections
        existing.threats = list(dict.fromkeys(existing.threats + incoming.threats))
        existing.notes = list(dict.fromkeys(existing.notes + incoming.notes))
        existing.mdns_services = list(dict.fromkeys(existing.mdns_services + incoming.mdns_services))
        existing.ws_types = list(dict.fromkeys(existing.ws_types + incoming.ws_types))

        # 8. Fingerprints & Flags
        if incoming.is_apple:
            existing.is_apple = True
        if incoming.is_randomized:
            existing.is_randomized = True
        if not existing.dhcp_fingerprint and incoming.dhcp_fingerprint:
            existing.dhcp_fingerprint = incoming.dhcp_fingerprint
        if not existing.dhcp_params and incoming.dhcp_params:
            existing.dhcp_params = incoming.dhcp_params
        if not existing.ssdp_fingerprint and incoming.ssdp_fingerprint:
            existing.ssdp_fingerprint = incoming.ssdp_fingerprint
        if not existing.tcp_syn_fingerprint and incoming.tcp_syn_fingerprint:
            existing.tcp_syn_fingerprint = incoming.tcp_syn_fingerprint
        if not existing.observed_ttl and incoming.observed_ttl:
            existing.observed_ttl = incoming.observed_ttl
        if not existing.ai_assessment and incoming.ai_assessment:
            existing.ai_assessment = incoming.ai_assessment

    @staticmethod
    def _compute_device_status(
        ip: str,
        net_info: NetworkInfo,
        active_devices: Dict[str, str],
        ssdp_devices: Dict[str, Dict[str, Any]],
        netbios_devices: Dict[str, Dict[str, Any]],
        mdns_devices: Optional[Dict[str, Dict[str, Any]]],
        ws_devices: Optional[Dict[str, Dict[str, Any]]],
        passive_transmitters: Dict[str, str],
        ipv6_devices: Optional[Dict[str, str]] = None,
    ) -> str:
        """Determines whether a discovered IP is the local machine, actively online, or an inactive lease."""
        if ip == net_info.local_ip:
            return "Local Machine"
        if (
            ip in active_devices
            or ip in ssdp_devices
            or ip in netbios_devices
            or (mdns_devices and ip in mdns_devices)
            or (ws_devices and ip in ws_devices)
            or ip in passive_transmitters
            or (ipv6_devices and ip in ipv6_devices)
        ):
            return "Online / Active"
        return "Sleeping / Inactive Lease"

    @staticmethod
    def _build_discovery_methods(
        ip: str,
        active_devices: Dict[str, str],
        passive_only_ips: Set[str],
        dns_leases: Dict[str, str],
        mdns_data: Optional[Dict[str, Any]],
        ws_data: Optional[Dict[str, Any]],
        ssdp_data: Optional[Dict[str, Any]],
        nb_data: Optional[Dict[str, Any]],
        phantom_devices: Optional[Dict[str, str]],
    ) -> str:
        """Compiles a comma-separated description of all protocols that observed this host."""
        discovery_methods: List[str] = []
        if phantom_devices and ip in phantom_devices:
            discovery_methods.append("Phantom Cross-Subnet (Promiscuous Layer-2)")
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
        return ", ".join(discovery_methods) if discovery_methods else "Active ARP Sweep"

    def _audit_device_ports_and_threats(
        self,
        ip: str,
        mac: str,
        status: str,
        clean_host: str,
        friendly_name: Optional[str],
        vendor: str,
        whitelist: Dict[str, dict],
        deep_scan: bool,
        custom_ports: Optional[List[int]],
        observed_ttl: Optional[int],
        tcp_syn_fingerprint: Optional[str],
        dhcp_fingerprint: Optional[str],
        active_honey_ports: Optional[Set[int]] = None,
    ) -> Tuple[List[str], List[str], List[str]]:
        """Executes port scanning, port drift analysis, and doppelganger checks for a single host."""
        open_ports: List[str] = []
        host_threats: List[str] = []
        port_notes: List[str] = []

        if status in ("Online / Active", "Local Machine"):
            scan_ports = custom_ports
            if status == "Local Machine" and active_honey_ports:
                if scan_ports is not None:
                    scan_ports = [p for p in scan_ports if p not in active_honey_ports]
                elif deep_scan:
                    scan_ports = [p for p in DEEP_PORTS if p not in active_honey_ports]
                else:
                    scan_ports = [p for p in FAST_PORTS if p not in active_honey_ports]

            open_ports, detected_threats, notes_ports = self.port_scanner.scan_host(
                ip, deep_scan=deep_scan, ports=scan_ports
            )
            port_notes.extend(notes_ports)

            w_entry = whitelist.get(mac) if mac else None
            baseline_port_nums: Set[str] = set()
            if w_entry and w_entry.get("trusted", True):
                for bp in (w_entry.get("ports") or w_entry.get("baseline_ports") or []):
                    bp_str = str(bp)
                    baseline_port_nums.add(bp_str.split("/")[0] if "/" in bp_str else bp_str)

            for t in detected_threats:
                # Example format: "[HIGH] Port 445 (SMB): ..."
                # Suppress static vulnerability warnings for ports already whitelisted on this trusted host.
                suppressed = False
                if baseline_port_nums and "Port " in t:
                    after_port = t.split("Port ", 1)[1]
                    p_num = after_port.split(" ", 1)[0].strip()
                    if p_num in baseline_port_nums:
                        suppressed = True
                if not suppressed:
                    host_threats.append(f"{ip} ({clean_host}): {t}")

            # Port Drift & Baseline Anomaly Check
            if open_ports and mac != "N/A (Asleep)":
                drift_threats = ThreatDetector.check_port_drift(
                    ip=ip,
                    mac=mac,
                    display_name=friendly_name or clean_host or vendor,
                    current_open_ports=open_ports,
                    whitelist_entry=w_entry,
                )
                host_threats.extend(drift_threats)

        # Hardware Doppelgänger & Identity Spoofing Check (MITRE ATT&CK T1036)
        if mac and not mac.startswith("N/A"):
            doppel_threats = ThreatDetector.check_device_doppelganger(
                ip=ip,
                mac=mac,
                display_name=friendly_name or clean_host or vendor,
                observed_ttl=observed_ttl,
                current_os=tcp_syn_fingerprint,
                dhcp_os=dhcp_fingerprint,
                whitelist_entry=whitelist.get(mac),
                vendor=vendor,
            )
            host_threats.extend(doppel_threats)

        return open_ports, host_threats, port_notes

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
        ipv6_devices: Optional[Dict[str, str]] = None,
        custom_ports: Optional[List[int]] = None,
        phantom_devices: Optional[Dict[str, str]] = None,
        active_honey_ports: Optional[Set[int]] = None,
    ) -> Tuple[Device, List[str]]:
        """Correlates multiple discovery signals into an enriched Device object and host threats."""
        mac = self._resolve_device_mac(
            ip=ip,
            net_info=net_info,
            active_devices=active_devices,
            ipv6_devices=ipv6_devices,
            mdns_devices=mdns_devices,
            whitelist=whitelist,
        )

        raw_hostname = dns_leases.get(ip, "")
        clean_host = RouterDnsAuditor.clean_hostname(raw_hostname) or "Unknown"
        vendor = "N/A"
        is_rand = False
        is_trusted = False
        friendly_name = None
        notes: List[str] = []
        ssdp_fingerprint: Optional[str] = None
        tcp_syn_fingerprint: Optional[str] = None

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

        # DHCP Option 55/60 Passive Fingerprint Unmasking
        dhcp_fp_info = DhcpFingerprintStore.get_instance().get(mac)
        dhcp_fingerprint = None
        dhcp_params = None
        dhcp_says_apple = False
        if dhcp_fp_info:
            dhcp_params = dhcp_fp_info.get("param_list")
            dhcp_match = self.signature_manager.match_dhcp(
                dhcp_params, dhcp_fp_info.get("vendor_class")
            )
            if dhcp_match:
                dhcp_fingerprint = dhcp_match.vendor
                notes.append(f"DHCP OS: {dhcp_match.vendor} ({dhcp_match.source})")
                if "apple" in dhcp_match.vendor.lower():
                    dhcp_says_apple = True
                if is_rand and vendor == "Randomized Private MAC":
                    vendor = f"{dhcp_match.vendor} (Randomized MAC)"
            if dhcp_fp_info.get("hostname") and clean_host == "Unknown":
                clean_host = dhcp_fp_info["hostname"]

        # Specialized Apple device identification
        is_apple, apple_type, resolved_name = self.apple_identifier.identify(
            ip, mac, raw_hostname, vendor
        )
        if resolved_name and clean_host == "Unknown":
            clean_host = resolved_name
        # DHCP Option 55/60 can independently indicate an Apple stack (e.g. behind a
        # privacy-randomized MAC); honor it when the identifier missed it.
        if dhcp_says_apple and not is_apple:
            is_apple = True
            apple_type = "Apple Device"
        if is_apple:
            apple_type = apple_type or "Apple Device"
            display = resolved_name or (clean_host if clean_host != "Unknown" else None)
            if not friendly_name and display:
                friendly_name = f"{apple_type} \"{display}\""
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

        # Match advertised mDNS service types against signature registry
        if mdns_data and mdns_data.get("services"):
            mdns_match = self.signature_manager.match_mdns(mdns_data["services"])
            if mdns_match:
                notes.append(f"mDNS Service Match: {mdns_match.vendor}")
                if vendor in ("N/A", "Unknown Vendor", "Randomized Private MAC"):
                    vendor = mdns_match.vendor

        # SSDP / UPnP Signature Resolution
        ssdp_store_info = SsdpFingerprintStore.get_instance().get(ip)
        ssdp_match = None
        if ssdp_store_info:
            ssdp_match = ssdp_store_info.get("match")
            if not ssdp_match:
                ssdp_match = self.signature_manager.match_ssdp(
                    server=ssdp_store_info.get("server")
                )
        if not ssdp_match and ssdp_data:
            ssdp_match = self.signature_manager.match_ssdp(
                server=ssdp_data.get("server")
            )
        if ssdp_match:
            ssdp_fingerprint = ssdp_match.vendor
            notes.append(f"SSDP Device: {ssdp_match.vendor} ({ssdp_match.source})")
            if vendor in ("N/A", "Unknown Vendor", "Randomized Private MAC"):
                vendor = ssdp_match.vendor
            elif is_rand and vendor == "Randomized Private MAC":
                vendor = f"{ssdp_match.vendor} (Randomized MAC)"

        # Passive TCP SYN Stack Fingerprint Resolution
        tcp_syn_info = TcpSynFingerprintStore.get_instance().get(ip)
        observed_ttl = None
        if tcp_syn_info:
            observed_ttl = tcp_syn_info.get("ttl")
            tcp_match = tcp_syn_info.get("match")
            if not tcp_match:
                tcp_match = self.signature_manager.match_tcp_syn(
                    ttl=tcp_syn_info["ttl"],
                    options=tcp_syn_info["options"],
                    window_size=tcp_syn_info.get("window_size"),
                )
            if tcp_match:
                tcp_syn_fingerprint = tcp_match.vendor
                notes.append(
                    f"TCP Stack OS: {tcp_match.vendor} (TTL={tcp_syn_info['ttl']}, Options={tcp_syn_info['options']})"
                )
                if vendor in ("N/A", "Unknown Vendor", "Randomized Private MAC") and not dhcp_fingerprint:
                    vendor = f"{tcp_match.vendor} (TCP SYN)"
                elif is_rand and vendor == "Randomized Private MAC" and not dhcp_fingerprint:
                    vendor = f"{tcp_match.vendor} (Randomized MAC)"

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

        status = self._compute_device_status(
            ip=ip,
            net_info=net_info,
            active_devices=active_devices,
            ssdp_devices=ssdp_devices,
            netbios_devices=netbios_devices,
            mdns_devices=mdns_devices,
            ws_devices=ws_devices,
            passive_transmitters=passive_transmitters,
            ipv6_devices=ipv6_devices,
        )
        if status == "Local Machine":
            is_trusted = True

        if not mac:
            if status == "Sleeping / Inactive Lease":
                mac = "N/A (Asleep)"
            else:
                mac = "N/A (Virtual / Alias)"

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

        open_ports, host_threats, port_notes = self._audit_device_ports_and_threats(
            ip=ip,
            mac=mac,
            status=status,
            clean_host=clean_host,
            friendly_name=friendly_name,
            vendor=vendor,
            whitelist=whitelist,
            deep_scan=deep_scan,
            custom_ports=custom_ports,
            observed_ttl=observed_ttl,
            tcp_syn_fingerprint=tcp_syn_fingerprint,
            dhcp_fingerprint=dhcp_fingerprint,
            active_honey_ports=active_honey_ports,
        )
        notes.extend(port_notes)

        # Flag out-of-subnet static host / phantom drop box
        if PhantomSweeper.is_out_of_subnet(ip, net_info.subnet_cidr) and ip != net_info.gateway_ip and ip != net_info.local_ip:
            notes.append(f"Mismatched Subnet: Host is operating outside local subnet {net_info.subnet_cidr}")

        is_alien = (not is_trusted) and (status == "Online / Active")

        discovery_str = self._build_discovery_methods(
            ip=ip,
            active_devices=active_devices,
            passive_only_ips=passive_only_ips,
            dns_leases=dns_leases,
            mdns_data=mdns_data,
            ws_data=ws_data,
            ssdp_data=ssdp_data,
            nb_data=nb_data,
            phantom_devices=phantom_devices,
        )

        aliases = mdns_data.get("aliases", []) if mdns_data else []
        if aliases:
            notes.append(f"Network Aliases: {', '.join(aliases)}")

        configured_primary = whitelist.get(mac, {}).get("primary_ip") if (whitelist and mac) else None
        final_ip = ip
        if configured_primary and self._ip_rank(configured_primary, net_info.subnet_cidr) > self._ip_rank(ip, net_info.subnet_cidr):
            final_ip = configured_primary
            if ip and ip != configured_primary and ip not in aliases:
                aliases.append(ip)

        dev_obj = Device(
            ip=final_ip,
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
            dhcp_fingerprint=dhcp_fingerprint,
            dhcp_params=dhcp_params,
            ssdp_fingerprint=ssdp_fingerprint,
            tcp_syn_fingerprint=tcp_syn_fingerprint,
            observed_ttl=observed_ttl,
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
        custom_ports: Optional[List[int]] = None,
        active_background_defenses: Optional[Dict[str, bool]] = None,
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

        # 1. Active Layer-2 ARP scan with candidate targets from whitelist
        candidate_targets: Dict[str, str] = {}
        for w_mac, w_info in whitelist.items():
            w_ip = w_info.get("primary_ip")
            if w_ip and w_mac and not w_mac.startswith("N/A"):
                candidate_targets[w_ip] = w_mac

        arp_scanner = ArpScanner(
            interface=net_info.interface,
            local_mac=net_info.local_mac,
            local_ip=net_info.local_ip,
            subnet_cidr=net_info.subnet_cidr,
        )
        active_devices = arp_scanner.scan(candidate_targets=candidate_targets)

        # 2. Gateway DNS lease audit (sleeping & firewalled devices)
        router_auditor = RouterDnsAuditor(net_info.gateway_ip)
        dns_leases = router_auditor.audit_subnet(net_info.subnet_base)

        # 3. Passive frame sniffer (Hardware Promiscuous Mode)
        sniffer = PassiveFrameSniffer(
            net_info.interface,
            subnet_cidr=net_info.subnet_cidr,
            gateway_mac=net_info.gateway_mac,
            local_mac=net_info.local_mac,
        )
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

        # 8. Active IPv6 Shadow Network Discovery
        ipv6_scanner = Ipv6DiscoveryScanner(net_info.interface)
        ipv6_devices = ipv6_scanner.scan(timeout=1.2)

        # 9. Active & Passive Phantom Cross-Subnet Discovery
        gw_mac_upper = net_info.gateway_mac.upper() if net_info.gateway_mac else None
        local_mac_upper = net_info.local_mac.upper() if net_info.local_mac else None
        if passive_duration > 0:
            # Derive phantom transmitters directly from PassiveFrameSniffer capture
            phantom_devices = {
                p_ip: p_mac.upper()
                for p_ip, p_mac in passive_transmitters.items()
                if (not gw_mac_upper or p_mac.upper() != gw_mac_upper)
                and (not local_mac_upper or p_mac.upper() != local_mac_upper)
                and PhantomSweeper.is_out_of_subnet(p_ip, net_info.subnet_cidr)
            }
        else:
            phantom_sweeper = PhantomSweeper(
                interface=net_info.interface,
                subnet_cidr=net_info.subnet_cidr,
                gateway_mac=net_info.gateway_mac,
                local_mac=net_info.local_mac,
            )
            phantom_devices = phantom_sweeper.scan(duration=1.0)
            for p_ip, p_mac in phantom_devices.items():
                if p_ip not in active_devices:
                    active_devices[p_ip] = p_mac

        # Combine all discovered IPs
        all_ips: Set[str] = (
            set(active_devices.keys())
            | set(dns_leases.keys())
            | set(ssdp_devices.keys())
            | set(netbios_devices.keys())
            | set(mdns_devices.keys())
            | set(ws_devices.keys())
            | set(passive_transmitters.keys())
            | set(ipv6_devices.keys())
            | set(phantom_devices.keys())
        )
        if net_info.gateway_ip:
            all_ips.add(net_info.gateway_ip)
        if net_info.local_ip:
            all_ips.add(net_info.local_ip)

        bg_defenses = active_background_defenses or {}
        active_honey_ports = set(bg_defenses.get("honey_ports") or [])

        # Threat Detection & Active Defenses:
        # a) ARP Spoofing / Rogue Gateway
        threats: List[str] = ThreatDetector.check_arp_spoofing(
            active_devices, net_info.gateway_ip, net_info.gateway_mac
        )
        # b) Rogue DHCP Server / Rogue Gateway Probe
        if not bg_defenses.get("rogue_dhcp"):
            threats.extend(
                ThreatDetector.check_rogue_dhcp(
                    interface=net_info.interface,
                    local_mac=net_info.local_mac,
                    gateway_ip=net_info.gateway_ip,
                    gateway_mac=net_info.gateway_mac,
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
        # g) Remote Promiscuous Node Anti-Sniff Test (on deep scan, wired Ethernet only)
        if deep_scan and active_devices and net_info.interface:
            if not net_info.interface.startswith(("wl", "wlan", "wifi", "ath", "ra", "wg", "tun", "tap")):
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
        if not bg_defenses.get("syn_scan"):
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
        if not bg_defenses.get("dns_tunneling"):
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
        if not bg_defenses.get("dhcp_starvation"):
            threats.extend(
                ThreatDetector.check_dhcp_starvation(
                    interface=net_info.interface,
                    duration=1.0,
                )
            )

        # l) Real-Time ARP Cache Poisoning & Gateway Masquerade Guard
        if not bg_defenses.get("arp_poison"):
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
        mac_to_dev: Dict[str, Device] = {}

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
                ipv6_devices=ipv6_devices,
                custom_ports=custom_ports,
                phantom_devices=phantom_devices,
                active_honey_ports=active_honey_ports,
            )
            mac_clean = (dev_obj.mac or "").strip().upper()
            if self._is_valid_hardware_mac(mac_clean):
                if mac_clean in mac_to_dev:
                    existing = mac_to_dev[mac_clean]
                    configured_primary = whitelist.get(mac_clean, {}).get("primary_ip") if whitelist else None
                    self._merge_device_telemetry(existing, dev_obj, net_info.subnet_cidr, configured_primary)
                    threats.extend(host_threats)
                    continue
                mac_to_dev[mac_clean] = dev_obj

            inventory.append(dev_obj)
            threats.extend(host_threats)

        alien_devices = [d for d in inventory if d.is_alien]

        # Evaluate Out-of-Subnet Phantom Device threats
        threats.extend(
            ThreatDetector.check_phantom_devices(
                devices=inventory,
                subnet_cidr=net_info.subnet_cidr,
                gateway_mac=net_info.gateway_mac,
                local_mac=net_info.local_mac,
            )
        )

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
