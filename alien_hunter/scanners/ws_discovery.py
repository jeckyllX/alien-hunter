"""
Web Services Dynamic Discovery (WS-Discovery) Scanner.
Discovers modern Windows 10/11 endpoints, ONVIF IP surveillance cameras,
network printers, and modern NAS storage devices over UDP 3702 (239.255.255.250).
"""

import ipaddress
import socket
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any

from .net_utils import create_udp_socket


class WsDiscoveryScanner:
    """Discovers modern Windows hosts and ONVIF devices using WS-Discovery SOAP probes."""

    WS_DISCOVERY_GROUP = "239.255.255.250"
    WS_DISCOVERY_PORT = 3702

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface

    @classmethod
    def build_probe(cls, message_uuid: Optional[str] = None) -> bytes:
        """Constructs an OASIS WS-Discovery Probe SOAP envelope."""
        msg_id = message_uuid or str(uuid.uuid4())
        probe_xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            "<soap:Header>"
            "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
            f"<wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>"
            "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
            "</soap:Header>"
            "<soap:Body>"
            "<wsd:Probe>"
            "<wsd:Types>wsd:Device</wsd:Types>"
            "</wsd:Probe>"
            "</soap:Body>"
            "</soap:Envelope>"
        )
        return probe_xml.encode("utf-8")

    @classmethod
    def parse_probe_match(cls, xml_data: str, src_ip: str) -> Optional[Dict[str, Any]]:
        """Parses a ProbeMatches SOAP response into structured device attributes."""
        try:
            root = ET.fromstring(xml_data)

            types_found: List[str] = []
            scopes_found: List[str] = []
            xaddrs_found: List[str] = []
            resolved_ip = src_ip

            # Locate ProbeMatch blocks regardless of namespace prefixes
            for elem in root.iter():
                tag_local = elem.tag.split("}")[-1].split(":")[-1]
                if tag_local == "ProbeMatch":
                    for child in elem:
                        child_local = child.tag.split("}")[-1].split(":")[-1]
                        if child_local == "Types" and child.text:
                            types_found.extend(child.text.strip().split())
                        elif child_local == "Scopes" and child.text:
                            scopes_found.extend(child.text.strip().split())
                        elif child_local == "XAddrs" and child.text:
                            for addr in child.text.strip().split():
                                xaddrs_found.append(addr)
                                parsed = urllib.parse.urlparse(addr)
                                if parsed.hostname:
                                    try:
                                        ip_obj = ipaddress.ip_address(parsed.hostname)
                                        if not ip_obj.is_loopback and not ip_obj.is_unspecified and not ip_obj.is_multicast:
                                            resolved_ip = str(ip_obj)
                                    except ValueError:
                                        pass

            if not types_found and not xaddrs_found and not scopes_found:
                return None

            # Infer hardware or service identity from Scopes
            inferred_name = None
            for scope in scopes_found:
                if "onvif://www.onvif.org/name/" in scope:
                    inferred_name = urllib.parse.unquote(scope.split("name/")[-1])
                    break
                elif "onvif://www.onvif.org/hardware/" in scope:
                    inferred_name = urllib.parse.unquote(scope.split("hardware/")[-1])
                    break

            return {
                "ip": resolved_ip,
                "types": types_found,
                "xaddrs": xaddrs_found,
                "scopes": scopes_found,
                "device_name": inferred_name,
                "is_onvif": any("onvif" in s.lower() or "onvif" in t.lower() for s in scopes_found for t in types_found),
            }
        except Exception:
            return None

    def scan(self, timeout: float = 1.5) -> Dict[str, Dict[str, Any]]:
        """
        Sends WS-Discovery Probes and returns discovered devices indexed by IP address.
        """
        pkt = self.build_probe()
        results: Dict[str, Dict[str, Any]] = {}
        sock = None

        try:
            sock = create_udp_socket(interface=self.interface, broadcast=True, timeout=0.4)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.sendto(pkt, (self.WS_DISCOVERY_GROUP, self.WS_DISCOVERY_PORT))

            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    xml_text = data.decode("utf-8", errors="replace")
                    parsed = self.parse_probe_match(xml_text, addr[0])
                    if parsed and parsed.get("ip"):
                        dev_ip = parsed["ip"]
                        results[dev_ip] = parsed
                except socket.timeout:
                    continue
                except Exception:
                    break

        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return results
