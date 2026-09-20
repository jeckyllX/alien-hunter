"""
Active SSDP / UPnP Discovery Scanner.
Discovers hidden Smart TVs, IoT hubs, cameras, media players, and smart speakers
broadcasting UPnP device descriptors on UDP port 1900.
"""

import re
import socket
import time
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from .net_utils import create_udp_socket, get_subnet_broadcast



class SsdpScanner:
    """Active SSDP (Simple Service Discovery Protocol) scanner for UPnP device profiling."""

    SSDP_MULTICAST_ADDR = "239.255.255.250"
    SSDP_PORT = 1900

    def __init__(self, local_ip: Optional[str] = None):
        self.local_ip = local_ip

    def scan(self, timeout: float = 2.0, fetch_details: bool = True) -> Dict[str, Dict[str, Any]]:
        """
        Broadcasts and multicasts SSDP M-SEARCH probes.
        Returns a dictionary of discovered devices indexed by IP address:
        {
            ip: {
                "server": str,
                "location": str,
                "device_name": Optional[str],
                "manufacturer": Optional[str],
                "model": Optional[str],
                "services": List[str],
            }
        }
        """
        results: Dict[str, Dict[str, Any]] = {}
        sock = None

        msearch_msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {self.SSDP_MULTICAST_ADDR}:{self.SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode("utf-8")

        try:
            sock = create_udp_socket(timeout=0.5)

            # Set Multicast interface if local IP is known
            if self.local_ip:
                try:
                    sock.setsockopt(
                        socket.IPPROTO_IP,
                        socket.IP_MULTICAST_IF,
                        socket.inet_aton(self.local_ip),
                    )
                except Exception:
                    pass

            # Multicast TTL = 2
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            except Exception:
                pass

            # Transmit M-SEARCH to standard SSDP multicast and broadcasts
            destinations = [(self.SSDP_MULTICAST_ADDR, self.SSDP_PORT), ("255.255.255.255", self.SSDP_PORT)]
            subnet_bcast = get_subnet_broadcast(self.local_ip)
            if subnet_bcast:
                destinations.append((subnet_bcast, self.SSDP_PORT))


            for dst in destinations:
                try:
                    sock.sendto(msearch_msg, dst)
                except Exception:
                    pass

            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    raw_text = data.decode("utf-8", errors="ignore")
                    headers = self._parse_headers(raw_text)

                    if ip not in results:
                        results[ip] = {
                            "server": headers.get("server", ""),
                            "location": headers.get("location", ""),
                            "device_name": None,
                            "manufacturer": None,
                            "model": None,
                            "services": [],
                        }

                    st = headers.get("st")
                    if st and st not in results[ip]["services"]:
                        results[ip]["services"].append(st)

                    # Update server/location if missing
                    if not results[ip]["server"] and headers.get("server"):
                        results[ip]["server"] = headers.get("server")
                    if not results[ip]["location"] and headers.get("location"):
                        results[ip]["location"] = headers.get("location")

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

        # Optionally inspect XML description descriptors
        if fetch_details:
            for ip, info in results.items():
                location = info.get("location")
                if location and location.startswith("http://"):
                    desc = self._fetch_device_descriptor(location)
                    if desc:
                        if desc.get("device_name"):
                            info["device_name"] = desc["device_name"]
                        if desc.get("manufacturer"):
                            info["manufacturer"] = desc["manufacturer"]
                        if desc.get("model"):
                            info["model"] = desc["model"]

        return results

    @staticmethod
    def _parse_headers(raw_text: str) -> Dict[str, str]:
        """Parses HTTP/SSDP header key-value pairs in a case-insensitive manner."""
        headers: Dict[str, str] = {}
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("HTTP/") or line.startswith("NOTIFY"):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()
        return headers

    @staticmethod
    def _fetch_device_descriptor(url: str, timeout: float = 0.8) -> Optional[Dict[str, str]]:
        """
        Fetches and extracts metadata (<friendlyName>, <manufacturer>, <modelName>)
        from an advertised UPnP XML device description descriptor.
        """
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AlienHunter/2.0 SSDP-Probe"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    xml_content = response.read(16384)
                    root = ET.fromstring(xml_content)

                    # Scan for tags regardless of XML namespace
                    friendly_name = None
                    manufacturer = None
                    model = None

                    for elem in root.iter():
                        tag = elem.tag.split("}")[-1].lower()
                        text = (elem.text or "").strip()
                        if not text:
                            continue
                        if tag == "friendlyname" and not friendly_name:
                            friendly_name = text
                        elif tag == "manufacturer" and not manufacturer:
                            manufacturer = text
                        elif (tag in ("modelname", "modelnumber")) and not model:
                            model = text

                    return {
                        "device_name": friendly_name or "",
                        "manufacturer": manufacturer or "",
                        "model": model or "",
                    }
        except Exception:
            pass
        return None
