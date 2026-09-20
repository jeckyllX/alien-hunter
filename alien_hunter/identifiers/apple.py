"""
Apple Device Identifier and Bonjour Name Resolver.
Identifies Apple hardware (iPhones, Macs, iPads, Apple TVs) and extracts
their human-friendly names using Multicast DNS (Bonjour, RFC 6762) and DHCP client attributes.
"""

import re
import socket
import time
from typing import Optional, Tuple
from ..scanners.router import RouterDnsAuditor

# ============================================================================
# Multicast DNS (mDNS / Bonjour) Constants
# ============================================================================

# IANA assigned link-local IPv4 multicast address for Multicast DNS (RFC 6762)
MDNS_IPV4_MULTICAST: str = "224.0.0.251"

# Standard UDP port dedicated to Multicast DNS services
MDNS_UDP_PORT: int = 5353

# Default network timeout (seconds) when listening for mDNS multicast responses
DEFAULT_MDNS_TIMEOUT: float = 1.0

# ----------------------------------------------------------------------------
# Wire-Format DNS Header (RFC 1035 Section 4.1.1):
# Length: 12 bytes
# Breakdown:
#   - Bytes 0-1  (0x0000): Transaction ID. In mDNS (RFC 6762), ID must be 0 for multicast queries.
#   - Bytes 2-3  (0x0000): Flags. Standard query: QR=0 (Query), Opcode=0, AA=0, TC=0, RD=0.
#   - Bytes 4-5  (0x0001): QDCOUNT = 1 (Number of questions in the Question section).
#   - Bytes 6-7  (0x0000): ANCOUNT = 0 (Number of resource records in Answer section).
#   - Bytes 8-9  (0x0000): NSCOUNT = 0 (Number of name server resource records).
#   - Bytes 10-11(0x0000): ARCOUNT = 0 (Number of resource records in Additional section).
# ----------------------------------------------------------------------------
DNS_QUERY_HEADER_STANDALONE: bytes = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"

# ----------------------------------------------------------------------------
# Wire-Format DNS Question Trailer (RFC 1035 Section 4.1.2):
# Follows the QNAME labels to specify the query type and class:
#   - Bytes 0-1 (0x000c): QTYPE = 12 (PTR record - Pointer for reverse IP-to-hostname lookups).
#   - Bytes 2-3 (0x0001): QCLASS = 1 (IN - Internet class).
# ----------------------------------------------------------------------------
DNS_PTR_IN_TRAILER: bytes = b"\x00\x0c\x00\x01"


class AppleDeviceIdentifier:
    """Specialized resolver for Apple devices and Bonjour hostnames."""

    def __init__(self, mdns_timeout: float = DEFAULT_MDNS_TIMEOUT):
        self.mdns_timeout = mdns_timeout

    def resolve_mdns_name(self, ip: str) -> Optional[str]:
        """
        Constructs and sends a reverse PTR query over mDNS to uncover the local Bonjour name.
        Transmits both to the link-local multicast group (224.0.0.251:5353) and unicast directly to the host.
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return None

        # Build reverse DNS domain labels (e.g. 154.1.168.192.in-addr.arpa)
        rev_domain = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"

        # Wire-format DNS packet: [Header] + [QNAME Labels] + [QTYPE/QCLASS Trailer]
        query = DNS_QUERY_HEADER_STANDALONE
        for label in rev_domain.split("."):
            query += bytes([len(label)]) + label.encode("ascii")
        query += b"\x00"  # Zero-length octet terminating the QNAME domain
        query += DNS_PTR_IN_TRAILER

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.settimeout(self.mdns_timeout)
        resolved_name = None

        try:
            # Send multicast to the local subnet and unicast to the target host
            s.sendto(query, (MDNS_IPV4_MULTICAST, MDNS_UDP_PORT))
            s.sendto(query, (ip, MDNS_UDP_PORT))

            start = time.time()
            while time.time() - start < self.mdns_timeout:
                try:
                    data, addr = s.recvfrom(2048)
                    if addr[0] == ip:
                        # Parse DNS answer: skip 12-byte header, question section, and inspect PTR record
                        p = 12
                        _, p = RouterDnsAuditor.parse_dns_name(data, p)
                        p += 4  # skip QTYPE and QCLASS
                        if p < len(data):
                            _, p = RouterDnsAuditor.parse_dns_name(data, p)
                            p += 8  # skip TYPE(2), CLASS(2), TTL(4)
                            p += 2  # skip RDLENGTH(2)
                            rname, _ = RouterDnsAuditor.parse_dns_name(data, p)
                            if rname:
                                # Strip trailing .local domain
                                resolved_name = rname.replace(".local", "")
                                break
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            s.close()

        return resolved_name

    def identify(
        self, ip: str, mac: str, raw_hostname: str, vendor: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Evaluates whether a device belongs to the Apple ecosystem and extracts its human name.
        Returns:
            (is_apple: bool, model_type: Optional[str], best_name: Optional[str])
        """
        mdns_name = self.resolve_mdns_name(ip)
        clean_name = RouterDnsAuditor.clean_hostname(raw_hostname)
        best_name = mdns_name or clean_name or ""

        is_apple = False
        model_type = "Apple Device"

        # Check vendor OUI
        if "apple" in vendor.lower():
            is_apple = True

        # Check hostname and mDNS name for Apple device signatures
        check_str = f"{best_name} {raw_hostname or ''}".lower()
        if re.search(r"\b(iphone|ipad|ipod|macbook|imac|apple)\b", check_str) or re.search(
            r"\bmac\b", check_str
        ):
            is_apple = True

        # If not an Apple device, return clean resolved name without tagging as Apple
        if not is_apple:
            return False, None, best_name or None

        # Determine specific Apple device category
        if "iphone" in check_str:
            model_type = "Apple iPhone"
        elif "macbook" in check_str or "imac" in check_str or re.search(r"\bmac\b", check_str):
            model_type = "Apple Mac"
        elif "ipad" in check_str:
            model_type = "Apple iPad"
        elif "apple tv" in check_str or "appletv" in check_str:
            model_type = "Apple TV"

        return True, model_type, best_name or model_type
