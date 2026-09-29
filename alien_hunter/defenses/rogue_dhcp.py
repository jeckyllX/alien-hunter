"""
Rogue DHCP Server & Gateway Hijack Canary Guard.
Passively monitors UDP 67/68 traffic for unauthorized DHCPOFFER and DHCPACK packets,
and actively emits canary DHCP Discover probes to detect rogue DHCP servers,
default gateway hijacking, and rogue DNS advertising (Responder, dnsmasq, WiFi Pineapple).
MITRE ATT&CK T1557 (Adversary-in-the-Middle).
"""

import collections
import os
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class RogueDhcpEvent:
    """Represents a detected rogue DHCP server, gateway hijack, or DNS hijacking event."""

    def __init__(
        self,
        threat_type: str,
        server_ip: str,
        server_mac: Optional[str] = None,
        offered_ip: Optional[str] = None,
        offered_router: Optional[str] = None,
        offered_dns: Optional[List[str]] = None,
        offered_domain: Optional[str] = None,
        lease_time: Optional[int] = None,
        server_id: Optional[str] = None,
        expected_gateway_ip: Optional[str] = None,
        expected_gateway_mac: Optional[str] = None,
        is_canary: bool = False,
        timestamp: float = 0.0,
        multiple_servers: Optional[List[str]] = None,
    ):
        self.threat_type = threat_type
        self.server_ip = server_ip
        self.server_mac = server_mac.upper() if server_mac else None
        self.offered_ip = offered_ip
        self.offered_router = offered_router
        self.offered_dns = offered_dns or []
        self.offered_domain = offered_domain
        self.lease_time = lease_time
        self.server_id = server_id
        self.expected_gateway_ip = expected_gateway_ip
        self.expected_gateway_mac = expected_gateway_mac.upper() if expected_gateway_mac else None
        self.is_canary = is_canary
        self.timestamp = timestamp or time.time()
        self.multiple_servers = multiple_servers or []

    def to_threat_string(self) -> str:
        canary_prefix = "[Canary Trap] " if self.is_canary else ""
        mac_info = f" [{self.server_mac}]" if self.server_mac else ""
        server_id_info = f" (Server-ID: {self.server_id})" if self.server_id and self.server_id != self.server_ip else ""

        if self.threat_type == "ROGUE_SERVER":
            lease_info = f" offering IP {self.offered_ip}" if self.offered_ip else ""
            router_info = f" with advertised Router: {self.offered_router}" if self.offered_router else ""
            expected_info = (
                f" (Expected Gateway: {self.expected_gateway_ip}"
                f"{f' [{self.expected_gateway_mac}]' if self.expected_gateway_mac else ''})"
                if self.expected_gateway_ip
                else ""
            )
            return (
                f"CRITICAL: {canary_prefix}Rogue DHCP Server detected! "
                f"Unauthorized server at {self.server_ip}{mac_info}{server_id_info}{lease_info}{router_info}{expected_info}! "
                f"Potential Adversary-in-the-Middle or rogue router on the network (MITRE ATT&CK T1557)."
            )

        elif self.threat_type == "GATEWAY_HIJACK":
            return (
                f"CRITICAL: {canary_prefix}DHCP Gateway Hijacking detected! "
                f"DHCP Server {self.server_ip}{mac_info}{server_id_info} is offering rogue default gateway "
                f"{self.offered_router} (Expected legitimate Gateway: {self.expected_gateway_ip or 'Unknown'})! "
                f"Adversary attempting full network traffic interception (MITRE ATT&CK T1557)."
            )

        elif self.threat_type == "DNS_HIJACK":
            dns_list = ", ".join(self.offered_dns)
            return (
                f"CRITICAL: {canary_prefix}DHCP DNS Hijacking detected! "
                f"DHCP Server {self.server_ip}{mac_info}{server_id_info} is advertising unauthorized DNS server(s): "
                f"[{dns_list}]! Potential credential harvesting or C2 redirection (MITRE ATT&CK T1557)."
            )

        elif self.threat_type == "MULTIPLE_SERVERS":
            srv_str = ", ".join(self.multiple_servers) if self.multiple_servers else self.server_ip
            return (
                f"WARNING: {canary_prefix}Multiple DHCP Servers active on the local link: [{srv_str}]. "
                f"Conflicting or rogue DHCP services can cause IP collisions and session hijacking."
            )

        else:
            return (
                f"CRITICAL: {canary_prefix}DHCP Protocol Anomaly detected from server {self.server_ip}{mac_info}! "
                f"(MITRE ATT&CK T1557)."
            )


class RogueDhcpGuard:
    """
    Guards against rogue DHCP servers, gateway redirection, and unauthorized DNS advertising
    through continuous passive offer monitoring and active canary probes.
    """

    SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1

    MAGIC_COOKIE = b"\x63\x82\x53\x63"

    def __init__(
        self,
        interface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        authorized_dhcp_ips: Optional[Set[str]] = None,
        authorized_dhcp_macs: Optional[Set[str]] = None,
        alert_cooldown: float = 30.0,
    ):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.upper() if gateway_mac else None
        self.authorized_dhcp_ips: Set[str] = set(authorized_dhcp_ips or [])
        self.authorized_dhcp_macs: Set[str] = {m.upper() for m in (authorized_dhcp_macs or [])}

        if self.gateway_ip:
            self.authorized_dhcp_ips.add(self.gateway_ip)
        if self.gateway_mac:
            self.authorized_dhcp_macs.add(self.gateway_mac)

        self.alert_cooldown = alert_cooldown

        # Telemetry: server_ip -> details dict
        self._observed_servers: Dict[str, Dict[str, Any]] = {}
        # Cooldown: (threat_type, server_ip, server_mac) -> timestamp
        self._last_alert_times: Dict[Tuple[str, str, str], float] = collections.defaultdict(float)
        self._detected_events: List[RogueDhcpEvent] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def update_topology(
        self,
        gateway_ip: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        authorized_dhcp_ips: Optional[Set[str]] = None,
        authorized_dhcp_macs: Optional[Set[str]] = None,
    ):
        """Updates network baseline and trusted DHCP server identities dynamically."""
        with self._lock:
            if gateway_ip:
                self.gateway_ip = gateway_ip
                self.authorized_dhcp_ips.add(gateway_ip)
            if gateway_mac:
                self.gateway_mac = gateway_mac.upper()
                self.authorized_dhcp_macs.add(self.gateway_mac)
            if authorized_dhcp_ips is not None:
                self.authorized_dhcp_ips.update(authorized_dhcp_ips)
            if authorized_dhcp_macs is not None:
                self.authorized_dhcp_macs.update({m.upper() for m in authorized_dhcp_macs})

    @staticmethod
    def _calc_ip_checksum(data: bytes) -> int:
        """Calculates RFC 791 IPv4 16-bit one's complement header checksum."""
        if len(data) % 2 == 1:
            data += b"\x00"
        s = sum(struct.unpack(f"!{len(data)//2}H", data))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    @staticmethod
    def build_dhcp_discover(xid: bytes, chaddr_bytes: bytes, broadcast: bool = True) -> bytes:
        """
        Builds RFC 2131 BOOTP/DHCP DISCOVER payload with parameter request list.
        """
        flags = b"\x80\x00" if broadcast else b"\x00\x00"
        pkt = bytearray(240)
        pkt[0] = 1  # BOOTREQUEST
        pkt[1] = 1  # HTYPE: 10mb ethernet
        pkt[2] = 6  # HLEN: 6 bytes MAC
        pkt[3] = 0  # HOPS
        pkt[4:8] = xid
        pkt[8:10] = b"\x00\x00"  # SECS
        pkt[10:12] = flags
        pkt[12:16] = b"\x00\x00\x00\x00"  # CIADDR
        pkt[16:20] = b"\x00\x00\x00\x00"  # YIADDR
        pkt[20:24] = b"\x00\x00\x00\x00"  # SIADDR
        pkt[24:28] = b"\x00\x00\x00\x00"  # GIADDR
        pkt[28 : 28 + len(chaddr_bytes)] = chaddr_bytes
        pkt[236:240] = RogueDhcpGuard.MAGIC_COOKIE

        # DHCP Options:
        # Option 53: DHCP Discover (type 1)
        pkt.extend(b"\x35\x01\x01")
        # Option 55: Parameter Request List (1=Subnet Mask, 3=Router, 6=DNS, 15=Domain, 28=Bcast, 51=Lease, 54=Server-ID)
        pkt.extend(b"\x37\x07\x01\x03\x06\x0f\x1c\x33\x36")
        # Option 255: End
        pkt.extend(b"\xff")
        return bytes(pkt)

    @classmethod
    def build_raw_dhcp_discover_frame(cls, xid: bytes, chaddr_mac: str) -> bytes:
        """
        Builds complete Layer 2 Ethernet frame (Ethernet + IPv4 + UDP + DHCP Discover).
        """
        clean_mac = chaddr_mac.replace(":", "").replace("-", "")
        chaddr_bytes = bytes.fromhex(clean_mac) if len(clean_mac) == 12 else b"\x02\x42" + os.urandom(4)

        dhcp_payload = cls.build_dhcp_discover(xid=xid, chaddr_bytes=chaddr_bytes, broadcast=True)

        # UDP Header: SrcPort=68, DstPort=67, Len, Checksum=0 (RFC 768 disabled)
        udp_len = 8 + len(dhcp_payload)
        udp_hdr = struct.pack("!HHHH", 68, 67, udp_len, 0)

        # IPv4 Header: Version=4, IHL=5, DSCP/ECN=0, TotalLen, ID, Flags=0, TTL=64, Proto=17 (UDP), Checksum, Src=0.0.0.0, Dst=255.255.255.255
        ip_total_len = 20 + udp_len
        ip_hdr_no_cksum = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            int.from_bytes(os.urandom(2), "big"),
            0,
            64,
            17,
            0,
            socket.inet_aton("0.0.0.0"),
            socket.inet_aton("255.255.255.255"),
        )
        ip_cksum = cls._calc_ip_checksum(ip_hdr_no_cksum)
        ip_hdr = ip_hdr_no_cksum[:10] + struct.pack("!H", ip_cksum) + ip_hdr_no_cksum[12:]

        # Ethernet Header: Dst=FF:FF:FF:FF:FF:FF, Src=chaddr_bytes, EtherType=0x0800
        eth_hdr = b"\xff\xff\xff\xff\xff\xff" + chaddr_bytes + struct.pack("!H", 0x0800)

        return eth_hdr + ip_hdr + udp_hdr + dhcp_payload

    @classmethod
    def parse_dhcp_packet(cls, pkt: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses raw Layer-2 Ethernet frame or bare UDP datagram into DHCP fields.
        Returns parsed dict or None if invalid or not a DHCP frame.
        """
        src_mac = None
        dst_mac = None
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        bootp_data = None

        # Check if frame has Ethernet Header (14 bytes)
        if len(pkt) >= 282 and struct.unpack("!H", pkt[12:14])[0] == 0x0800:
            dst_mac = ":".join(f"{b:02X}" for b in pkt[0:6])
            src_mac = ":".join(f"{b:02X}" for b in pkt[6:12])

            v_ihl = pkt[14]
            if (v_ihl >> 4) != 4:
                return None
            ihl = (v_ihl & 0x0F) * 4
            if ihl < 20 or len(pkt) < 14 + ihl + 8 + 240:
                return None

            proto = pkt[23]
            if proto != 17:  # IPPROTO_UDP
                return None

            src_ip = socket.inet_ntoa(pkt[26:30])
            dst_ip = socket.inet_ntoa(pkt[30:34])

            udp_off = 14 + ihl
            src_port, dst_port = struct.unpack("!HH", pkt[udp_off : udp_off + 4])
            bootp_data = pkt[udp_off + 8 :]

        # Bare UDP / BOOTP packet (e.g. from recvfrom on UDP socket)
        elif len(pkt) >= 240:
            bootp_data = pkt

        if not bootp_data or len(bootp_data) < 240:
            return None

        # Verify BOOTP magic cookie
        if bootp_data[236:240] != cls.MAGIC_COOKIE:
            return None

        op = bootp_data[0]
        htype = bootp_data[1]
        hlen = bootp_data[2]
        xid = bootp_data[4:8]
        ciaddr = socket.inet_ntoa(bootp_data[12:16])
        yiaddr = socket.inet_ntoa(bootp_data[16:20])
        siaddr = socket.inet_ntoa(bootp_data[20:24])
        giaddr = socket.inet_ntoa(bootp_data[24:28])

        chaddr_bytes = bootp_data[28 : 28 + hlen] if hlen == 6 else bootp_data[28:34]
        chaddr_mac = ":".join(f"{b:02X}" for b in chaddr_bytes)

        # Parse DHCP Options
        options = bootp_data[240:]
        msg_type: Optional[int] = None
        subnet_mask: Optional[str] = None
        routers: List[str] = []
        dns_servers: List[str] = []
        domain_name: Optional[str] = None
        lease_time: Optional[int] = None
        server_id: Optional[str] = None

        idx = 0
        while idx < len(options):
            opt = options[idx]
            if opt == 255:  # End of options
                break
            if opt == 0:  # Pad
                idx += 1
                continue
            if idx + 1 >= len(options):
                break
            opt_len = options[idx + 1]
            if idx + 2 + opt_len > len(options):
                break
            opt_val = options[idx + 2 : idx + 2 + opt_len]

            if opt == 53 and opt_len >= 1:
                msg_type = opt_val[0]
            elif opt == 1 and opt_len == 4:
                subnet_mask = socket.inet_ntoa(opt_val)
            elif opt == 3 and opt_len >= 4:
                for off in range(0, opt_len - 3, 4):
                    routers.append(socket.inet_ntoa(opt_val[off : off + 4]))
            elif opt == 6 and opt_len >= 4:
                for off in range(0, opt_len - 3, 4):
                    dns_servers.append(socket.inet_ntoa(opt_val[off : off + 4]))
            elif opt == 15 and opt_len > 0:
                try:
                    domain_name = opt_val.decode("utf-8", errors="ignore").strip("\x00")
                except Exception:
                    pass
            elif opt == 51 and opt_len == 4:
                lease_time = struct.unpack("!I", opt_val)[0]
            elif opt == 54 and opt_len == 4:
                server_id = socket.inet_ntoa(opt_val)

            idx += 2 + opt_len

        return {
            "op": op,
            "xid": xid,
            "ciaddr": ciaddr,
            "yiaddr": yiaddr,
            "siaddr": siaddr,
            "giaddr": giaddr,
            "chaddr": chaddr_mac,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "msg_type": msg_type,
            "subnet_mask": subnet_mask,
            "routers": routers,
            "dns_servers": dns_servers,
            "domain_name": domain_name,
            "lease_time": lease_time,
            "server_id": server_id,
        }

    def process_packet(
        self,
        pkt: bytes,
        now: Optional[float] = None,
        expected_xid: Optional[bytes] = None,
        is_canary: bool = False,
    ) -> List[RogueDhcpEvent]:
        """
        Inspects an incoming frame. Identifies rogue DHCPOFFER and DHCPACK packets,
        detects gateway hijacking, and tracks active DHCP servers.
        """
        parsed = self.parse_dhcp_packet(pkt)
        if not parsed:
            return []

        # Only evaluate server replies: BOOTREPLY (op == 2)
        # Message types: 2 (DHCPOFFER), 5 (DHCPACK)
        if parsed["op"] != 2:
            return []

        msg_type = parsed["msg_type"]
        if msg_type not in (2, 5):
            return []

        # If filtering by canary transaction ID, ignore mismatched frames
        if expected_xid is not None and parsed["xid"] != expected_xid:
            return []

        if now is None:
            now = time.time()

        server_ip = parsed.get("server_id") or parsed.get("src_ip") or parsed.get("siaddr") or "0.0.0.0"
        server_mac = parsed.get("src_mac") or ""
        offered_router = parsed["routers"][0] if parsed["routers"] else None
        offered_ip = parsed["yiaddr"] if parsed["yiaddr"] != "0.0.0.0" else None

        events: List[RogueDhcpEvent] = []

        with self._lock:
            # Track server inventory
            self._observed_servers[server_ip] = {
                "server_ip": server_ip,
                "server_mac": server_mac,
                "server_id": parsed.get("server_id"),
                "offered_ip": offered_ip,
                "offered_router": offered_router,
                "dns_servers": parsed["dns_servers"],
                "domain_name": parsed["domain_name"],
                "lease_time": parsed["lease_time"],
                "last_seen": now,
            }

            # 1. Check for Rogue DHCP Server identity
            is_authorized_ip = (
                not self.authorized_dhcp_ips
                or server_ip in self.authorized_dhcp_ips
                or (parsed.get("src_ip") and parsed["src_ip"] in self.authorized_dhcp_ips)
            )

            is_authorized_mac = (
                not self.authorized_dhcp_macs
                or not server_mac
                or server_mac.upper() in self.authorized_dhcp_macs
            )

            is_rogue_server = not (is_authorized_ip and is_authorized_mac)

            if is_rogue_server:
                key = ("ROGUE_SERVER", server_ip, server_mac)
                if now - self._last_alert_times[key] >= self.alert_cooldown:
                    self._last_alert_times[key] = now
                    ev = RogueDhcpEvent(
                        threat_type="ROGUE_SERVER",
                        server_ip=server_ip,
                        server_mac=server_mac,
                        offered_ip=offered_ip,
                        offered_router=offered_router,
                        offered_dns=parsed["dns_servers"],
                        offered_domain=parsed["domain_name"],
                        lease_time=parsed["lease_time"],
                        server_id=parsed.get("server_id"),
                        expected_gateway_ip=self.gateway_ip,
                        expected_gateway_mac=self.gateway_mac,
                        is_canary=is_canary,
                        timestamp=now,
                    )
                    self._detected_events.append(ev)
                    events.append(ev)

            # 2. Check for Gateway Hijacking (Advertised router != legitimate gateway)
            if offered_router and self.gateway_ip and offered_router != self.gateway_ip:
                key = ("GATEWAY_HIJACK", server_ip, offered_router)
                if now - self._last_alert_times[key] >= self.alert_cooldown:
                    self._last_alert_times[key] = now
                    ev = RogueDhcpEvent(
                        threat_type="GATEWAY_HIJACK",
                        server_ip=server_ip,
                        server_mac=server_mac,
                        offered_ip=offered_ip,
                        offered_router=offered_router,
                        offered_dns=parsed["dns_servers"],
                        offered_domain=parsed["domain_name"],
                        lease_time=parsed["lease_time"],
                        server_id=parsed.get("server_id"),
                        expected_gateway_ip=self.gateway_ip,
                        expected_gateway_mac=self.gateway_mac,
                        is_canary=is_canary,
                        timestamp=now,
                    )
                    self._detected_events.append(ev)
                    events.append(ev)

        return events

    def probe_canary(
        self,
        timeout: float = 2.0,
        canary_mac: Optional[str] = None,
    ) -> List[RogueDhcpEvent]:
        """
        Actively emits a benign canary DHCP Discover probe with a unique transaction ID.
        Listens for responses to detect rogue servers, gateway hijacking, and multiple DHCP listeners.
        """
        if not canary_mac:
            # Generate locally administered unicast MAC: 02:xx:xx:xx:xx:xx
            rand_bytes = os.urandom(5)
            canary_mac = ":".join(f"{b:02X}" for b in (b"\x02" + rand_bytes))

        canary_xid = os.urandom(4)
        events: List[RogueDhcpEvent] = []
        observed_probe_servers: Dict[str, Dict[str, Any]] = {}

        # 1. Attempt sending and listening via AF_PACKET raw socket first
        raw_sock = None
        udp_sock = None
        mreq = None

        try:
            # Try raw socket setup for full Layer-2 frame capture
            try:
                raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface:
                    raw_sock.bind((self.interface, 0))
                    try:
                        ifindex = socket.if_nametoindex(self.interface)
                        mreq = struct.pack("IHH8s", ifindex, self.PACKET_MR_PROMISC, 0, b"")
                        raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
                    except Exception:
                        pass
                raw_sock.settimeout(0.4)

                # Send raw Ethernet Discover frame
                discover_frame = self.build_raw_dhcp_discover_frame(canary_xid, canary_mac)
                if self.interface:
                    raw_sock.sendto(discover_frame, (self.interface, 0))
                else:
                    raw_sock.send(discover_frame)
            except Exception:
                # Raw socket unavailable (non-root or platform limit); fallback to UDP broadcast
                if raw_sock:
                    try:
                        raw_sock.close()
                    except Exception:
                        pass
                    raw_sock = None

            if not raw_sock:
                # Fallback: standard UDP broadcast socket
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    udp_sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_REUSEPORT", 15), 1)
                except Exception:
                    pass
                if self.interface:
                    try:
                        udp_sock.setsockopt(socket.SOL_SOCKET, 25, (self.interface + "\0").encode("utf-8"))
                    except Exception:
                        pass

                clean_mac = canary_mac.replace(":", "").replace("-", "")
                ch_bytes = bytes.fromhex(clean_mac)
                payload = self.build_dhcp_discover(canary_xid, ch_bytes, broadcast=True)

                try:
                    udp_sock.bind(("0.0.0.0", 68))
                except Exception:
                    pass

                udp_sock.settimeout(0.5)
                udp_sock.sendto(payload, ("255.255.255.255", 67))

            # Receive loop for timeout duration
            start_time = time.time()
            active_sock = raw_sock if raw_sock else udp_sock

            while time.time() - start_time < timeout:
                try:
                    data, addr = active_sock.recvfrom(2048)
                    evs = self.process_packet(
                        data,
                        expected_xid=canary_xid,
                        is_canary=True,
                    )
                    if evs:
                        events.extend(evs)

                    parsed = self.parse_dhcp_packet(data)
                    if parsed and parsed["op"] == 2 and parsed["xid"] == canary_xid:
                        srv_key = parsed.get("server_id") or parsed.get("src_ip") or addr[0]
                        observed_probe_servers[srv_key] = parsed

                except socket.timeout:
                    continue
                except Exception:
                    break

            # 3. Check for multiple distinct DHCP servers responding to same canary
            if len(observed_probe_servers) > 1:
                server_list = list(observed_probe_servers.keys())
                now = time.time()
                key = ("MULTIPLE_SERVERS", ",".join(sorted(server_list)), "")
                if now - self._last_alert_times[key] >= self.alert_cooldown:
                    self._last_alert_times[key] = now
                    multi_ev = RogueDhcpEvent(
                        threat_type="MULTIPLE_SERVERS",
                        server_ip=server_list[0],
                        multiple_servers=server_list,
                        is_canary=True,
                        timestamp=now,
                    )
                    with self._lock:
                        self._detected_events.append(multi_ev)
                    events.append(multi_ev)

        except Exception:
            pass
        finally:
            if raw_sock:
                if mreq:
                    try:
                        raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_DROP_MEMBERSHIP, mreq)
                    except Exception:
                        pass
                try:
                    raw_sock.close()
                except Exception:
                    pass
            if udp_sock:
                try:
                    udp_sock.close()
                except Exception:
                    pass

        return events

    def sniff(self, duration: float = 2.0) -> List[RogueDhcpEvent]:
        """
        Passively sniffs Layer-2 frames for DHCP server traffic for duration seconds.
        """
        events: List[RogueDhcpEvent] = []
        raw_sock = None
        mreq = None

        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                raw_sock.bind((self.interface, 0))
                try:
                    ifindex = socket.if_nametoindex(self.interface)
                    mreq = struct.pack("IHH8s", ifindex, self.PACKET_MR_PROMISC, 0, b"")
                    raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
                except Exception:
                    mreq = None

            raw_sock.settimeout(0.5)
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    pkt, _ = raw_sock.recvfrom(2048)
                    evs = self.process_packet(pkt, is_canary=False)
                    if evs:
                        events.extend(evs)
                except socket.timeout:
                    continue
        except Exception:
            pass
        finally:
            if raw_sock:
                if mreq:
                    try:
                        raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_DROP_MEMBERSHIP, mreq)
                    except Exception:
                        pass
                try:
                    raw_sock.close()
                except Exception:
                    pass

        return events

    def start(self) -> bool:
        """Starts background listener thread for continuous sentinel monitoring."""
        with self._lock:
            if self._running:
                return True
            try:
                test_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                test_sock.close()
            except Exception:
                return False

            self._running = True
            self._thread = threading.Thread(
                target=self._sniff_loop, daemon=True, name="RogueDhcpGuard"
            )
            self._thread.start()
            return True

    def stop(self):
        """Stops background listener thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    @property
    def is_running(self) -> bool:
        return self._running

    def _sniff_loop(self):
        """Continuous sniffing loop executed in daemon background thread."""
        raw_sock = None
        mreq = None
        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                raw_sock.bind((self.interface, 0))
                try:
                    ifindex = socket.if_nametoindex(self.interface)
                    mreq = struct.pack("IHH8s", ifindex, self.PACKET_MR_PROMISC, 0, b"")
                    raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
                except Exception:
                    mreq = None

            raw_sock.settimeout(1.0)
            while self._running:
                try:
                    pkt, _ = raw_sock.recvfrom(2048)
                    self.process_packet(pkt, is_canary=False)
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            if raw_sock:
                if mreq:
                    try:
                        raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_DROP_MEMBERSHIP, mreq)
                    except Exception:
                        pass
                try:
                    raw_sock.close()
                except Exception:
                    pass

    def get_threat_strings(self) -> List[str]:
        """Drains and returns all detected threat alert strings."""
        with self._lock:
            threats = [e.to_threat_string() for e in self._detected_events]
            self._detected_events.clear()
            return threats

    def get_server_inventory(self) -> List[Dict[str, Any]]:
        """Returns snapshot of all observed DHCP servers and advertised parameters."""
        with self._lock:
            return list(self._observed_servers.values())
