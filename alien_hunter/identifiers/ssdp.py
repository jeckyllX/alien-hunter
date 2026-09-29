"""
SSDP / UPnP Device Harvester and Passive Listener.
Captures SSDP NOTIFY broadcasts and M-SEARCH responses on UDP port 1900 (239.255.255.250)
to fingerprint Smart TVs, streaming players, IoT bridges, and gaming consoles.
"""

import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from .signatures import SignatureManager, SsdpFingerprintStore, DeviceFingerprintMatch


class SsdpParser:
    """Parses raw SSDP/UPnP HTTP-like datagram payloads."""

    @staticmethod
    def parse_headers(raw_data: bytes) -> Dict[str, str]:
        """Parses case-insensitive HTTP-like headers from raw SSDP payload bytes."""
        headers: Dict[str, str] = {}
        try:
            text = raw_data.decode("utf-8", errors="ignore")
        except Exception:
            return headers

        lines = text.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("NOTIFY") or line.startswith("M-SEARCH") or line.startswith("HTTP/"):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()
        return headers

    @classmethod
    def process_payload(
        cls,
        data: bytes,
        src_ip: str,
        sig_manager: Optional[SignatureManager] = None,
        now: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Parses an incoming SSDP datagram, correlates against registered SSDP signatures,
        and records the result in SsdpFingerprintStore.
        """
        if not data or not src_ip:
            return None

        headers = cls.parse_headers(data)
        if not headers:
            return None

        server = headers.get("server", "")
        target = headers.get("st") or headers.get("nt") or ""
        location = headers.get("location", "")

        mgr = sig_manager or SignatureManager()
        match: Optional[DeviceFingerprintMatch] = mgr.match_ssdp(server=server, target=target)

        services = [target] if target else []
        SsdpFingerprintStore.get_instance().record(
            ip=src_ip,
            server=server or None,
            location=location or None,
            services=services,
            match=match,
            now=now,
        )

        return {
            "ip": src_ip,
            "server": server,
            "target": target,
            "location": location,
            "match": match,
        }


class SsdpListener:
    """
    Background multicast listener for SSDP / UPnP datagrams on UDP 1900.
    Passively intercepts NOTIFY announcements as IoT devices join or refresh their lease.
    """

    SSDP_MULTICAST_ADDR = "239.255.255.250"
    SSDP_PORT = 1900

    def __init__(
        self,
        interface_ip: Optional[str] = None,
        sig_manager: Optional[SignatureManager] = None,
    ):
        self.interface_ip = interface_ip
        self.sig_manager = sig_manager or SignatureManager()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> bool:
        """Starts the SSDP listener daemon thread."""
        with self._lock:
            if self._running:
                return True

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # SO_REUSEPORT if supported on Linux
                if hasattr(socket, "SO_REUSEPORT"):
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except Exception:
                        pass

                sock.bind(("", self.SSDP_PORT))

                # Join 239.255.255.250 multicast group
                if self.interface_ip:
                    mreq = struct.pack(
                        "4s4s",
                        socket.inet_aton(self.SSDP_MULTICAST_ADDR),
                        socket.inet_aton(self.interface_ip),
                    )
                else:
                    mreq = struct.pack(
                        "4sl",
                        socket.inet_aton(self.SSDP_MULTICAST_ADDR),
                        socket.INADDR_ANY,
                    )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                sock.settimeout(1.0)
                self._sock = sock
                self._running = True

                self._thread = threading.Thread(
                    target=self._listen_loop, daemon=True, name="SsdpListener"
                )
                self._thread.start()
                return True
            except Exception:
                if self._sock:
                    try:
                        self._sock.close()
                    except Exception:
                        pass
                    self._sock = None
                return False

    def stop(self):
        """Stops the SSDP listener."""
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def is_running(self) -> bool:
        return self._running

    def _listen_loop(self):
        while self._running:
            try:
                if not self._sock:
                    break
                data, addr = self._sock.recvfrom(4096)
                if data and addr:
                    SsdpParser.process_payload(
                        data=data,
                        src_ip=addr[0],
                        sig_manager=self.sig_manager,
                    )
            except socket.timeout:
                continue
            except Exception:
                if not self._running:
                    break
                time.sleep(0.1)

    def sniff(self, duration: float = 2.0) -> List[Dict[str, Any]]:
        """Synchronously captures SSDP packets over a given duration."""
        results: List[Dict[str, Any]] = []
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except Exception:
                    pass
            sock.bind(("", self.SSDP_PORT))
            mreq = struct.pack("4sl", socket.inet_aton(self.SSDP_MULTICAST_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(0.5)

            start = time.time()
            while time.time() - start < duration:
                try:
                    data, addr = sock.recvfrom(4096)
                    res = SsdpParser.process_payload(
                        data=data,
                        src_ip=addr[0],
                        sig_manager=self.sig_manager,
                    )
                    if res:
                        results.append(res)
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
