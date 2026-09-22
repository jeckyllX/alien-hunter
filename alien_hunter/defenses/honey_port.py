"""
Decoy Honey-Port Canary Listener.
Binds non-blocking decoy TCP sockets to detect internal reconnaissance,
lateral movement, and worm propagation by compromised network hosts.
"""

import select
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple, Any


from .honey_auth import HoneyAuthTrap


class HoneyPortEvent:
    """Represents a connection attempt against a decoy honey-port."""

    def __init__(
        self,
        src_ip: str,
        src_port: int,
        dest_port: int,
        timestamp: float,
        payload_snippet: str = "",
        tooling: str = "",
        credentials: str = "",
    ):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.timestamp = timestamp
        self.payload_snippet = payload_snippet
        self.tooling = tooling
        self.credentials = credentials

    def to_threat_string(self) -> str:
        details = []
        if self.tooling:
            details.append(f"Tooling: {self.tooling}")
        if self.payload_snippet:
            details.append(f"Payload: {self.payload_snippet}")
        if self.credentials:
            details.append(f"Attempted Credentials: {self.credentials}")
        detail_str = f" [{', '.join(details)}]" if details else ""
        return (
            f"CRITICAL: Honey-Port Canary Triggered! Host at {self.src_ip} (port {self.src_port}) "
            f"attempted connection to decoy honeypot port {self.dest_port}!{detail_str} "
            f"Active internal reconnaissance, lateral movement, or worm scanning detected!"
        )


class HoneyPortListener:
    """
    Manages non-blocking decoy listeners on high-attraction decoy ports.
    """

    DEFAULT_DECOY_PORTS = [5555, 2323, 8888]

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        on_intrusion: Optional[Callable[[HoneyPortEvent], None]] = None,
        bind_host: str = "0.0.0.0",
    ):
        self.requested_ports = ports or self.DEFAULT_DECOY_PORTS
        self.on_intrusion = on_intrusion
        self.bind_host = bind_host
        self.active_sockets: Dict[int, socket.socket] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.detected_events: List[HoneyPortEvent] = []

    def start(self) -> List[int]:
        """
        Binds to requested decoy ports that are available and starts background listener thread.
        Returns list of successfully bound decoy ports.
        """
        bound_ports: List[int] = []
        with self._lock:
            for port in self.requested_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((self.bind_host, port))
                    s.listen(5)
                    s.setblocking(False)
                    self.active_sockets[port] = s
                    bound_ports.append(port)
                except Exception:
                    # Port already in use by host or permission denied (<1024 without root)
                    continue

            if bound_ports and not self._running:
                self._running = True
                self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="HoneyPortListener")
                self._thread.start()

        return bound_ports

    def stop(self):
        """Stops the listener thread and closes all decoy sockets."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

        with self._lock:
            for port, s in list(self.active_sockets.items()):
                try:
                    s.close()
                except Exception:
                    pass
            self.active_sockets.clear()

    def _listen_loop(self):
        """Internal select-based loop monitoring decoy sockets."""
        while self._running:
            with self._lock:
                sockets_list = list(self.active_sockets.values())

            if not sockets_list:
                break

            try:
                readable, _, _ = select.select(sockets_list, [], [], 0.5)
                for s in readable:
                    try:
                        conn, addr = s.accept()
                        src_ip, src_port = addr[0], addr[1]
                        dest_port = s.getsockname()[1]
                        meta = HoneyAuthTrap.inspect_connection(conn, dest_port)
                        try:
                            conn.close()
                        except Exception:
                            pass

                        event = HoneyPortEvent(
                            src_ip=src_ip,
                            src_port=src_port,
                            dest_port=dest_port,
                            timestamp=time.time(),
                            payload_snippet=meta.get("payload_snippet", ""),
                            tooling=meta.get("tooling", ""),
                            credentials=meta.get("credentials", ""),
                        )

                        with self._lock:
                            self.detected_events.append(event)

                        if self.on_intrusion:
                            try:
                                self.on_intrusion(event)
                            except Exception:
                                pass

                    except Exception:
                        continue
            except Exception:
                continue

    def drain_events(self) -> List[HoneyPortEvent]:
        """Returns and clears all recorded intrusion events."""
        with self._lock:
            events = list(self.detected_events)
            self.detected_events.clear()
            return events

    def get_threat_strings(self) -> List[str]:
        """Returns threat descriptions for all recorded intrusion events and clears them."""
        events = self.drain_events()
        return [e.to_threat_string() for e in events]
