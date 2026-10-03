"""
Layer-2 Broadcast Storm & Switch CAM Table Flooding Guard.
Passively monitors raw Layer-2 Ethernet frames (AF_PACKET, SOCK_RAW, ETH_P_ALL)
to detect switch CAM table exhaustion attacks (macof) and broadcast storms.
MITRE ATT&CK T1499 (Endpoint Denial of Service), T1557 (Adversary-in-the-Middle).
Zero external dependencies.
"""

from collections import deque
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Set, Tuple, Any


class StormEvent:
    """Represents a Layer-2 storm or CAM table flooding security event."""

    def __init__(
        self,
        threat_type: str,
        pps: float,
        threshold: float,
        timestamp: float = 0.0,
        distinct_mac_count: int = 0,
        sample_macs: Optional[List[str]] = None,
        duration: float = 1.0,
    ):
        self.threat_type = threat_type  # "CAM_TABLE_FLOOD" or "BROADCAST_STORM"
        self.pps = pps
        self.threshold = threshold
        self.timestamp = timestamp or time.time()
        self.distinct_mac_count = distinct_mac_count
        self.sample_macs = sample_macs or []
        self.duration = duration

    def to_threat_string(self) -> str:
        if self.threat_type == "CAM_TABLE_FLOOD":
            macs_str = ", ".join(self.sample_macs[:5])
            sample_str = f" (Samples: {macs_str}...)" if macs_str else ""
            return (
                f"CRITICAL: Switch CAM Table Flooding Attack detected! "
                f"Observed {self.distinct_mac_count} distinct source MACs in {self.duration:.1f}s "
                f"(Threshold: {int(self.threshold)} MACs){sample_str}! "
                f"Adversary attempting switch CAM exhaustion to force fail-open hub sniffing (MITRE ATT&CK T1499 / T1557)."
            )
        elif self.threat_type == "BROADCAST_STORM":
            return (
                f"WARNING: Layer-2 Broadcast Storm detected! "
                f"Broadcast/multicast traffic surged to {self.pps:.0f} pps "
                f"(Threshold: {int(self.threshold)} pps over {self.duration:.1f}s)! "
                f"Possible Layer-2 network loop, faulty NIC, or broadcast flood (MITRE ATT&CK T1499)."
            )
        return f"ALERT: Layer-2 Traffic Anomaly: {self.threat_type} ({self.pps:.0f} pps)"


class StormGuard:
    """
    Passively monitors Layer-2 frame telemetry to identify switch memory exhaustion
    attacks (macof) and broadcast/multicast storm conditions in real time.
    """

    SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1
    ETH_P_ALL = 0x0003
    ARPHRD_ETHER = 1
    PACKET_OUTGOING = 4
    PACKET_LOOPBACK = 5

    def __init__(
        self,
        interface: Optional[str] = None,
        local_mac: Optional[str] = None,
        cam_flood_threshold: int = 30,
        broadcast_storm_threshold: int = 150,
        window_seconds: float = 2.0,
        alert_cooldown: float = 30.0,
        history_maxlen: int = 250,
    ):
        self.interface = interface
        self.local_mac = local_mac.upper() if local_mac else None
        self.cam_flood_threshold = cam_flood_threshold
        self.broadcast_storm_threshold = broadcast_storm_threshold
        self.window_seconds = window_seconds
        self.alert_cooldown = alert_cooldown
        self.history_maxlen = history_maxlen

        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None
        self._lock = threading.Lock()

        # Sliding window of (timestamp, src_mac, is_broadcast_or_multicast)
        self._frame_history: deque = deque()
        self._total_frames_processed = 0

        # Output threat queues
        self._threat_queue: deque = deque(maxlen=history_maxlen)
        self._event_history: List[StormEvent] = []
        self._last_alert_times: Dict[str, float] = {}

    def update_local_mac(self, local_mac: Optional[str]):
        """Dynamically updates local host MAC address to exclude local transmissions."""
        if local_mac:
            with self._lock:
                self.local_mac = local_mac.upper()

    @property
    def is_running(self) -> bool:
        return self.running

    @staticmethod
    def parse_ethernet_header(frame: bytes) -> Optional[Tuple[str, str, int, bool]]:
        """
        Parses raw Ethernet frame into (dst_mac, src_mac, ethertype, is_broadcast_or_multicast).
        Returns None if frame is truncated or invalid.
        """
        if len(frame) < 14:
            return None

        dst_bytes, src_bytes, ethertype = struct.unpack("!6s6sH", frame[:14])

        # Source MAC cannot be all zeroes or have the multicast bit set (IEEE 802.3 standard)
        if src_bytes == b"\x00\x00\x00\x00\x00\x00" or bool(src_bytes[0] & 0x01):
            return None

        dst_mac = ":".join(f"{b:02x}" for b in dst_bytes).upper()
        src_mac = ":".join(f"{b:02x}" for b in src_bytes).upper()

        # Support 802.1Q VLAN encapsulation
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = struct.unpack("!H", frame[16:18])[0]

        is_broadcast = (dst_mac == "FF:FF:FF:FF:FF:FF")
        is_multicast = bool(dst_bytes[0] & 0x01)
        is_bcast_or_mcast = is_broadcast or is_multicast

        return dst_mac, src_mac, ethertype, is_bcast_or_mcast

    def process_frame(self, frame: bytes, now: Optional[float] = None) -> Optional[StormEvent]:
        """
        Processes a single raw Ethernet frame through the sliding-window analyzer.
        Returns a StormEvent if an attack threshold was breached, or None.
        Thread-safe.
        """
        parsed = self.parse_ethernet_header(frame)
        if not parsed:
            return None

        _, src_mac, _, is_bcast_mcast = parsed

        # Filter out traffic originating from the local machine itself
        if self.local_mac and src_mac == self.local_mac:
            return None

        ts = now if now is not None else time.time()

        with self._lock:
            self._total_frames_processed += 1
            self._frame_history.append((ts, src_mac, is_bcast_mcast))

            # Evict entries outside the sliding window
            cutoff = ts - self.window_seconds
            while self._frame_history and self._frame_history[0][0] < cutoff:
                self._frame_history.popleft()

            if len(self._frame_history) < 5:
                return None

            oldest_ts = self._frame_history[0][0]
            duration = max(0.1, ts - oldest_ts)

            # 1. Evaluate CAM Table Flooding (rapid MAC churn)
            distinct_macs = {item[1] for item in self._frame_history}
            distinct_count = len(distinct_macs)

            if distinct_count >= self.cam_flood_threshold:
                last_alert = self._last_alert_times.get("CAM_TABLE_FLOOD", 0.0)
                if ts - last_alert >= self.alert_cooldown:
                    self._last_alert_times["CAM_TABLE_FLOOD"] = ts
                    mac_rate = distinct_count / duration
                    event = StormEvent(
                        threat_type="CAM_TABLE_FLOOD",
                        pps=mac_rate,
                        threshold=self.cam_flood_threshold,
                        timestamp=ts,
                        distinct_mac_count=distinct_count,
                        sample_macs=sorted(list(distinct_macs))[:8],
                        duration=duration,
                    )
                    self._threat_queue.append(event.to_threat_string())
                    self._event_history.append(event)
                    return event

            # 2. Evaluate Broadcast / Multicast Storm
            # Require at least 50 broadcast frames and a minimum 0.5s observation duration
            # to prevent brief sub-second packet bursts (e.g. ARP sweeps or mDNS lookups) from extrapolating into storms.
            bcast_count = sum(1 for item in self._frame_history if item[2])
            if bcast_count >= min(50, self.broadcast_storm_threshold) and duration >= 0.5:
                bcast_pps = bcast_count / duration

                if bcast_pps >= self.broadcast_storm_threshold:
                    last_alert = self._last_alert_times.get("BROADCAST_STORM", 0.0)
                    if ts - last_alert >= self.alert_cooldown:
                        self._last_alert_times["BROADCAST_STORM"] = ts
                        event = StormEvent(
                            threat_type="BROADCAST_STORM",
                            pps=bcast_pps,
                            threshold=self.broadcast_storm_threshold,
                            timestamp=ts,
                            distinct_mac_count=distinct_count,
                            duration=duration,
                        )
                        self._threat_queue.append(event.to_threat_string())
                        self._event_history.append(event)
                        return event

            return None

    def get_threat_strings(self) -> List[str]:
        """Drains and returns all newly detected storm/flooding threat strings."""
        threats: List[str] = []
        with self._lock:
            while self._threat_queue:
                threats.append(self._threat_queue.popleft())
        return threats

    def get_telemetry(self, now: Optional[float] = None) -> Dict[str, Any]:
        """Returns live statistical telemetry for the dashboard and status reporting."""
        with self._lock:
            ts = now if now is not None else time.time()
            cutoff = ts - self.window_seconds
            while self._frame_history and self._frame_history[0][0] < cutoff:
                self._frame_history.popleft()

            window_len = len(self._frame_history)
            duration = max(0.1, min(self.window_seconds, (ts - self._frame_history[0][0]) if self._frame_history else 0.1))
            bcast_count = sum(1 for item in self._frame_history if item[2])
            distinct_macs = len({item[1] for item in self._frame_history})

            return {
                "running": self.running,
                "interface": self.interface,
                "total_frames_processed": self._total_frames_processed,
                "current_fps": round(window_len / duration, 1) if window_len else 0.0,
                "current_broadcast_pps": round(bcast_count / duration, 1) if window_len else 0.0,
                "distinct_macs_in_window": distinct_macs,
                "cam_flood_threshold": self.cam_flood_threshold,
                "broadcast_storm_threshold": self.broadcast_storm_threshold,
                "events_detected_count": len(self._event_history),
            }

    def sniff(self, duration: float = 1.0) -> List[StormEvent]:
        """
        Passively sniffs raw Layer-2 Ethernet frames for a specified duration
        and returns any detected storm or CAM flooding events.
        """
        events: List[StormEvent] = []
        raw_sock = None
        mreq = None
        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ALL))
            if self.interface:
                try:
                    raw_sock.bind((self.interface, 0))
                except Exception:
                    pass

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
                    pkt, sll = raw_sock.recvfrom(2048)
                    if isinstance(sll, tuple) and len(sll) >= 4:
                        ifname, proto, pkttype, hatype = sll[0], sll[1], sll[2], sll[3]
                        if hatype != self.ARPHRD_ETHER:
                            continue
                        if pkttype in (self.PACKET_OUTGOING, self.PACKET_LOOPBACK):
                            continue
                        if self.interface and ifname != self.interface:
                            continue
                    ev = self.process_frame(pkt)
                    if ev:
                        events.append(ev)
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
        """Initializes raw Layer-2 socket and launches listener thread."""
        with self._lock:
            if self.running:
                return True

            try:
                # AF_PACKET is Linux-native. Verify socket creation capability.
                test_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ALL))
                test_sock.close()
            except Exception:
                return False

            self.running = True
            self._thread = threading.Thread(
                target=self._sniff_loop, daemon=True, name="StormGuard"
            )
            self._thread.start()
            return True

    def stop(self):
        """Stops the sniffing thread and releases socket resources."""
        self.running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def _sniff_loop(self):
        """Background worker thread capturing Layer-2 Ethernet frames."""
        raw_sock = None
        mreq = None
        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ALL))
            self._socket = raw_sock

            if self.interface:
                try:
                    raw_sock.bind((self.interface, 0))
                except Exception:
                    pass

                # Enable promiscuous mode to capture frames during switch fail-open
                try:
                    ifindex = socket.if_nametoindex(self.interface)
                    mreq = struct.pack("IHH8s", ifindex, self.PACKET_MR_PROMISC, 0, b"")
                    raw_sock.setsockopt(self.SOL_PACKET, self.PACKET_ADD_MEMBERSHIP, mreq)
                except Exception:
                    mreq = None

            raw_sock.settimeout(0.5)
            while self.running:
                try:
                    pkt, sll = raw_sock.recvfrom(2048)
                    if isinstance(sll, tuple) and len(sll) >= 4:
                        ifname, proto, pkttype, hatype = sll[0], sll[1], sll[2], sll[3]
                        if hatype != self.ARPHRD_ETHER:
                            continue
                        if pkttype in (self.PACKET_OUTGOING, self.PACKET_LOOPBACK):
                            continue
                        if self.interface and ifname != self.interface:
                            continue
                    self.process_frame(pkt)
                except socket.timeout:
                    continue
                except Exception:
                    if not self.running:
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
            self.running = False
