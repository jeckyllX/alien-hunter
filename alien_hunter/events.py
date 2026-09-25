"""
Security Event Logging and Persistent Audit Journal.
Maintains a thread-safe in-memory timeline and appends to events.jsonl.
Zero external dependencies.
"""

from collections import deque
from dataclasses import dataclass, asdict
import json
import os
import threading
import time
from typing import Dict, Any, List, Optional


@dataclass
class SecurityEvent:
    timestamp: str
    event_type: str
    severity: str
    title: str
    description: str
    device_name: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.details is None:
            data.pop("details", None)
        return data


class EventManager:
    """Thread-safe security event journal with in-memory deque and JSONL log persistence."""

    def __init__(
        self,
        log_path: Optional[str] = None,
        max_memory_entries: int = 1000,
        max_log_bytes: int = 5 * 1024 * 1024,  # 5MB log rotation threshold
    ):
        self.log_path = log_path
        self.max_memory_entries = max_memory_entries
        self.max_log_bytes = max_log_bytes
        self._lock = threading.Lock()
        self._events: deque = deque(maxlen=max_memory_entries)

        if self.log_path:
            self._load_from_log()

    def _load_from_log(self):
        """Loads historical events from existing events.jsonl into memory on startup."""
        if not self.log_path or not os.path.exists(self.log_path):
            return
        try:
            loaded: List[Dict[str, Any]] = []
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        loaded.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            with self._lock:
                for ev in loaded[-self.max_memory_entries:]:
                    self._events.append(ev)
        except Exception:
            pass

    def record(
        self,
        event_type: str,
        severity: str,
        title: str,
        description: str,
        device_name: Optional[str] = None,
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates, stores in memory, and persists a security event."""
        if not timestamp:
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        event_data: Dict[str, Any] = {
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
            "title": title,
            "description": description,
            "device_name": device_name,
            "ip": ip,
            "mac": mac,
        }
        if details:
            event_data["details"] = details

        with self._lock:
            self._events.append(event_data)

            if self.log_path:
                try:
                    parent = os.path.dirname(os.path.abspath(self.log_path))
                    os.makedirs(parent, exist_ok=True)

                    # Append event line
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(event_data) + "\n")

                    # Check for log compaction if file exceeds maximum size
                    if os.path.exists(self.log_path) and os.path.getsize(self.log_path) > self.max_log_bytes:
                        self._compact_log_file()
                except Exception:
                    pass

        return event_data

    def _compact_log_file(self):
        """Compacts the JSONL file to retain the most recent max_memory_entries atomically."""
        try:
            tmp_path = self.log_path + ".tmp"
            events_to_keep = list(self._events)
            with open(tmp_path, "w", encoding="utf-8") as f:
                for ev in events_to_keep:
                    f.write(json.dumps(ev) + "\n")
            os.replace(tmp_path, self.log_path)
        except Exception:
            pass

    def get_events(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns events in reverse chronological order (newest first)."""
        with self._lock:
            ev_list = list(self._events)

        if event_type:
            ev_list = [e for e in ev_list if e.get("event_type") == event_type]

        ev_list.reverse()
        return ev_list[:limit]

    def clear(self):
        """Clears in-memory events."""
        with self._lock:
            self._events.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
