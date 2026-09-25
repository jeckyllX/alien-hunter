"""
Unit tests for EventManager and SecurityEvent logging.
"""

import json
import os
import tempfile
import unittest

from alien_hunter.events import EventManager, SecurityEvent


class TestSecurityEvent(unittest.TestCase):
    """Tests the SecurityEvent data structure and serialization."""

    def test_security_event_dict_conversion(self):
        ev = SecurityEvent(
            timestamp="2026-09-25T20:00:00Z",
            event_type="ALIEN_DETECTED",
            severity="CRITICAL",
            title="Alien Device Detected",
            description="Unrecognized device on LAN",
            device_name="Unknown ESP8266",
            ip="192.168.1.105",
            mac="AA:BB:CC:DD:EE:FF",
            details={"vendor": "Espressif"},
        )
        d = ev.to_dict()
        self.assertEqual(d["event_type"], "ALIEN_DETECTED")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["ip"], "192.168.1.105")
        self.assertEqual(d["details"], {"vendor": "Espressif"})

    def test_security_event_without_details(self):
        ev = SecurityEvent(
            timestamp="2026-09-25T20:00:00Z",
            event_type="DEVICE_ONLINE",
            severity="INFO",
            title="Device Online",
            description="MacBook Pro is active",
        )
        d = ev.to_dict()
        self.assertNotIn("details", d)


class TestEventManager(unittest.TestCase):
    """Tests in-memory and persistent JSONL event journaling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.temp_dir.name, "events.jsonl")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_record_in_memory(self):
        mgr = EventManager(max_memory_entries=10)
        mgr.record(
            event_type="DEVICE_ONLINE",
            severity="INFO",
            title="Online",
            description="Host is active",
            ip="192.168.1.10",
        )
        self.assertEqual(len(mgr), 1)
        events = mgr.get_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "DEVICE_ONLINE")
        self.assertEqual(events[0]["ip"], "192.168.1.10")

    def test_persistence_and_loading(self):
        mgr = EventManager(log_path=self.log_path, max_memory_entries=10)
        mgr.record(
            event_type="DEVICE_ONLINE",
            severity="INFO",
            title="First Event",
            description="Device online",
        )
        mgr.record(
            event_type="ALIEN_DETECTED",
            severity="CRITICAL",
            title="Second Event",
            description="Alien detected",
        )

        self.assertTrue(os.path.exists(self.log_path))
        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        self.assertEqual(len(lines), 2)

        # Reload into a new EventManager instance
        mgr_new = EventManager(log_path=self.log_path, max_memory_entries=10)
        self.assertEqual(len(mgr_new), 2)
        events = mgr_new.get_events()
        # Newest first
        self.assertEqual(events[0]["title"], "Second Event")
        self.assertEqual(events[1]["title"], "First Event")

    def test_filtering_and_limits(self):
        mgr = EventManager()
        for i in range(10):
            mgr.record(
                event_type="DEVICE_ONLINE" if i % 2 == 0 else "ALIEN_DETECTED",
                severity="INFO" if i % 2 == 0 else "CRITICAL",
                title=f"Event {i}",
                description=f"Desc {i}",
            )

        self.assertEqual(len(mgr), 10)
        all_events = mgr.get_events(limit=5)
        self.assertEqual(len(all_events), 5)
        self.assertEqual(all_events[0]["title"], "Event 9")

        aliens = mgr.get_events(event_type="ALIEN_DETECTED")
        self.assertEqual(len(aliens), 5)
        for ev in aliens:
            self.assertEqual(ev["event_type"], "ALIEN_DETECTED")

    def test_max_memory_entries_capping(self):
        mgr = EventManager(max_memory_entries=5)
        for i in range(10):
            mgr.record(
                event_type="DEVICE_ONLINE",
                severity="INFO",
                title=f"Event {i}",
                description=f"Desc {i}",
            )
        self.assertEqual(len(mgr), 5)
        events = mgr.get_events()
        # Events 5, 6, 7, 8, 9 should be preserved (newest first: 9, 8, 7, 6, 5)
        self.assertEqual(events[0]["title"], "Event 9")
        self.assertEqual(events[-1]["title"], "Event 5")

    def test_log_compaction(self):
        # Set max_log_bytes tiny (100 bytes) to force compaction
        mgr = EventManager(log_path=self.log_path, max_memory_entries=3, max_log_bytes=100)
        for i in range(10):
            mgr.record(
                event_type="DEVICE_ONLINE",
                severity="INFO",
                title=f"Compacted Event {i}",
                description="Short desc",
            )

        self.assertTrue(os.path.exists(self.log_path))
        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        # Compaction retains the current in-memory entries (3 entries)
        self.assertEqual(len(lines), 3)


if __name__ == "__main__":
    unittest.main()
