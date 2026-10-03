"""
Unit tests for Layer-2 Broadcast Storm and Switch CAM Table Flooding Guard (StormGuard).
"""

import struct
import time
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.defenses.storm_guard import StormGuard, StormEvent
from alien_hunter.threats import ThreatDetector


def build_ethernet_frame(
    dst_mac: str,
    src_mac: str,
    ethertype: int = 0x0800,
    vlan_id: int = 0,
    payload: bytes = b"\x00" * 46,
) -> bytes:
    """Builds a synthetic Layer-2 Ethernet frame with optional 802.1Q tag."""
    dst_bytes = bytes.fromhex(dst_mac.replace(":", ""))
    src_bytes = bytes.fromhex(src_mac.replace(":", ""))

    if vlan_id > 0:
        # 802.1Q encapsulation
        eth_hdr = struct.pack("!6s6sHHH", dst_bytes, src_bytes, 0x8100, vlan_id, ethertype)
    else:
        eth_hdr = struct.pack("!6s6sH", dst_bytes, src_bytes, ethertype)

    return eth_hdr + payload


class TestStormGuard(unittest.TestCase):
    """Test suite for StormGuard Layer-2 intrusion and anomaly detection."""

    def setUp(self):
        self.guard = StormGuard(
            interface="eth0",
            cam_flood_threshold=30,
            broadcast_storm_threshold=150,
            window_seconds=2.0,
            alert_cooldown=10.0,
        )

    def test_parse_ethernet_header(self):
        # 1. Unicast frame
        unicast_frame = build_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", ethertype=0x0800)
        parsed = StormGuard.parse_ethernet_header(unicast_frame)
        self.assertIsNotNone(parsed)
        dst, src, proto, is_bcast_mcast = parsed
        self.assertEqual(dst, "00:11:22:33:44:55")
        self.assertEqual(src, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(proto, 0x0800)
        self.assertFalse(is_bcast_mcast)

        # 2. Broadcast frame
        bcast_frame = build_ethernet_frame("FF:FF:FF:FF:FF:FF", "AA:BB:CC:DD:EE:FF", ethertype=0x0806)
        parsed_bcast = StormGuard.parse_ethernet_header(bcast_frame)
        self.assertIsNotNone(parsed_bcast)
        self.assertTrue(parsed_bcast[3])

        # 3. Multicast frame (IPv4 multicast 01:00:5E:...)
        mcast_frame = build_ethernet_frame("01:00:5E:00:00:FB", "AA:BB:CC:DD:EE:FF", ethertype=0x0800)
        parsed_mcast = StormGuard.parse_ethernet_header(mcast_frame)
        self.assertIsNotNone(parsed_mcast)
        self.assertTrue(parsed_mcast[3])

        # 4. 802.1Q tagged frame
        vlan_frame = build_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", ethertype=0x0800, vlan_id=10)
        parsed_vlan = StormGuard.parse_ethernet_header(vlan_frame)
        self.assertIsNotNone(parsed_vlan)
        self.assertEqual(parsed_vlan[2], 0x0800)

        # 5. Truncated frame
        self.assertIsNone(StormGuard.parse_ethernet_header(b"\x00" * 10))

    def test_normal_traffic_no_alert(self):
        base_time = 1000.0
        # Simulate normal traffic from 3 devices over 1 second
        for i in range(20):
            src = f"00:11:22:33:44:0{i % 3}"
            is_bcast = (i % 10 == 0)
            dst = "FF:FF:FF:FF:FF:FF" if is_bcast else "00:11:22:33:44:99"
            frame = build_ethernet_frame(dst, src)
            ev = self.guard.process_frame(frame, now=base_time + (i * 0.05))
            self.assertIsNone(ev)

        self.assertEqual(len(self.guard.get_threat_strings()), 0)
        telemetry = self.guard.get_telemetry(now=base_time + 1.0)
        self.assertEqual(telemetry["total_frames_processed"], 20)
        self.assertEqual(telemetry["distinct_macs_in_window"], 3)
        self.assertEqual(telemetry["events_detected_count"], 0)

    def test_cam_table_flood_detection(self):
        base_time = 2000.0
        event = None

        # Simulate macof attack: 35 frames from distinct random MACs in rapid succession
        for i in range(35):
            src_mac = f"02:00:00:00:{i // 256:02X}:{i % 256:02X}"
            frame = build_ethernet_frame("00:11:22:33:44:55", src_mac)
            res = self.guard.process_frame(frame, now=base_time + (i * 0.02))
            if res:
                event = res

        self.assertIsNotNone(event)
        self.assertEqual(event.threat_type, "CAM_TABLE_FLOOD")
        self.assertGreaterEqual(event.distinct_mac_count, 30)
        threat_msg = event.to_threat_string()
        self.assertIn("CRITICAL: Switch CAM Table Flooding Attack detected", threat_msg)
        self.assertIn("MITRE ATT&CK T1499 / T1557", threat_msg)

        # Draining threats returns the queued alert
        threats = self.guard.get_threat_strings()
        self.assertEqual(len(threats), 1)
        self.assertIn("Switch CAM Table Flooding", threats[0])
        # Queue should now be empty
        self.assertEqual(len(self.guard.get_threat_strings()), 0)

    def test_broadcast_storm_detection(self):
        base_time = 3000.0
        event = None

        # Send 160 broadcast packets from 2 MACs across 0.8 seconds (200 pps)
        for i in range(160):
            src_mac = "AA:BB:CC:DD:EE:01" if (i % 2 == 0) else "AA:BB:CC:DD:EE:02"
            frame = build_ethernet_frame("FF:FF:FF:FF:FF:FF", src_mac)
            res = self.guard.process_frame(frame, now=base_time + (i * 0.005))
            if res:
                event = res

        self.assertIsNotNone(event)
        self.assertEqual(event.threat_type, "BROADCAST_STORM")
        self.assertGreaterEqual(event.pps, 150)
        threat_msg = event.to_threat_string()
        self.assertIn("WARNING: Layer-2 Broadcast Storm detected", threat_msg)
        self.assertIn("MITRE ATT&CK T1499", threat_msg)

    def test_alert_cooldown(self):
        base_time = 4000.0
        alerts = []

        # Generate a CAM flood
        for i in range(35):
            src_mac = f"02:AA:BB:00:{i // 256:02X}:{i % 256:02X}"
            frame = build_ethernet_frame("00:11:22:33:44:55", src_mac)
            res = self.guard.process_frame(frame, now=base_time + (i * 0.01))
            if res:
                alerts.append(res)

        self.assertEqual(len(alerts), 1)

        # Immediately send 10 more distinct MACs within cooldown (time + 1.0s)
        for i in range(35, 45):
            src_mac = f"02:AA:BB:00:{i // 256:02X}:{i % 256:02X}"
            frame = build_ethernet_frame("00:11:22:33:44:55", src_mac)
            res = self.guard.process_frame(frame, now=base_time + 1.0)
            if res:
                alerts.append(res)

        # Cooldown prevents repeat alert
        self.assertEqual(len(alerts), 1)

        # Advance past cooldown (10s threshold -> advance by 11s)
        for i in range(45, 80):
            src_mac = f"02:CC:DD:00:{i // 256:02X}:{i % 256:02X}"
            frame = build_ethernet_frame("00:11:22:33:44:55", src_mac)
            res = self.guard.process_frame(frame, now=base_time + 12.0 + ((i - 45) * 0.01))
            if res:
                alerts.append(res)

        # A new alert fires once cooldown has elapsed
        self.assertEqual(len(alerts), 2)

    def test_threat_detector_facade(self):
        with patch.object(StormGuard, "sniff") as mock_sniff:
            ev = StormEvent(
                threat_type="CAM_TABLE_FLOOD",
                pps=45.0,
                threshold=30,
                distinct_mac_count=35,
                duration=1.0,
            )
            mock_sniff.return_value = [ev]

            threats = ThreatDetector.check_layer2_storms(interface="eth0", duration=1.0)
            self.assertEqual(len(threats), 1)
            self.assertIn("Switch CAM Table Flooding Attack detected", threats[0])

    @patch("socket.socket")
    def test_start_and_stop_lifecycle(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        self.assertTrue(self.guard.start())
        self.assertTrue(self.guard.is_running)

        # Duplicate start returns True immediately
        self.assertTrue(self.guard.start())

        self.guard.stop()
        self.assertFalse(self.guard.is_running)

    def test_local_mac_frames_ignored(self):
        guard = StormGuard(
            interface="wlan0",
            local_mac="DC:A6:32:A2:4F:8E",
            broadcast_storm_threshold=150,
        )
        base_time = 5000.0

        # Simulate 200 raw ARP sweep frames sent by local host
        for i in range(200):
            frame = build_ethernet_frame("FF:FF:FF:FF:FF:FF", "DC:A6:32:A2:4F:8E")
            res = guard.process_frame(frame, now=base_time + (i * 0.001))
            self.assertIsNone(res)

        self.assertEqual(len(guard.get_threat_strings()), 0)
        telemetry = guard.get_telemetry(now=base_time + 0.5)
        self.assertEqual(telemetry["total_frames_processed"], 0)

    def test_subsecond_brief_burst_no_storm_alert(self):
        base_time = 6000.0

        # Simulate brief 15-packet burst over 0.075s from external host
        for i in range(15):
            frame = build_ethernet_frame("FF:FF:FF:FF:FF:FF", "AA:BB:CC:DD:EE:01")
            res = self.guard.process_frame(frame, now=base_time + (i * 0.005))
            self.assertIsNone(res)

        self.assertEqual(len(self.guard.get_threat_strings()), 0)


if __name__ == "__main__":
    unittest.main()
