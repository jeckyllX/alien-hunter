"""
Unit tests for the Active ARP Self-Healing & IPS Counter-Poisoning Subsystem (ArpSelfHealing).
"""

import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.defenses.arp_healing import ArpSelfHealing, ArpHealAction
from alien_hunter.defenses.arp_poison import ArpPoisonGuard, ArpPoisonEvent


class TestArpSelfHealing(unittest.TestCase):
    """Tests Gratuitous ARP frame synthesis, burst transmission, and automated healing hooks."""

    def test_build_gratuitous_arp_reply(self):
        frame = ArpSelfHealing.build_gratuitous_arp(
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            opcode=2,
        )
        self.assertEqual(len(frame), 42)

        # Ethernet Header (14 bytes)
        dst_mac = frame[0:6]
        src_mac = frame[6:12]
        ethertype = struct.unpack("!H", frame[12:14])[0]

        self.assertEqual(dst_mac, b"\xff\xff\xff\xff\xff\xff")
        self.assertEqual(src_mac, bytes.fromhex("001122334455"))
        self.assertEqual(ethertype, 0x0806)

        # ARP Payload (28 bytes)
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", frame[14:22])
        self.assertEqual(htype, 1)  # Ethernet
        self.assertEqual(ptype, 0x0800)  # IPv4
        self.assertEqual(hlen, 6)
        self.assertEqual(plen, 4)
        self.assertEqual(op, 2)  # ARP Reply

        sender_mac = frame[22:28]
        sender_ip = socket.inet_ntoa(frame[28:32])
        target_mac = frame[32:38]
        target_ip = socket.inet_ntoa(frame[38:42])

        self.assertEqual(sender_mac, bytes.fromhex("001122334455"))
        self.assertEqual(sender_ip, "192.168.1.1")
        self.assertEqual(target_mac, b"\xff\xff\xff\xff\xff\xff")
        self.assertEqual(target_ip, "192.168.1.1")  # GARP target IP == sender IP

    def test_build_gratuitous_arp_request(self):
        frame = ArpSelfHealing.build_gratuitous_arp(
            ip="192.168.1.254",
            mac="AA:BB:CC:DD:EE:FF",
            opcode=1,
        )
        self.assertEqual(len(frame), 42)
        op = struct.unpack("!H", frame[20:22])[0]
        self.assertEqual(op, 1)  # ARP Request

    def test_build_targeted_gratuitous_arp(self):
        target = "66:77:88:99:AA:BB"
        frame = ArpSelfHealing.build_gratuitous_arp(
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            opcode=2,
            target_mac=target,
        )
        self.assertEqual(frame[0:6], bytes.fromhex(target.replace(":", "")))
        self.assertEqual(frame[32:38], bytes.fromhex(target.replace(":", "")))

    def test_heal_burst_transmission(self):
        mock_sock = MagicMock()
        healer = ArpSelfHealing(
            interface="wlan0",
            burst_count=3,
            burst_interval=0.001,
            cooldown_seconds=2.0,
        )

        action = healer.heal(
            spoofed_ip="192.168.1.1",
            legitimate_mac="00:11:22:33:44:55",
            attacker_mac="AA:BB:CC:DD:EE:99",
            threat_type="GATEWAY_POISONING",
            raw_socket=mock_sock,
        )

        self.assertIsNotNone(action)
        self.assertEqual(action.frames_sent, 3)
        self.assertEqual(action.spoofed_ip, "192.168.1.1")
        self.assertEqual(action.legitimate_mac, "00:11:22:33:44:55")
        self.assertEqual(action.attacker_mac, "AA:BB:CC:DD:EE:99")
        self.assertEqual(mock_sock.sendto.call_count, 3)
        self.assertIn("Subnet neighbor caches restored", action.to_log_string())

        history = healer.get_healing_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["spoofed_ip"], "192.168.1.1")

    def test_heal_cooldown_rate_limiting(self):
        mock_sock = MagicMock()
        healer = ArpSelfHealing(
            interface="wlan0",
            cooldown_seconds=5.0,
            burst_interval=0.0,
        )

        # First trigger at t=1000.0
        act1 = healer.heal(
            spoofed_ip="192.168.1.1",
            legitimate_mac="00:11:22:33:44:55",
            now=1000.0,
            raw_socket=mock_sock,
        )
        self.assertIsNotNone(act1)

        # Immediate follow-up at t=1002.0 (suppressed by cooldown)
        act2 = healer.heal(
            spoofed_ip="192.168.1.1",
            legitimate_mac="00:11:22:33:44:55",
            now=1002.0,
            raw_socket=mock_sock,
        )
        self.assertIsNone(act2)

        # After cooldown expiry at t=1006.0
        act3 = healer.heal(
            spoofed_ip="192.168.1.1",
            legitimate_mac="00:11:22:33:44:55",
            now=1006.0,
            raw_socket=mock_sock,
        )
        self.assertIsNotNone(act3)

    def test_heal_event_gateway_poisoning(self):
        mock_sock = MagicMock()
        healer = ArpSelfHealing(interface="eth0", burst_interval=0.0)

        event = ArpPoisonEvent(
            threat_type="GATEWAY_POISONING",
            spoofed_ip="192.168.1.1",
            attacker_mac="AA:BB:CC:DD:EE:FF",
            expected_mac="00:11:22:33:44:55",
        )

        action = healer.heal_event(event, raw_socket=mock_sock)
        self.assertIsNotNone(action)
        self.assertEqual(action.spoofed_ip, "192.168.1.1")
        self.assertEqual(action.legitimate_mac, "00:11:22:33:44:55")

    def test_heal_event_unsupported_threat_type(self):
        healer = ArpSelfHealing(interface="eth0")
        event = ArpPoisonEvent(
            threat_type="L2_MAC_MISMATCH",
            spoofed_ip="192.168.1.50",
            attacker_mac="AA:BB:CC:DD:EE:FF",
            expected_mac=None,
        )
        action = healer.heal_event(event)
        self.assertIsNone(action)

    def test_arp_poison_guard_triggers_self_healing(self):
        mock_sock = MagicMock()
        guard = ArpPoisonGuard(
            gateway_ip="192.168.1.1",
            gateway_mac="00:11:22:33:44:55",
            self_healing_enabled=True,
        )
        self.assertTrue(guard.is_self_healing_enabled)

        # Build simulated attacking ARP frame claiming 192.168.1.1 from rogue MAC
        eth_hdr = (
            bytes.fromhex("66778899AABB")
            + bytes.fromhex("AABBCCDDEEFF")
            + struct.pack("!H", 0x0806)
        )
        arp_payload = struct.pack(
            "!HHBBH6s4s6s4s",
            1,
            0x0800,
            6,
            4,
            2,  # Reply
            bytes.fromhex("AABBCCDDEEFF"),
            socket.inet_aton("192.168.1.1"),
            bytes.fromhex("66778899AABB"),
            socket.inet_aton("192.168.1.50"),
        )
        poison_pkt = eth_hdr + arp_payload

        with patch("socket.socket", return_value=mock_sock):
            event = guard.process_packet(poison_pkt)

        self.assertIsNotNone(event)
        self.assertEqual(event.threat_type, "GATEWAY_POISONING")
        # Check healing history inside the guard's healer
        history = guard.healer.get_healing_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["spoofed_ip"], "192.168.1.1")
        self.assertEqual(history[0]["legitimate_mac"], "00:11:22:33:44:55")


if __name__ == "__main__":
    unittest.main()
