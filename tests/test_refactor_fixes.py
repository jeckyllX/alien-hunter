"""
Unit tests for the Priority 0 refactor: prefix-aware subnet CIDR, the
SentinelConfig dataclass, diagnostic logging, and defensive bug fixes.
"""

import logging
import unittest
from unittest.mock import patch

from alien_hunter.models import NetworkInfo, SentinelConfig
from alien_hunter.logging_setup import configure, get_logger, LOGGER_NAME
from alien_hunter.identifiers.signatures import DhcpFingerprintStore
from alien_hunter.scanners.ports import PortScanner
from alien_hunter.core.engine import DiscoveryEngine


class TestNetworkInfoPrefixAware(unittest.TestCase):
    """Validates CIDR/broadcast derivation from the kernel-reported prefix length."""

    def test_subnet_cidr_slash24(self):
        net = NetworkInfo("eth0", "192.168.1.73", "00:11:22:33:44:55", subnet_base="192.168.1", prefix_len=24)
        self.assertEqual(net.subnet_cidr, "192.168.1.0/24")
        self.assertEqual(net.broadcast_ip, "192.168.1.255")

    def test_subnet_cidr_slash16(self):
        net = NetworkInfo("eth0", "10.0.5.3", "00:11:22:33:44:55", subnet_base="10.0.5", prefix_len=16)
        self.assertEqual(net.subnet_cidr, "10.0.0.0/16")
        self.assertEqual(net.broadcast_ip, "10.0.255.255")

    def test_subnet_cidr_slash8(self):
        net = NetworkInfo("eth0", "10.9.9.9", "00:11:22:33:44:55", subnet_base="10.9.9", prefix_len=8)
        self.assertEqual(net.subnet_cidr, "10.0.0.0/8")
        self.assertEqual(net.broadcast_ip, "10.255.255.255")

    def test_legacy_fallback_without_prefix(self):
        # Callers that only populate subnet_base retain the historical /24 assumption.
        net = NetworkInfo("eth0", "192.168.1.73", "00:11:22:33:44:55", subnet_base="192.168.1")
        self.assertEqual(net.subnet_cidr, "192.168.1.0/24")
        self.assertEqual(net.broadcast_ip, "192.168.1.255")

    def test_empty_network_returns_none_broadcast(self):
        net = NetworkInfo("eth0", "", "")
        self.assertEqual(net.subnet_cidr, "")
        self.assertIsNone(net.broadcast_ip)


class TestGetNetworkInfoPrefix(unittest.TestCase):
    """Ensures get_network_info() propagates the kernel-reported prefix length."""

    def test_parses_prefixlen_from_ip_addr(self):
        def fake_ip_json(*args):
            if args == ("route",):
                return [{"dst": "default", "dev": "eth0", "gateway": "10.0.0.1"}]
            if args == ("addr", "show", "dev", "eth0"):
                return [{
                    "ifname": "eth0",
                    "address": "aa:bb:cc:dd:ee:ff",
                    "addr_info": [{"family": "inet", "local": "10.0.5.3", "prefixlen": 16}],
                }]
            if args == ("neigh", "show", "10.0.0.1"):
                return [{"dst": "10.0.0.1", "lladdr": "AA:BB:CC:DD:EE:FF"}]
            return []

        with patch.object(DiscoveryEngine, "_run_ip_json", side_effect=fake_ip_json):
            net = DiscoveryEngine.get_network_info()

        self.assertEqual(net.prefix_len, 16)
        self.assertEqual(net.subnet_cidr, "10.0.0.0/16")
        self.assertEqual(net.broadcast_ip, "10.0.255.255")


class TestSentinelConfig(unittest.TestCase):
    """Validates the bundled SentinelWatchdog configuration dataclass."""

    def test_defaults(self):
        cfg = SentinelConfig()
        self.assertEqual(cfg.interval, 300)
        self.assertTrue(cfg.syn_scan_enabled)
        self.assertEqual(cfg.honey_ports, None)
        self.assertTrue(cfg.sync_db)

    def test_from_defense_config(self):
        config = {
            "auto_sync_database": False,
            "web_ui": {"enabled": True, "host": "127.0.0.1", "port": 9090},
            "defenses": {
                "honey_port_enabled": False,
                "syn_scan_enabled": False,
                "cam_flood_threshold": 50,
                "broadcast_storm_threshold": 200,
            },
        }
        cfg = SentinelConfig.from_defense_config(config)
        self.assertFalse(cfg.sync_db)
        self.assertTrue(cfg.web_enabled)
        self.assertEqual(cfg.web_host, "127.0.0.1")
        self.assertEqual(cfg.web_port, 9090)
        self.assertIsNone(cfg.honey_ports)  # honey_port_enabled False -> None
        self.assertFalse(cfg.syn_scan_enabled)
        self.assertEqual(cfg.cam_flood_threshold, 50)
        self.assertEqual(cfg.broadcast_storm_threshold, 200)

    def test_overrides_win_over_config(self):
        cfg = SentinelConfig.from_defense_config({"defenses": {}}, interval=42, web_port=1234)
        self.assertEqual(cfg.interval, 42)
        self.assertEqual(cfg.web_port, 1234)

    def test_unknown_override_keys_are_ignored(self):
        cfg = SentinelConfig.from_defense_config({}, not_a_real_field=1)
        self.assertEqual(cfg.interval, 300)


class TestLoggingSetup(unittest.TestCase):
    """Validates the shared diagnostic logger."""

    def test_configure_debug_sets_debug_level(self):
        logger = configure(debug=True)
        self.assertEqual(logger.level, logging.DEBUG)
        self.assertEqual(get_logger().name, LOGGER_NAME)

    def test_configure_default_sets_warning_level(self):
        logger = configure(debug=False)
        self.assertEqual(logger.level, logging.WARNING)

    def test_get_logger_returns_shared_instance(self):
        self.assertIs(get_logger(), logging.getLogger(LOGGER_NAME))


class TestAppleDhcpUnmasking(unittest.TestCase):
    """Ensures DHCP Option 55/60 Apple signals are honored (R6 dead-branch fix)."""

    def setUp(self):
        DhcpFingerprintStore.get_instance().clear()

    def tearDown(self):
        DhcpFingerprintStore.get_instance().clear()

    @patch.object(PortScanner, "scan_host", return_value=([], [], []))
    def test_dhcp_apple_signal_sets_is_apple(self, _mock_scan):
        engine = DiscoveryEngine()
        mac = "2A:A9:34:C4:17:28"
        ip = "192.168.1.60"

        # Apple iOS Option 55 parameter request list -> match_dhcp identifies Apple.
        DhcpFingerprintStore.get_instance().record(
            mac, [1, 121, 3, 6, 15, 114, 119, 252], vendor_class="dhcp-client"
        )

        net_info = NetworkInfo(
            "eth0", "192.168.1.73", "00:11:22:33:44:55",
            gateway_ip="192.168.1.1", gateway_mac="AA:BB:CC:DD:EE:FF",
            subnet_base="192.168.1", prefix_len=24,
        )

        with patch.object(engine.apple_identifier, "resolve_mdns_name", return_value=None):
            dev, _threats = engine._correlate_device(
                ip=ip,
                net_info=net_info,
                active_devices={ip: mac},
                dns_leases={},
                ssdp_devices={},
                netbios_devices={},
                passive_transmitters={},
                passive_only_ips=set(),
                whitelist={},
            )

        self.assertTrue(dev.is_apple)
        self.assertIn("Apple", dev.vendor)


if __name__ == "__main__":
    unittest.main()
