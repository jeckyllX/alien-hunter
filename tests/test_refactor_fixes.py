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


class TestAtomicSaveJson(unittest.TestCase):
    """Validates atomic file replacement in ConfigManager.save_json (F4a)."""

    def test_atomic_save_replaces_file_and_leaves_no_tmp(self):
        import os
        import tempfile
        from alien_hunter.config import ConfigManager

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "known_devices.json")
            ConfigManager.save_json(target, {"AA:BB:CC:DD:EE:FF": {"name": "TestHost"}})
            self.assertTrue(os.path.exists(target))
            loaded = ConfigManager.load_json(target, {})
            self.assertEqual(loaded["AA:BB:CC:DD:EE:FF"]["name"], "TestHost")
            leftovers = [f for f in os.listdir(tmpdir) if ".tmp." in f]
            self.assertEqual(leftovers, [])


class TestWebStateAndDeviceRoundTrip(unittest.TestCase):
    """Validates device serialization, threat mapping, and whitelist updates (F4b-F4d)."""

    def test_device_to_dict_and_cli_from_dict_round_trip(self):
        from alien_hunter.models import Device
        from alien_hunter.web.state import SentinelState
        from alien_hunter.cli import device_from_dict

        dev = Device(
            ip="192.168.1.50",
            mac="FA:CE:00:11:22:33",
            hostname="TestPhone",
            vendor="Randomized (Private) MAC",
            friendly_name="TestPhone",
            status="Online / Active",
            is_randomized=True,
            is_apple=True,
            mdns_services=["_companion-link._tcp"],
            ws_types=["Device"],
            dhcp_fingerprint="Apple iOS",
            dhcp_params=[1, 3, 6, 15],
            ssdp_fingerprint="UPnP/1.0",
            tcp_syn_fingerprint="iOS/macOS",
            observed_ttl=64,
        )
        serialized = SentinelState._device_to_dict(dev)
        self.assertTrue(serialized["is_randomized"])
        self.assertTrue(serialized["is_apple"])
        self.assertEqual(serialized["dhcp_fingerprint"], "Apple iOS")
        self.assertEqual(serialized["observed_ttl"], 64)

        reconstructed = device_from_dict(serialized)
        self.assertEqual(reconstructed.mdns_services, ["_companion-link._tcp"])
        self.assertEqual(reconstructed.ws_types, ["Device"])
        self.assertEqual(reconstructed.dhcp_fingerprint, "Apple iOS")
        self.assertEqual(reconstructed.dhcp_params, [1, 3, 6, 15])
        self.assertEqual(reconstructed.ssdp_fingerprint, "UPnP/1.0")
        self.assertEqual(reconstructed.tcp_syn_fingerprint, "iOS/macOS")
        self.assertEqual(reconstructed.observed_ttl, 64)

    def test_record_threat_event_mappings_and_severity(self):
        from alien_hunter.web.state import SentinelState

        state = SentinelState()
        state._record_threat_event("CRITICAL: ROGUE DHCP SERVER at 192.168.1.99")
        state._record_threat_event("CRITICAL: MAC Spoofing (Doppelganger) by AA:BB:CC:DD:EE:FF")
        state._record_threat_event("WARNING: Out-of-Subnet Phantom Implant transmitting: 11:22:33:44:55:66")
        state._record_threat_event("CRITICAL: L2 Broadcast Storm detected (500 fps)")

        payload = state.get_events_payload(limit=20)
        events_by_type = {e["event_type"]: e for e in payload["events"]}
        self.assertIn("ROGUE_DHCP_DETECTED", events_by_type)
        self.assertEqual(events_by_type["ROGUE_DHCP_DETECTED"]["severity"], "CRITICAL")
        self.assertIn("DOPPELGANGER_DETECTED", events_by_type)
        self.assertEqual(events_by_type["DOPPELGANGER_DETECTED"]["severity"], "CRITICAL")
        self.assertIn("PHANTOM_DEVICE_DETECTED", events_by_type)
        self.assertEqual(events_by_type["PHANTOM_DEVICE_DETECTED"]["severity"], "WARN")
        self.assertIn("L2_STORM_DETECTED", events_by_type)
        self.assertEqual(events_by_type["L2_STORM_DETECTED"]["severity"], "CRITICAL")

    def test_update_whitelist_entry_updates_in_place_without_duplicates(self):
        from alien_hunter.web.state import SentinelState

        state = SentinelState()
        state.trusted_devices = [{
            "ip": "192.168.1.10",
            "mac": "AA:BB:CC:DD:EE:FF",
            "name": "OldName",
            "vendor": "Intel",
            "status": "Online / Active",
            "ports": [22],
        }]
        state.update_whitelist_entry(
            "AA:BB:CC:DD:EE:FF",
            {"name": "NewName", "owner": "Admin", "device_type": "Workstation"},
        )
        self.assertEqual(len(state.trusted_devices), 1)
        self.assertEqual(state.trusted_devices[0]["name"], "NewName")
        self.assertEqual(state.trusted_devices[0]["owner"], "Admin")
        self.assertEqual(state.trusted_devices[0]["device_type"], "Workstation")
        self.assertEqual(state.trusted_devices[0]["ports"], [22])


class TestRunAuditSkipsActiveDefenses(unittest.TestCase):
    """Validates DiscoveryEngine.run_audit skipping redundant one-shot sniffers (F2)."""

    def test_run_audit_skips_background_active_guards(self):
        from alien_hunter.core import engine as engine_mod
        from alien_hunter.models import Device
        from alien_hunter.threats import ThreatDetector

        engine = DiscoveryEngine()
        net_info = NetworkInfo(
            "eth0", "192.168.1.73", "00:11:22:33:44:55",
            gateway_ip="192.168.1.1", gateway_mac="AA:BB:CC:DD:EE:FF",
            subnet_base="192.168.1", prefix_len=24,
        )

        with patch.object(DiscoveryEngine, "get_network_info", return_value=net_info), \
             patch.object(engine_mod.ArpScanner, "scan", return_value={}), \
             patch.object(engine_mod.RouterDnsAuditor, "audit_subnet", return_value={}), \
             patch.object(engine_mod.PassiveFrameSniffer, "sniff", return_value={}), \
             patch.object(engine_mod.SsdpScanner, "scan", return_value={}), \
             patch.object(engine_mod.NetbiosScanner, "scan", return_value={}), \
             patch.object(engine_mod.MdnsScanner, "scan", return_value={}), \
             patch.object(engine_mod.WsDiscoveryScanner, "scan", return_value={}), \
             patch.object(engine_mod.Ipv6DiscoveryScanner, "scan", return_value={}), \
             patch.object(engine_mod.PhantomSweeper, "scan", return_value={}), \
             patch.object(ThreatDetector, "check_llmnr_poisoning", return_value=[]), \
             patch.object(ThreatDetector, "check_mdns_poisoning", return_value=[]), \
             patch.object(ThreatDetector, "check_dns_integrity", return_value=[]), \
             patch.object(ThreatDetector, "check_rogue_ipv6_ra", return_value=[]), \
             patch.object(ThreatDetector, "check_phantom_devices", return_value=[]), \
             patch.object(ThreatDetector, "check_rogue_dhcp") as mock_dhcp, \
             patch.object(ThreatDetector, "check_syn_scans") as mock_syn, \
             patch.object(ThreatDetector, "check_dns_tunneling") as mock_dns, \
             patch.object(ThreatDetector, "check_dhcp_starvation") as mock_starv, \
             patch.object(ThreatDetector, "check_realtime_arp_poisoning") as mock_arp, \
             patch.object(engine, "_correlate_device", return_value=(Device(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF"), [])):

            engine.run_audit(
                whitelist={},
                passive_duration=0,
                active_background_defenses={
                    "rogue_dhcp": True,
                    "syn_scan": True,
                    "dns_tunneling": True,
                    "dhcp_starvation": True,
                    "arp_poison": True,
                },
            )

            mock_dhcp.assert_not_called()
            mock_syn.assert_not_called()
            mock_dns.assert_not_called()
            mock_starv.assert_not_called()
            mock_arp.assert_not_called()

    @patch.object(
        PortScanner,
        "scan_host",
        return_value=(
            ["445/SMB"],
            ["[HIGH] Port 445 (SMB): Direct SMB file sharing. Potential target for remote execution / ransomware."],
            [],
        ),
    )
    def test_whitelisted_baseline_port_suppresses_static_threat(self, _mock_scan):
        engine = DiscoveryEngine()
        mac = "64:4A:7D:D0:0E:1C"
        whitelist = {
            mac: {
                "name": "Lenovo Work",
                "trusted": True,
                "ports": ["445/SMB"],
            }
        }
        open_ports, host_threats, _notes = engine._audit_device_ports_and_threats(
            ip="192.168.1.132",
            mac=mac,
            status="Online / Active",
            clean_host="RE50E5",
            friendly_name="Lenovo Work",
            vendor="Intel",
            whitelist=whitelist,
            deep_scan=False,
            custom_ports=None,
            observed_ttl=128,
            tcp_syn_fingerprint=None,
            dhcp_fingerprint=None,
        )
        self.assertEqual(open_ports, ["445/SMB"])
        self.assertEqual(host_threats, [])

    def test_local_mac_vpn_traffic_ignored_as_phantom(self):
        from alien_hunter.models import Device
        from alien_hunter.threats import ThreatDetector

        local_mac = "DC:A6:32:A2:4F:8E"
        vpn_peer_dev = Device(
            ip="10.253.3.5",
            mac=local_mac,
            hostname="Unknown",
            vendor="Raspberry Pi Trading Ltd (GB)",
            status="Online / Active",
        )
        threats = ThreatDetector.check_phantom_devices(
            devices=[vpn_peer_dev],
            subnet_cidr="192.168.1.0/24",
            gateway_mac="18:EF:C0:10:FF:B0",
            local_mac=local_mac,
        )
        self.assertEqual(threats, [])


if __name__ == "__main__":
    unittest.main()

