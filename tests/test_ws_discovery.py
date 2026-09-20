"""
Unit tests for WS-Discovery scanner.
"""

import unittest
from alien_hunter.scanners.ws_discovery import WsDiscoveryScanner


class TestWsDiscoveryScanner(unittest.TestCase):
    """Tests WS-Discovery probe generation and XML response parsing."""

    def test_build_probe(self):
        probe_bytes = WsDiscoveryScanner.build_probe(message_uuid="12345678-1234-1234-1234-123456789abc")
        probe_str = probe_bytes.decode("utf-8")
        self.assertIn("12345678-1234-1234-1234-123456789abc", probe_str)
        self.assertIn("http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe", probe_str)
        self.assertIn("wsd:Device", probe_str)

    def test_parse_probe_match_windows(self):
        sample_xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            '<soap:Body>'
            '<wsd:ProbeMatches>'
            '<wsd:ProbeMatch>'
            '<wsa:EndpointReference><wsa:Address>urn:uuid:550e8400-e29b-41d4-a716-446655440000</wsa:Address></wsa:EndpointReference>'
            '<wsd:Types>wsd:Device pub:Computer</wsd:Types>'
            '<wsd:Scopes>onvif://www.onvif.org/name/DESKTOP-WORKSTATION</wsd:Scopes>'
            '<wsd:XAddrs>http://192.168.1.88:5357/wsd</wsd:XAddrs>'
            '</wsd:ProbeMatch>'
            '</wsd:ProbeMatches>'
            '</soap:Body>'
            '</soap:Envelope>'
        )

        parsed = WsDiscoveryScanner.parse_probe_match(sample_xml, "192.168.1.88")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["ip"], "192.168.1.88")
        self.assertEqual(parsed["device_name"], "DESKTOP-WORKSTATION")
        self.assertIn("pub:Computer", parsed["types"])
        self.assertIn("http://192.168.1.88:5357/wsd", parsed["xaddrs"])


if __name__ == "__main__":
    unittest.main()
