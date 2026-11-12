"""
Unit tests for network and socket utilities.
"""

import socket
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.scanners.net_utils import (
    PACKET_ADD_MEMBERSHIP,
    PACKET_DROP_MEMBERSHIP,
    bind_socket_to_device,
    create_udp_socket,
    disable_promiscuous_mode,
    enable_promiscuous_mode,
    get_subnet_broadcast,
    is_promiscuous_safe_interface,
)


class TestNetUtils(unittest.TestCase):
    """Tests for reusable network and socket helpers."""

    def test_get_subnet_broadcast(self):
        self.assertEqual(get_subnet_broadcast("192.168.1.50"), "192.168.1.255")
        self.assertEqual(get_subnet_broadcast("192.168.1"), "192.168.1.255")
        self.assertEqual(get_subnet_broadcast("10.0.0.1"), "10.0.0.255")
        self.assertIsNone(get_subnet_broadcast(""))
        self.assertIsNone(get_subnet_broadcast(None))

    @patch("socket.socket")
    def test_create_udp_socket_options(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        sock = create_udp_socket(broadcast=True, reuse_port=True, interface="eth0", timeout=1.5)

        self.assertEqual(sock, mock_sock)
        # Verify setsockopt calls
        calls = [c[0] for c in mock_sock.setsockopt.call_args_list]
        self.assertTrue(any(socket.SO_REUSEADDR in c for c in calls))
        self.assertTrue(any(socket.SO_BROADCAST in c for c in calls))
        # Verify timeout set
        mock_sock.settimeout.assert_called_once_with(1.5)

    def test_bind_socket_to_device_handles_none(self):
        mock_sock = MagicMock()
        res = bind_socket_to_device(mock_sock, None)
        self.assertFalse(res)

    @patch("os.path.exists", return_value=False)
    def test_is_promiscuous_safe_interface(self, mock_exists):
        self.assertTrue(is_promiscuous_safe_interface("eth0"))
        self.assertTrue(is_promiscuous_safe_interface("enp3s0"))
        self.assertFalse(is_promiscuous_safe_interface("wlan0"))
        self.assertFalse(is_promiscuous_safe_interface("wlp2s0"))
        self.assertFalse(is_promiscuous_safe_interface("lo"))
        self.assertFalse(is_promiscuous_safe_interface("tailscale0"))
        self.assertFalse(is_promiscuous_safe_interface("wg0"))
        self.assertFalse(is_promiscuous_safe_interface(None))
        self.assertFalse(is_promiscuous_safe_interface(""))

    @patch("os.path.exists", return_value=True)
    def test_is_promiscuous_safe_interface_sysfs_wireless(self, mock_exists):
        self.assertFalse(is_promiscuous_safe_interface("eth0"))

    @patch("os.path.exists", return_value=False)
    @patch("socket.if_nametoindex", return_value=2)
    def test_enable_and_disable_promiscuous_mode(self, mock_ifindex, mock_exists):
        mock_sock = MagicMock()
        mreq = enable_promiscuous_mode(mock_sock, "eth0")
        self.assertIsNotNone(mreq)
        self.assertEqual(mock_sock.setsockopt.call_count, 1)
        self.assertEqual(mock_sock.setsockopt.call_args[0][1], PACKET_ADD_MEMBERSHIP)

        disable_promiscuous_mode(mock_sock, mreq)
        self.assertEqual(mock_sock.setsockopt.call_count, 2)
        self.assertEqual(mock_sock.setsockopt.call_args[0][1], PACKET_DROP_MEMBERSHIP)

        # Wireless skips setsockopt
        mock_wifi_sock = MagicMock()
        self.assertIsNone(enable_promiscuous_mode(mock_wifi_sock, "wlan0"))
        mock_wifi_sock.setsockopt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
