"""
Unit tests for network and socket utilities.
"""

import socket
import unittest
from unittest.mock import MagicMock, patch

from alien_hunter.scanners.net_utils import (
    bind_socket_to_device,
    create_udp_socket,
    get_subnet_broadcast,
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


if __name__ == "__main__":
    unittest.main()
