"""
Network and Raw Socket Utilities for Alien Hunter scanners.
Provides reusable socket creation, interface binding, and broadcast resolution.
"""

import socket
from typing import Optional


def bind_socket_to_device(sock: socket.socket, interface: Optional[str]) -> bool:
    """Safely binds a socket to a specific network interface (SO_BINDTODEVICE = 25)."""
    if not interface:
        return False
    try:
        # SO_BINDTODEVICE = 25 on Linux
        sock.setsockopt(socket.SOL_SOCKET, 25, (interface + "\0").encode("utf-8"))
        return True
    except Exception:
        return False


def create_udp_socket(
    broadcast: bool = True,
    reuse_port: bool = True,
    interface: Optional[str] = None,
    timeout: Optional[float] = None,
) -> socket.socket:
    """Creates and configures a standard UDP socket with fail-safe socket options."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if reuse_port:
        try:
            # SO_REUSEPORT = 15 on Linux
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_REUSEPORT", 15), 1)
        except Exception:
            pass

    if broadcast:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass

    if interface:
        bind_socket_to_device(sock, interface)

    if timeout is not None:
        sock.settimeout(timeout)

    return sock


def get_subnet_broadcast(ip_or_base: Optional[str]) -> Optional[str]:
    """Calculates standard /24 subnet broadcast address from IP or base (e.g. 192.168.1)."""
    if not ip_or_base:
        return None
    parts = ip_or_base.strip().split(".")
    if len(parts) >= 3:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.255"
    return None
