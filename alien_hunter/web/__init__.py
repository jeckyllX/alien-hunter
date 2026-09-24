"""
Web Subsystem for Alien Hunter.
Provides embedded web dashboard and REST API using standard library http.server.
"""

from .state import SentinelState
from .server import LightweightWebServer

__all__ = ["SentinelState", "LightweightWebServer"]
