"""Core orchestration subpackage for Alien Hunter."""

from .engine import DiscoveryEngine
from .sentinel import SentinelWatchdog

__all__ = ["DiscoveryEngine", "SentinelWatchdog"]
