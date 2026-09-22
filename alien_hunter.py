#!/usr/bin/env python3
"""
Alien Hunter (alien-hunter)
LAN security auditor and network discovery tool

License: MIT
"""

import os
import sys

# Ensure package path is resolved when executed directly
pkg_dir = os.path.dirname(os.path.abspath(__file__))
if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)

from alien_hunter.cli import main

if __name__ == "__main__":
    main()
