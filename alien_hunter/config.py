"""
Configuration and Whitelist Management for Alien Hunter.
Handles generic path resolution, storage, and persistence of trusted devices.
"""

import ipaddress
import json
import os
import time
from typing import List, Dict, Any, Optional


class ConfigManager:
    """Manages file locations, whitelist persistence, and configuration settings."""

    @staticmethod
    def resolve_path(filename: str, custom_path: Optional[str] = None) -> str:
        """
        Resolves the configuration file location with a clear fallback hierarchy:
        1. Explicit custom path provided via CLI
        2. Current working directory
        3. Directory containing the package/script
        4. User's standard config directory (~/.config/alien-hunter/)
        """
        if custom_path and custom_path.strip():
            return os.path.abspath(custom_path)

        # Check current working directory
        cwd_path = os.path.join(os.getcwd(), filename)
        if os.path.exists(cwd_path):
            return cwd_path

        # Check directory of this package
        pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pkg_path = os.path.join(pkg_dir, filename)
        if os.path.exists(pkg_path):
            return pkg_path

        # Check user config directory (~/.config/alien-hunter/)
        sudo_user = os.environ.get("SUDO_USER")
        home = os.path.expanduser(f"~{sudo_user}") if sudo_user else os.path.expanduser("~")
        user_cfg = os.path.join(home, ".config", "alien-hunter", filename)
        if os.path.exists(user_cfg):
            return user_cfg

        # Check system-wide config directory (/etc/alien-hunter/)
        etc_cfg = os.path.join("/etc", "alien-hunter", filename)
        if os.path.exists(etc_cfg):
            return etc_cfg

        # Default fallback to current working directory
        return cwd_path

    @staticmethod
    def load_json(filepath: str, default: Optional[Any] = None) -> Any:
        """Safely load a JSON file, returning a default value if missing or invalid."""
        if default is None:
            default = {}
        if not os.path.exists(filepath):
            return default
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default

    @staticmethod
    def save_json(filepath: str, data: Any) -> bool:
        """Safely write data to a JSON file."""
        try:
            parent = os.path.dirname(os.path.abspath(filepath))
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

    def load_whitelist(self, custom_path: Optional[str] = None) -> Dict[str, dict]:
        path = self.resolve_path("known_devices.json", custom_path)
        raw = self.load_json(path, default={})
        return {k.upper(): v for k, v in raw.items() if isinstance(v, dict)}

    def save_whitelist(self, whitelist: Dict[str, dict], custom_path: Optional[str] = None) -> bool:
        path = self.resolve_path("known_devices.json", custom_path)
        return self.save_json(path, whitelist)

    def load_config(self, custom_path: Optional[str] = None) -> Dict[str, Any]:
        path = self.resolve_path("config.json", custom_path)
        return self.load_json(path, default={})

    def sync_device_inventory(
        self,
        devices: List[Any],
        custom_path: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
    ) -> bool:
        """
        Enriches known_devices.json with live observed telemetry (IP, aliases,
        discovery methods, services, ports, and last_seen timestamps) for trusted hosts,
        preserving user-configured fields like name, owner, and device_type.
        Uses Python ipaddress for clean, RFC-compliant topological subnet prioritization.
        """
        raw = self.load_whitelist(custom_path)
        modified = False

        local_net = None
        if subnet_cidr:
            try:
                local_net = ipaddress.ip_network(subnet_cidr, strict=False)
            except (ValueError, TypeError):
                local_net = None

        for dev in devices:
            mac_upper = getattr(dev, "mac", "").upper()
            if not mac_upper or mac_upper.startswith("N/A") or mac_upper not in raw:
                continue

            # Only synchronize telemetry and update last_seen for actively observed devices
            dev_status = getattr(dev, "status", "Online / Active")
            if dev_status not in ("Online / Active", "Local Machine"):
                continue

            entry = raw[mac_upper]

            # Aggregate all observed IP addresses (dev.ip + aliases)
            candidate_ips: List[str] = []
            dev_ip = getattr(dev, "ip", None)
            if dev_ip and dev_ip not in candidate_ips:
                candidate_ips.append(dev_ip)
            for alias_ip in getattr(dev, "aliases", []):
                if alias_ip and alias_ip not in candidate_ips:
                    candidate_ips.append(alias_ip)

            # Filter valid non-loopback, non-multicast, non-unspecified IP candidates
            valid_ips: List[str] = []
            for ip_cand in candidate_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_cand)
                    if not ip_obj.is_loopback and not ip_obj.is_unspecified and not ip_obj.is_multicast:
                        valid_ips.append(ip_cand)
                except ValueError:
                    pass

            if valid_ips:
                current_p_ip = entry.get("primary_ip")
                current_is_local = False
                if current_p_ip:
                    try:
                        curr_obj = ipaddress.ip_address(current_p_ip)
                        if local_net and curr_obj in local_net:
                            current_is_local = True
                    except ValueError:
                        pass

                # Categorize candidates based on network topology
                local_candidates: List[str] = []
                private_candidates: List[str] = []
                for ip_str in valid_ips:
                    try:
                        cand_obj = ipaddress.ip_address(ip_str)
                        if local_net and cand_obj in local_net:
                            local_candidates.append(ip_str)
                        elif cand_obj.is_private:
                            private_candidates.append(ip_str)
                    except ValueError:
                        pass

                # Authoritatively resolve primary_ip:
                # 1. Prefer an IP on the local subnet
                # 2. Preserve existing primary_ip if it is already local
                # 3. Fallback to private IP, then first valid IP
                chosen_primary = None
                if local_candidates:
                    if current_is_local and current_p_ip in local_candidates:
                        chosen_primary = current_p_ip
                    else:
                        chosen_primary = local_candidates[0]
                elif current_is_local:
                    chosen_primary = current_p_ip
                elif private_candidates:
                    chosen_primary = private_candidates[0]
                else:
                    chosen_primary = valid_ips[0]

                if entry.get("primary_ip") != chosen_primary:
                    entry["primary_ip"] = chosen_primary
                    modified = True

                # Correlate all remaining IP candidates as secondary aliases
                other_aliases = [ip for ip in valid_ips if ip != chosen_primary]
                existing_aliases = set(entry.get("aliases", []))
                merged_aliases = sorted(list((existing_aliases | set(other_aliases)) - {chosen_primary}))
                if merged_aliases != entry.get("aliases"):
                    entry["aliases"] = merged_aliases
                    modified = True

            vendor = getattr(dev, "vendor", "")
            if vendor and vendor != "N/A" and entry.get("vendor") != vendor:
                entry["vendor"] = vendor
                modified = True

            disc_method = getattr(dev, "discovery_method", "")
            if disc_method:
                methods = [m.strip() for m in disc_method.split(",") if m.strip()]
                existing_methods = set(entry.get("discovery_methods", []))
                merged_methods = sorted(list(existing_methods | set(methods)))
                if merged_methods != entry.get("discovery_methods"):
                    entry["discovery_methods"] = merged_methods
                    modified = True

            services = getattr(dev, "mdns_services", [])
            if services:
                existing_services = set(entry.get("services", []))
                merged_services = sorted(list(existing_services | set(services)))
                if merged_services != entry.get("services"):
                    entry["services"] = merged_services
                    modified = True

            open_ports = getattr(dev, "open_ports", [])
            if open_ports and entry.get("ports") != open_ports:
                entry["ports"] = open_ports
                modified = True

            entry["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            modified = True

        if modified:
            return self.save_whitelist(raw, custom_path)
        return True
