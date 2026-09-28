"""
Privacy-Preserving Dynamic Signature Synchronization Engine.
Periodically fetches updated device signature definitions from a remote feed
using HTTP conditional caching (ETag / If-None-Match) with zero transmission
of local network telemetry or identifying device data.
"""

import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from typing import Dict, Any, Optional, Tuple

from ..config import ConfigManager


class SignatureSyncEngine:
    """
    Synchronizes device signatures against an upstream repository.
    Enforces privacy by design: transmits zero local IP, MAC, or network data.
    """

    DEFAULT_FEED_URL = (
        "https://raw.githubusercontent.com/jekyll86/alien-hunter/main/alien_hunter/data/signatures.json"
    )
    DEFAULT_TIMEOUT: float = 10.0
    MIN_SYNC_INTERVAL_SECONDS: float = 86400.0  # 24 hours
    METADATA_FILENAME = ".signatures_sync.json"
    USER_AGENT = "AlienHunterSentinel/2.0 (Defensive LAN Sentinel; Python stdlib)"

    def __init__(
        self,
        feed_url: str = DEFAULT_FEED_URL,
        timeout: float = DEFAULT_TIMEOUT,
        target_path: Optional[str] = None,
    ):
        self.feed_url = feed_url
        self.timeout = timeout
        self._target_path = target_path

    def get_target_path(self) -> str:
        """Determines the target file path for writing downloaded signatures."""
        if self._target_path:
            return os.path.abspath(self._target_path)
        # Defaults to user config directory
        return ConfigManager.resolve_path("signatures.json")

    def get_metadata_path(self) -> str:
        """Determines path to metadata storage for ETag and sync timestamps."""
        target = self.get_target_path()
        parent = os.path.dirname(os.path.abspath(target))
        return os.path.join(parent, self.METADATA_FILENAME)

    def load_metadata(self) -> Dict[str, Any]:
        """Loads sync cache metadata (ETag, last modified, last check time)."""
        meta_path = self.get_metadata_path()
        return ConfigManager.load_json(meta_path, default={})

    def save_metadata(self, data: Dict[str, Any]) -> bool:
        """Saves sync cache metadata."""
        meta_path = self.get_metadata_path()
        return ConfigManager.save_json(meta_path, data)

    @staticmethod
    def validate_signatures_data(data: Any) -> Tuple[bool, str]:
        """Validates that downloaded signature data conforms to schema requirements."""
        if not isinstance(data, dict):
            return False, "Payload root must be a JSON object"
        if "dhcp_signatures" not in data or "mdns_signatures" not in data:
            return False, "Payload missing required 'dhcp_signatures' or 'mdns_signatures' keys"
        if not isinstance(data["dhcp_signatures"], list):
            return False, "'dhcp_signatures' must be a list"
        if not isinstance(data["mdns_signatures"], dict):
            return False, "'mdns_signatures' must be a dictionary"
        if len(data["dhcp_signatures"]) < 5:
            return False, "Signature payload rejected: contains fewer than 5 DHCP signatures"

        return True, "Valid"

    def sync(self, force: bool = False) -> Tuple[bool, str]:
        """
        Executes an anonymous conditional HTTP GET to update signature definitions.
        Returns:
            (success: bool, status_message: str)
        """
        now = time.time()
        meta = self.load_metadata()
        last_check = float(meta.get("last_checked", 0.0))

        if not force and (now - last_check < self.MIN_SYNC_INTERVAL_SECONDS):
            hours_ago = (now - last_check) / 3600.0
            return (
                True,
                f"Signatures up-to-date (checked {hours_ago:.1f}h ago; threshold is 24h). Use --force to override.",
            )

        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/json",
        }
        if meta.get("etag"):
            headers["If-None-Match"] = meta["etag"]
        if meta.get("last_modified"):
            headers["If-Modified-Since"] = meta["last_modified"]

        req = urllib.request.Request(self.feed_url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = resp.status
                etag = resp.headers.get("ETag")
                last_mod = resp.headers.get("Last-Modified")
                raw_bytes = resp.read()

                try:
                    payload = json.loads(raw_bytes.decode("utf-8"))
                except Exception as e:
                    return False, f"Downloaded signatures corrupted or invalid JSON: {e}"

                is_valid, reason = self.validate_signatures_data(payload)
                if not is_valid:
                    return False, f"Signature payload validation failed: {reason}"

                target_file = self.get_target_path()
                target_dir = os.path.dirname(os.path.abspath(target_file))
                os.makedirs(target_dir, exist_ok=True)

                # Atomic write: write to temp file in target directory, then atomic rename
                tmp_fd, tmp_path = tempfile.mkstemp(dir=target_dir, prefix=".sig_tmp_")
                try:
                    with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                        json.dump(payload, f, indent=2)
                    os.replace(tmp_path, target_file)
                except Exception as e:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                    return False, f"Failed to save signatures to disk: {e}"

                # Update metadata
                meta["last_checked"] = now
                if etag:
                    meta["etag"] = etag
                if last_mod:
                    meta["last_modified"] = last_mod
                meta["version"] = payload.get("version", "1.0.0")
                meta["signature_count"] = len(payload.get("dhcp_signatures", []))
                self.save_metadata(meta)

                return (
                    True,
                    f"Successfully synchronized signatures to version {meta['version']} "
                    f"({meta['signature_count']} DHCP signatures).",
                )

        except urllib.error.HTTPError as e:
            if e.code == 304:
                # Upstream content unchanged
                meta["last_checked"] = now
                self.save_metadata(meta)
                return True, "Signatures up-to-date (HTTP 304 Not Modified; 0 bytes transferred)."
            return False, f"HTTP Error {e.code} during signature sync: {e.reason}"

        except urllib.error.URLError as e:
            return False, f"Network error during signature sync: {e.reason}"

        except Exception as e:
            return False, f"Unexpected error during signature sync: {e}"
