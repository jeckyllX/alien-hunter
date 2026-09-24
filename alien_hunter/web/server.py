"""
Embedded Web Server for Alien Hunter.
Uses standard library http.server (ThreadingHTTPServer) with zero external dependencies.
Provides REST endpoints and static single-page interface with in-memory state lookup.
"""

import json
import re
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
try:
    from http.server import ThreadingHTTPServer
except ImportError:
    ThreadingHTTPServer = HTTPServer  # type: ignore

from typing import Optional
from urllib.parse import urlparse

from .state import SentinelState
from .ui import DASHBOARD_HTML
from ..config import ConfigManager

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


class SentinelHTTPHandler(BaseHTTPRequestHandler):
    """Zero-dependency HTTP handler for dashboard and micro-JSON REST API."""

    server_version = "AlienHunter-Web/1.0"
    sys_version = ""

    def log_message(self, format: str, *args):
        """Suppress default stdout access logging to prevent console pollution."""
        pass

    def _send_json_response(self, status_code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _send_html_response(self, status_code: int, html_str: str):
        body = html_str.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path in ("", "/index.html"):
            self._send_html_response(200, DASHBOARD_HTML)
        elif path == "/api/status":
            state: Optional[SentinelState] = getattr(self.server, "state", None)
            if state:
                self._send_json_response(200, state.get_status_summary())
            else:
                self._send_json_response(503, {"error": "State unavailable"})
        elif path == "/api/devices":
            state: Optional[SentinelState] = getattr(self.server, "state", None)
            if state:
                self._send_json_response(200, state.get_devices_payload())
            else:
                self._send_json_response(503, {"error": "State unavailable"})
        else:
            self._send_json_response(404, {"error": "Not Found"})

    def do_HEAD(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path in ("", "/index.html"):
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
        elif path in ("/api/status", "/api/devices"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path == "/api/whitelist":
            self._handle_whitelist_post()
        else:
            self._send_json_response(404, {"error": "Not Found"})

    def _handle_whitelist_post(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_json_response(400, {"success": False, "message": "Invalid Content-Length header"})
            return

        if content_length <= 0 or content_length > 65536:
            self._send_json_response(400, {"success": False, "message": "Invalid request body size"})
            return

        try:
            raw_body = self.rfile.read(content_length).decode("utf-8")
            payload = json.loads(raw_body)
        except Exception as e:
            self._send_json_response(400, {"success": False, "message": f"Invalid JSON payload: {e}"})
            return

        if not isinstance(payload, dict):
            self._send_json_response(400, {"success": False, "message": "Payload must be a JSON object"})
            return

        mac = str(payload.get("mac", "")).strip().upper()
        if not mac or not MAC_REGEX.match(mac):
            self._send_json_response(400, {"success": False, "message": f"Invalid MAC address format: {mac}"})
            return

        name = str(payload.get("name", "")).strip() or "Trusted Device"
        owner = str(payload.get("owner", "")).strip() or "User"
        device_type = str(payload.get("device_type", "")).strip() or "Generic"
        primary_ip = str(payload.get("primary_ip", "")).strip()

        config_mgr: Optional[ConfigManager] = getattr(self.server, "config_mgr", None)
        whitelist_path: Optional[str] = getattr(self.server, "whitelist_path", None)
        state: Optional[SentinelState] = getattr(self.server, "state", None)

        # Look up existing alien device in state to preserve discovered vendor if available
        vendor = "Manual Entry"
        if state:
            with state._lock:
                for dev in state.alien_devices:
                    if dev.get("mac", "").upper() == mac:
                        vendor = dev.get("vendor", vendor)
                        if not primary_ip:
                            primary_ip = dev.get("ip", "")
                        break

        current_entry = {
            "name": name,
            "owner": owner,
            "device_type": device_type,
            "primary_ip": primary_ip,
            "vendor": vendor,
            "trusted": True,
            "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # Persist to disk via ConfigManager if available
        if config_mgr:
            try:
                whitelist = config_mgr.load_whitelist(whitelist_path)
                whitelist[mac] = current_entry
                config_mgr.save_whitelist(whitelist, whitelist_path)
            except Exception as e:
                self._send_json_response(500, {"success": False, "message": f"Failed to persist whitelist: {e}"})
                return

        # Update in-memory state
        if state:
            state.update_whitelist_entry(mac, current_entry)

        self._send_json_response(200, {
            "success": True,
            "message": f"Device {mac} whitelisted successfully",
            "entry": current_entry,
        })


class AlienHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server with port reuse enabled."""
    allow_reuse_address = True
    daemon_threads = True


class LightweightWebServer:
    """
    Manages the background HTTP server daemon thread.
    Uses select/poll socket waiting; non-blocking to the Sentinel audit cycle.
    """

    def __init__(
        self,
        state: SentinelState,
        config_mgr: Optional[ConfigManager] = None,
        whitelist_path: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 8080,
    ):
        self.state = state
        self.config_mgr = config_mgr
        self.whitelist_path = whitelist_path
        self.host = host
        self.port = port
        self.server: Optional[AlienHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Starts the HTTP server daemon thread."""
        try:
            self.server = AlienHTTPServer((self.host, self.port), SentinelHTTPHandler)
            self.port = self.server.server_address[1]
            self.server.state = self.state  # type: ignore
            self.server.config_mgr = self.config_mgr  # type: ignore
            self.server.whitelist_path = self.whitelist_path  # type: ignore

            self.thread = threading.Thread(
                target=self.server.serve_forever,
                name="AlienHunter-WebServer",
                daemon=True,
            )
            self.thread.start()
            return True
        except Exception as e:
            print(f"[!] Failed to start Lightweight Web Server on {self.host}:{self.port} - {e}")
            return False

    def stop(self):
        """Shuts down the HTTP server and releases bound sockets."""
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
            self.thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
