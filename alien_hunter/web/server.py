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

from typing import Optional, Any
from urllib.parse import urlparse, parse_qs

from .state import SentinelState
from .ui import DASHBOARD_HTML
from .auth import WebAuthenticator
from ..config import ConfigManager
from ..logging_setup import get_logger
from ..models import estimate_initial_ttl

log = get_logger()

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
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            log.debug("Client closed socket during JSON response write")

    def _send_html_response(self, status_code: int, html_str: str, headers: Optional[dict] = None):
        body = html_str.encode("utf-8")
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            log.debug("Client closed socket during HTML response write")

    def _get_client_ip(self) -> str:
        """Resolves client IP, honoring trusted proxy headers for local connections."""
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        if client_ip in ("127.0.0.1", "::1"):
            forwarded = self.headers.get("X-Forwarded-For")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip()
            else:
                real_ip = self.headers.get("X-Real-IP")
                if real_ip:
                    client_ip = real_ip.strip()
        return client_ip

    def _is_request_authorized(self) -> bool:
        """Validates session token or loopback CLI bypass."""
        auth: Optional[WebAuthenticator] = getattr(self.server, "authenticator", None)
        if not auth or not auth.enabled:
            return True

        # Check local CLI bypass (direct loopback connection with no proxy header)
        raw_client = self.client_address[0] if self.client_address else ""
        if raw_client in ("127.0.0.1", "::1") and not self.headers.get("X-Forwarded-For") and not self.headers.get("X-Real-IP"):
            user_agent = self.headers.get("User-Agent", "")
            if "AlienHunterCLI" in user_agent:
                return True

        # Check session cookie
        cookie_header = self.headers.get("Cookie", "")
        if "ah_session=" in cookie_header:
            match = re.search(r"ah_session=([^;]+)", cookie_header)
            if match:
                token = match.group(1).strip()
                username = auth.session_manager.validate_session(token)
                if username:
                    return True

        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        auth: Optional[WebAuthenticator] = getattr(self.server, "authenticator", None)

        if path in ("", "/index.html"):
            self._send_html_response(200, DASHBOARD_HTML)
        elif path == "/api/auth/status":
            is_auth = self._is_request_authorized()
            self._send_json_response(200, {
                "auth_enabled": bool(auth and auth.enabled),
                "auth_required": bool(auth and auth.enabled),
                "is_authenticated": is_auth,
                "authenticated": is_auth,
                "username": auth.username if (auth and is_auth) else None,
            })
        elif path == "/api/status":
            if not self._is_request_authorized():
                self._send_json_response(401, {"error": "Authentication required", "auth_required": True})
                return
            state: Optional[SentinelState] = getattr(self.server, "state", None)
            if state:
                self._send_json_response(200, state.get_status_summary())
            else:
                self._send_json_response(503, {"error": "State unavailable"})
        elif path == "/api/devices":
            if not self._is_request_authorized():
                self._send_json_response(401, {"error": "Authentication required", "auth_required": True})
                return
            state: Optional[SentinelState] = getattr(self.server, "state", None)
            if state:
                self._send_json_response(200, state.get_devices_payload())
            else:
                self._send_json_response(503, {"error": "State unavailable"})
        elif path == "/api/events":
            if not self._is_request_authorized():
                self._send_json_response(401, {"error": "Authentication required", "auth_required": True})
                return
            state: Optional[SentinelState] = getattr(self.server, "state", None)
            if state:
                query = parse_qs(parsed.query)
                limit = 100
                if "limit" in query:
                    try:
                        limit = max(1, min(500, int(query["limit"][0])))
                    except (ValueError, TypeError):
                        limit = 100
                event_type = query.get("type", [None])[0]
                mac = query.get("mac", [None])[0]
                ip = query.get("ip", [None])[0]
                self._send_json_response(
                    200,
                    state.get_events_payload(limit=limit, event_type=event_type, mac=mac, ip=ip),
                )
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
        elif path in ("/api/status", "/api/devices", "/api/events"):
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
        if path == "/api/auth/login":
            self._handle_login_post()
        elif path == "/api/auth/logout":
            self._handle_logout_post()
        elif path == "/api/whitelist":
            if not self._is_request_authorized():
                self._send_json_response(401, {"error": "Authentication required", "auth_required": True})
                return
            self._handle_whitelist_post()
        elif path == "/api/scan":
            if not self._is_request_authorized():
                self._send_json_response(401, {"error": "Authentication required", "auth_required": True})
                return
            self._handle_scan_post(parsed)
        else:
            self._send_json_response(404, {"error": "Not Found"})

    def _handle_login_post(self):
        auth: Optional[WebAuthenticator] = getattr(self.server, "authenticator", None)
        if not auth or not auth.enabled:
            self._send_json_response(200, {"success": True, "message": "Authentication disabled"})
            return

        client_ip = self._get_client_ip()
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_json_response(400, {"success": False, "message": "Invalid Content-Length header"})
            return

        if content_length <= 0 or content_length > 4096:
            self._send_json_response(400, {"success": False, "message": "Invalid request body size"})
            return

        try:
            raw_body = self.rfile.read(content_length).decode("utf-8")
            payload = json.loads(raw_body)
        except Exception:
            self._send_json_response(400, {"success": False, "message": "Invalid JSON payload"})
            return

        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", "")).strip()

        success, token, err_msg, retry_after = auth.authenticate(username, password, client_ip)

        if not success:
            state: Optional[SentinelState] = getattr(self.server, "state", None)
            if state and hasattr(state, "event_mgr"):
                state.event_mgr.record(
                    event_type="AUTH_FAILURE",
                    severity="WARN",
                    title="Web Login Failure",
                    description=f"Failed login attempt for user '{username}' from IP {client_ip}",
                    ip=client_ip,
                )

            status_code = 429 if retry_after > 0 else 401
            body = json.dumps({"success": False, "message": err_msg or "Invalid credentials", "retry_after": retry_after}).encode("utf-8")
            try:
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if retry_after > 0:
                    self.send_header("Retry-After", str(retry_after))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                pass
            return

        # Success - set cookie
        is_https = self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        cookie_parts = [
            f"ah_session={token}",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            f"Max-Age={auth.session_manager.ttl_seconds}",
        ]
        if is_https:
            cookie_parts.append("Secure")
        cookie_header = "; ".join(cookie_parts)

        body = json.dumps({"success": True, "message": "Authenticated successfully"}).encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", cookie_header)
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def _handle_logout_post(self):
        auth: Optional[WebAuthenticator] = getattr(self.server, "authenticator", None)
        if auth and auth.enabled:
            cookie_header = self.headers.get("Cookie", "")
            if "ah_session=" in cookie_header:
                match = re.search(r"ah_session=([^;]+)", cookie_header)
                if match:
                    auth.session_manager.revoke_session(match.group(1).strip())

        cookie_header = "ah_session=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; SameSite=Strict"
        body = json.dumps({"success": True, "message": "Logged out successfully"}).encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", cookie_header)
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def _handle_scan_post(self, parsed):
        scan_trigger = getattr(self.server, "scan_trigger", None)
        if not scan_trigger:
            self._send_json_response(501, {"success": False, "message": "Manual scan triggering not supported in this mode"})
            return

        query = parse_qs(parsed.query)
        deep = query.get("deep", ["true"])[0].lower() in ("true", "1", "yes")
        ai = query.get("ai", ["true"])[0].lower() in ("true", "1", "yes")
        analyze_all = query.get("analyze_all", ["false"])[0].lower() in ("true", "1", "yes")

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0 and content_length <= 65536:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                payload = json.loads(raw_body)
                if isinstance(payload, dict):
                    if "deep" in payload:
                        deep = bool(payload["deep"])
                    if "ai" in payload:
                        ai = bool(payload["ai"])
                    if "analyze_all" in payload:
                        analyze_all = bool(payload["analyze_all"])
        except Exception:
            pass

        try:
            scan_trigger(deep=deep, ai=ai, analyze_all=analyze_all)
            self._send_json_response(200, {
                "success": True,
                "message": "Manual network audit triggered successfully",
                "deep": deep,
                "ai": ai,
                "analyze_all": analyze_all,
            })
        except Exception as e:
            self._send_json_response(500, {"success": False, "message": f"Failed to trigger scan: {e}"})

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

        # Look up existing device in state to preserve discovered telemetry
        vendor = "Manual Entry"
        discovered_dev: Optional[dict] = None
        if state:
            with state._lock:
                for dev in state.alien_devices + state.trusted_devices:
                    if dev.get("mac", "").upper() == mac:
                        discovered_dev = dict(dev)
                        vendor = dev.get("vendor") or vendor
                        if not primary_ip:
                            primary_ip = dev.get("ip", "")
                        break

        current_entry: dict = {}
        if discovered_dev:
            for field_src, field_dst in (
                ("ports", "ports"),
                ("open_ports", "ports"),
                ("services", "services"),
                ("mdns_services", "services"),
                ("aliases", "aliases"),
            ):
                val = discovered_dev.get(field_src)
                if val and not current_entry.get(field_dst):
                    current_entry[field_dst] = list(val)

            disc_method = discovered_dev.get("discovery_method", "")
            if disc_method:
                methods = [m.strip() for m in str(disc_method).split(",") if m.strip()]
                if methods:
                    current_entry["discovery_methods"] = sorted(list(set(methods)))

            obs_ttl = discovered_dev.get("observed_ttl")
            if isinstance(obs_ttl, int) and obs_ttl > 0:
                current_entry["baseline_ttl"] = estimate_initial_ttl(obs_ttl)

            learned_os = discovered_dev.get("tcp_syn_fingerprint") or discovered_dev.get("dhcp_fingerprint")
            if learned_os:
                current_entry["baseline_os"] = learned_os

        current_entry.update({
            "name": name,
            "owner": owner,
            "device_type": device_type,
            "primary_ip": primary_ip,
            "vendor": vendor,
            "trusted": True,
            "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

        # Persist to disk via ConfigManager if available, merging with any existing record
        if config_mgr:
            try:
                whitelist = config_mgr.load_whitelist(whitelist_path)
                existing_entry = whitelist.get(mac)
                if isinstance(existing_entry, dict):
                    merged = dict(existing_entry)
                    if not primary_ip and merged.get("primary_ip"):
                        current_entry["primary_ip"] = merged["primary_ip"]
                    if vendor == "Manual Entry" and merged.get("vendor"):
                        current_entry["vendor"] = merged["vendor"]
                    merged.update(current_entry)
                    current_entry = merged
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
    """Threaded HTTP server with port reuse enabled and quiet socket-reset handling."""
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Suppress multi-line tracebacks when clients abruptly close keep-alive sockets."""
        import sys
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            log.debug("HTTP client %s closed connection early: %s", client_address, exc)
            return
        super().handle_error(request, client_address)


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
        scan_trigger: Optional[Any] = None,
        auth_config: Optional[dict] = None,
        auth_log_path: Optional[str] = None,
    ):
        self.state = state
        self.config_mgr = config_mgr
        self.whitelist_path = whitelist_path
        self.host = host
        self.port = port
        self.scan_trigger = scan_trigger
        self.authenticator = WebAuthenticator(auth_config=auth_config, auth_log_path=auth_log_path)
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
            self.server.scan_trigger = self.scan_trigger  # type: ignore
            self.server.authenticator = self.authenticator  # type: ignore

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
