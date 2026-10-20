"""
Unit tests for Alien Hunter Web UI Authentication, DoS Rate Limiting,
and Fail2ban compatibility.
"""

from collections import deque
import json
import os
import re
import tempfile
import time
import unittest
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from alien_hunter.config import ConfigManager
from alien_hunter.models import Device
from alien_hunter.web.auth import (
    AuthRateLimiter,
    PasswordHasher,
    SessionManager,
    WebAuthenticator,
)
from alien_hunter.web.server import LightweightWebServer
from alien_hunter.web.state import SentinelState


class TestPasswordHasher(unittest.TestCase):
    """Tests password hashing and verification with bcrypt and fallback."""

    def setUp(self):
        self.hasher = PasswordHasher()

    def test_bcrypt_or_pbkdf2_hashing(self):
        password = "CorrectHorseBatteryStaple123!"
        hashed = self.hasher.hash_password(password)
        self.assertIsInstance(hashed, str)
        self.assertTrue(hashed.startswith("$2b$") or hashed.startswith("pbkdf2:sha256:"))

        # Verify correct password
        self.assertTrue(self.hasher.verify_password(password, hashed))

        # Verify incorrect password
        self.assertFalse(self.hasher.verify_password("WrongPassword!", hashed))

    def test_pbkdf2_fallback_explicit(self):
        password = "MySecurePassword"
        pbkdf2_hash = self.hasher._hash_pbkdf2(password)
        self.assertTrue(pbkdf2_hash.startswith("pbkdf2:sha256:"))
        self.assertTrue(self.hasher.verify_password(password, pbkdf2_hash))
        self.assertFalse(self.hasher.verify_password("WrongPass", pbkdf2_hash))

    def test_password_truncation_72_bytes(self):
        # bcrypt has a 72-byte limit; hasher should truncate safely without raising
        long_password = "A" * 100
        hashed = self.hasher.hash_password(long_password)
        self.assertTrue(self.hasher.verify_password(long_password, hashed))
        # First 72 characters should match
        self.assertTrue(self.hasher.verify_password("A" * 72 + "XYZ", hashed))
        # Different first 72 characters should fail
        self.assertFalse(self.hasher.verify_password("B" * 72, hashed))

    def test_invalid_hash_format(self):
        self.assertFalse(self.hasher.verify_password("password", "invalid_garbage_hash"))
        self.assertFalse(self.hasher.verify_password("password", ""))


class TestAuthRateLimiter(unittest.TestCase):
    """Tests sliding window rate limiting and exponential backoff lockout."""

    def setUp(self):
        self.limiter = AuthRateLimiter(
            max_attempts=3,
            window_seconds=10,
            base_delay_seconds=5.0,
            max_lockout_seconds=60.0,
        )

    def test_allow_within_limit(self):
        ip = "192.168.1.100"
        allowed, retry = self.limiter.check_allowed(ip)
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)

        # Record 2 failures (limit is 3)
        self.assertEqual(self.limiter.record_failure(ip), 0)
        self.assertEqual(self.limiter.record_failure(ip), 0)

        allowed, retry = self.limiter.check_allowed(ip)
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)

    def test_lockout_and_backoff(self):
        ip = "192.168.1.101"
        self.limiter.record_failure(ip)
        self.limiter.record_failure(ip)
        lockout1 = self.limiter.record_failure(ip)
        self.assertEqual(lockout1, 5)

        # Should now be locked out
        allowed, retry = self.limiter.check_allowed(ip)
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        self.assertLessEqual(retry, 5)

        # Additional failure while locked out doubles backoff (5 * 2^1 = 10)
        lockout2 = self.limiter.record_failure(ip)
        self.assertEqual(lockout2, 10)

    def test_reset_on_success(self):
        ip = "192.168.1.102"
        self.limiter.record_failure(ip)
        self.limiter.record_failure(ip)
        self.limiter.record_success(ip)

        allowed, retry = self.limiter.check_allowed(ip)
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)
        self.assertNotIn(ip, self.limiter._records)

    def test_sliding_window_eviction(self):
        ip = "192.168.1.103"
        now = time.time()
        # Seed attempts in the past outside the 10s window
        self.limiter._records[ip] = {
            "failures": deque([now - 20, now - 15]),
            "consecutive_failures": 2,
            "locked_until": 0.0,
            "last_seen": now - 15,
        }
        allowed, _ = self.limiter.check_allowed(ip)
        self.assertTrue(allowed)
        # Old attempts should be evicted
        self.assertEqual(len(self.limiter._records[ip]["failures"]), 0)


class TestSessionManager(unittest.TestCase):
    """Tests session token issuance, validation, expiration, and eviction."""

    def setUp(self):
        self.sessions = SessionManager(ttl_seconds=2, max_sessions=3)

    def test_create_and_validate_session(self):
        token = self.sessions.create_session("admin", "192.168.1.50")
        self.assertIsInstance(token, str)
        self.assertGreaterEqual(len(token), 32)
        self.assertEqual(self.sessions.validate_session(token), "admin")

    def test_invalid_session(self):
        self.assertIsNone(self.sessions.validate_session("nonexistent_token"))
        self.assertIsNone(self.sessions.validate_session(None))
        self.assertIsNone(self.sessions.validate_session(""))

    def test_revoke_session(self):
        token = self.sessions.create_session("admin", "192.168.1.50")
        self.assertEqual(self.sessions.validate_session(token), "admin")
        self.assertTrue(self.sessions.revoke_session(token))
        self.assertIsNone(self.sessions.validate_session(token))

    def test_session_ttl_expiration(self):
        token = self.sessions.create_session("admin", "192.168.1.50")
        # Artificially age the session expiration
        self.sessions._sessions[token]["expires"] = time.time() - 10
        self.assertIsNone(self.sessions.validate_session(token))
        self.assertNotIn(token, self.sessions._sessions)

    def test_max_sessions_eviction(self):
        t1 = self.sessions.create_session("user1", "10.0.0.1")
        time.sleep(0.01)
        t2 = self.sessions.create_session("user2", "10.0.0.2")
        time.sleep(0.01)
        t3 = self.sessions.create_session("user3", "10.0.0.3")
        time.sleep(0.01)
        # 4th session should evict t1 (oldest expiry)
        t4 = self.sessions.create_session("user4", "10.0.0.4")

        self.assertIsNone(self.sessions.validate_session(t1))
        self.assertEqual(self.sessions.validate_session(t2), "user2")
        self.assertEqual(self.sessions.validate_session(t3), "user3")
        self.assertEqual(self.sessions.validate_session(t4), "user4")


class TestWebAuthenticator(unittest.TestCase):
    """Tests WebAuthenticator integration with logging and rate limiting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = os.path.join(self.temp_dir.name, "auth.log")
        self.hasher = PasswordHasher()
        self.pw_hash = self.hasher.hash_password("AdminPass123")
        self.config = {
            "enabled": True,
            "username": "secadmin",
            "password_hash": self.pw_hash,
            "rate_limit_window": 600,
            "max_login_attempts": 3,
            "initial_backoff_seconds": 30,
            "max_backoff_seconds": 3600,
            "session_ttl_seconds": 86400,
        }
        self.auth = WebAuthenticator(self.config, auth_log_path=self.log_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_authenticate_success(self):
        success, token, msg, retry = self.auth.authenticate("secadmin", "AdminPass123", "192.168.1.77")
        self.assertTrue(success)
        self.assertIsNotNone(token)
        self.assertIsNone(msg)
        self.assertEqual(retry, 0)
        self.assertEqual(self.auth.session_manager.validate_session(token), "secadmin")

    def test_authenticate_wrong_password(self):
        success, token, msg, retry = self.auth.authenticate("secadmin", "WrongPass", "192.168.1.77")
        self.assertFalse(success)
        self.assertIsNone(token)
        self.assertIn("Invalid", msg)

    def test_authenticate_wrong_user(self):
        success, token, msg, retry = self.auth.authenticate("wronguser", "AdminPass123", "192.168.1.77")
        self.assertFalse(success)
        self.assertIsNone(token)
        self.assertIn("Invalid", msg)

    def test_dos_lockout(self):
        ip = "192.168.1.88"
        for _ in range(3):
            self.auth.authenticate("secadmin", "bad", ip)

        # 4th attempt should be blocked by rate limiter
        success, token, msg, retry = self.auth.authenticate("secadmin", "AdminPass123", ip)
        self.assertFalse(success)
        self.assertIsNone(token)
        self.assertGreater(retry, 0)
        self.assertIn("Too many failed", msg)

    def test_fail2ban_log_format(self):
        self.auth.log_auth_failure("intruder", "192.168.1.200", reason="invalid_credentials")
        with open(self.log_file, "r", encoding="utf-8") as f:
            log_content = f.read().strip()

        # Regex matching deploy/fail2ban/filter.d/alien-hunter.conf
        pattern = r'\[AUTH_FAILURE\] user="(?P<user>[^"]+)" ip="(?P<ip>[^"]+)" reason="(?P<reason>[^"]+)"'
        match = re.search(pattern, log_content)
        self.assertIsNotNone(match)
        self.assertEqual(match.group("user"), "intruder")
        self.assertEqual(match.group("ip"), "192.168.1.200")
        self.assertEqual(match.group("reason"), "invalid_credentials")


class TestWebServerAuthenticationEndpoints(unittest.TestCase):
    """Integration tests for HTTP endpoints with authentication enabled."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.whitelist_file = os.path.join(self.temp_dir.name, "known_devices.json")
        self.config_mgr = ConfigManager()

        initial_whitelist = {
            "11:22:33:44:55:66": {
                "name": "Gateway Router",
                "owner": "Admin",
                "device_type": "Gateway",
                "primary_ip": "192.168.1.1",
            }
        }
        self.config_mgr.save_whitelist(initial_whitelist, self.whitelist_file)

        self.state = SentinelState(interval=300)
        self.state.initialize_from_whitelist(initial_whitelist)

        hasher = PasswordHasher()
        self.password = "Secur3Passw0rd!"
        self.pw_hash = hasher.hash_password(self.password)

        self.auth_config = {
            "enabled": True,
            "username": "admin",
            "password_hash": self.pw_hash,
            "max_attempts": 3,
            "window_seconds": 60,
            "base_delay_seconds": 10.0,
            "session_ttl_seconds": 3600,
        }

        self.web_server = LightweightWebServer(
            state=self.state,
            config_mgr=self.config_mgr,
            whitelist_path=self.whitelist_file,
            host="127.0.0.1",
            port=0,
            auth_config=self.auth_config,
        )
        self.assertTrue(self.web_server.start())
        self.base_url = f"http://127.0.0.1:{self.web_server.port}"

    def tearDown(self):
        self.web_server.stop()
        self.temp_dir.cleanup()

    def test_unauthenticated_protected_api_endpoints(self):
        headers = {"User-Agent": "Mozilla/5.0"}
        for endpoint in ["/api/status", "/api/devices", "/api/events"]:
            req = Request(f"{self.base_url}{endpoint}", headers=headers)
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req, timeout=3)
            self.assertEqual(ctx.exception.code, 401)
            err_data = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertTrue(err_data.get("auth_required"))

    def test_auth_status_endpoint(self):
        headers = {"User-Agent": "Mozilla/5.0"}
        req = Request(f"{self.base_url}/api/auth/status", headers=headers)
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(data.get("auth_enabled") or data.get("auth_required"))
            self.assertFalse(data.get("is_authenticated") or data.get("authenticated"))

    def test_login_flow_and_session_cookie(self):
        headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}

        # 1. Failed login
        bad_payload = json.dumps({"username": "admin", "password": "WrongPassword"}).encode("utf-8")
        req = Request(f"{self.base_url}/api/auth/login", data=bad_payload, headers=headers, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 401)

        # 2. Successful login
        good_payload = json.dumps({"username": "admin", "password": self.password}).encode("utf-8")
        req = Request(f"{self.base_url}/api/auth/login", data=good_payload, headers=headers, method="POST")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(data["success"])

            # Check Set-Cookie header
            cookie_header = res.headers.get("Set-Cookie", "")
            self.assertIn("ah_session=", cookie_header)
            self.assertIn("HttpOnly", cookie_header)
            self.assertIn("SameSite=Strict", cookie_header)

            token = cookie_header.split("ah_session=")[1].split(";")[0]

        # 3. Access protected endpoint with cookie
        auth_headers = {"User-Agent": "Mozilla/5.0", "Cookie": f"ah_session={token}"}
        req = Request(f"{self.base_url}/api/status", headers=auth_headers)
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            status_data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(status_data["is_running"])

        # 4. Logout
        req = Request(f"{self.base_url}/api/auth/logout", data=b"{}", headers=auth_headers, method="POST")
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            logout_cookie = res.headers.get("Set-Cookie", "")
            self.assertIn("Max-Age=0", logout_cookie)

        # 5. Protected endpoint should now return 401
        req = Request(f"{self.base_url}/api/status", headers=auth_headers)
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 401)

    def test_dos_rate_limit_http_429(self):
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json",
            "X-Forwarded-For": "203.0.113.42",
        }
        bad_payload = json.dumps({"username": "admin", "password": "WrongPassword"}).encode("utf-8")

        # First 2 attempts return 401 (max_attempts is 3)
        for _ in range(2):
            req = Request(f"{self.base_url}/api/auth/login", data=bad_payload, headers=headers, method="POST")
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req, timeout=3)
            self.assertEqual(ctx.exception.code, 401)

        # 3rd attempt triggers lockout threshold and returns 429
        req = Request(f"{self.base_url}/api/auth/login", data=bad_payload, headers=headers, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 429)
        self.assertIn("Retry-After", ctx.exception.headers)

        # 4th attempt is blocked pre-hash by rate limiter and returns 429
        req = Request(f"{self.base_url}/api/auth/login", data=bad_payload, headers=headers, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 429)
        self.assertIn("Retry-After", ctx.exception.headers)

    def test_cli_local_bypass(self):
        # Direct CLI user agent on loopback should bypass auth
        cli_headers = {"User-Agent": "AlienHunterCLI/1.0"}
        req = Request(f"{self.base_url}/api/status", headers=cli_headers)
        with urlopen(req, timeout=3) as res:
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode("utf-8"))
            self.assertTrue(data["is_running"])


if __name__ == "__main__":
    unittest.main()
