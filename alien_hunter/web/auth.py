"""
Authentication, Session Management, and Denial-of-Service Protection for Alien Hunter.
Implements dual-engine hashing (bcrypt with PBKDF2-HMAC-SHA256 fallback),
in-memory sliding-window rate limiting with exponential backoff lockout,
thread-safe session token management, and structured Fail2ban logging.
"""

from collections import deque
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
from typing import Dict, Optional, Tuple, Any

from ..logging_setup import get_logger

log = get_logger()

# Optional bcrypt support with graceful standard library fallback
try:
    import bcrypt  # type: ignore
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

MAX_PASSWORD_BYTES = 72  # bcrypt input length limit; prevents CPU complexity DoS


class PasswordHasher:
    """
    Dual-engine password hasher.
    Prefers bcrypt ($2b$12$) when available; falls back to PBKDF2-HMAC-SHA256 (600,000 rounds).
    """

    _hash_semaphore = threading.BoundedSemaphore(2)  # Limits concurrent expensive hashing

    @classmethod
    def _hash_pbkdf2(cls, password: str, rounds: int = 600_000) -> str:
        """Hashes password using standard-library PBKDF2-HMAC-SHA256."""
        pw_bytes = password.encode("utf-8")
        if len(pw_bytes) > MAX_PASSWORD_BYTES:
            pw_bytes = pw_bytes[:MAX_PASSWORD_BYTES]
        salt_bytes = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt_bytes, rounds)
        return f"pbkdf2:sha256:{rounds}${salt_bytes.hex()}${dk.hex()}"

    @classmethod
    def hash_password(cls, password: str, cost: int = 12) -> str:
        """Hashes a plaintext password string."""
        pw_bytes = password.encode("utf-8")
        if len(pw_bytes) > MAX_PASSWORD_BYTES:
            pw_bytes = pw_bytes[:MAX_PASSWORD_BYTES]

        with cls._hash_semaphore:
            if HAS_BCRYPT:
                salt = bcrypt.gensalt(rounds=cost)
                hashed = bcrypt.hashpw(pw_bytes, salt)
                return hashed.decode("utf-8")
            else:
                return cls._hash_pbkdf2(password)

    @classmethod
    def verify_password(cls, password: str, stored_hash: str) -> bool:
        """Verifies a plaintext password against a stored bcrypt or PBKDF2 hash."""
        if not stored_hash or not password:
            return False

        pw_bytes = password.encode("utf-8")
        if len(pw_bytes) > MAX_PASSWORD_BYTES:
            pw_bytes = pw_bytes[:MAX_PASSWORD_BYTES]

        with cls._hash_semaphore:
            try:
                # 1. bcrypt check
                if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
                    if HAS_BCRYPT:
                        return bcrypt.checkpw(pw_bytes, stored_hash.encode("utf-8"))
                    else:
                        log.debug("Encountered bcrypt hash but bcrypt library is not installed.")
                        return False

                # 2. PBKDF2 check format: pbkdf2:sha256:rounds$salt_hex$hash_hex
                if stored_hash.startswith("pbkdf2:sha256:"):
                    parts = stored_hash.split("$")
                    if len(parts) == 3:
                        header, salt_hex, expected_hex = parts
                        rounds = int(header.split(":")[-1])
                        salt_bytes = bytes.fromhex(salt_hex)
                        computed = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt_bytes, rounds).hex()
                        return secrets.compare_digest(computed, expected_hex)

                return False
            except Exception as e:
                log.debug("Password verification error: %s", e)
                return False


class AuthRateLimiter:
    """
    Sliding-window rate limiter with exponential backoff lockout.
    Tracks failed authentication attempts per client IP in memory with bounded state.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 600,
        base_delay_seconds: float = 2.0,
        max_lockout_seconds: float = 1800.0,
        max_tracked_ips: int = 2048,
        **kwargs,
    ):
        if "max_login_attempts" in kwargs:
            max_attempts = kwargs["max_login_attempts"]
        if "initial_backoff_seconds" in kwargs:
            base_delay_seconds = kwargs["initial_backoff_seconds"]
        if "max_backoff_seconds" in kwargs:
            max_lockout_seconds = kwargs["max_backoff_seconds"]
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.base_delay_seconds = base_delay_seconds
        self.max_lockout_seconds = max_lockout_seconds
        self.max_tracked_ips = max_tracked_ips
        self._lock = threading.Lock()
        self._records: Dict[str, Dict[str, Any]] = {}

    def _prune_expired_window(self, ip_data: Dict[str, Any], now: float) -> None:
        failures: deque = ip_data["failures"]
        cutoff = now - self.window_seconds
        while failures and failures[0] < cutoff:
            failures.popleft()

    def check_allowed(self, ip: str) -> Tuple[bool, int]:
        """
        Returns (is_allowed, retry_after_seconds).
        Executed in O(1) memory time BEFORE verifying password hashes.
        """
        now = time.time()
        with self._lock:
            data = self._records.get(ip)
            if not data:
                return True, 0

            # 1. Check active lockout
            locked_until = data.get("locked_until", 0.0)
            if now < locked_until:
                retry_after = max(1, int(locked_until - now))
                return False, retry_after

            # 2. Prune sliding window; reset consecutive failure count if window emptied
            self._prune_expired_window(data, now)
            if not data["failures"]:
                data["consecutive_failures"] = 0
                data["locked_until"] = 0.0

            return True, 0

    def record_failure(self, ip: str) -> int:
        """
        Records a failed attempt for client IP and computes lockout if threshold is met.
        Returns remaining lockout / delay in seconds (0 if not locked out).
        """
        now = time.time()
        with self._lock:
            if len(self._records) >= self.max_tracked_ips and ip not in self._records:
                # Evict oldest entry
                oldest_ip = min(self._records.keys(), key=lambda k: self._records[k].get("last_seen", 0.0))
                del self._records[oldest_ip]

            data = self._records.setdefault(
                ip,
                {"failures": deque(), "consecutive_failures": 0, "locked_until": 0.0, "last_seen": now},
            )
            data["last_seen"] = now
            self._prune_expired_window(data, now)
            if not data["failures"]:
                data["consecutive_failures"] = 0
            data["failures"].append(now)
            data["consecutive_failures"] += 1

            if data["consecutive_failures"] >= self.max_attempts:
                exponent = max(0, data["consecutive_failures"] - self.max_attempts)
                lock_duration = min(self.max_lockout_seconds, self.base_delay_seconds * (2 ** exponent))
                data["locked_until"] = now + lock_duration
                return max(1, int(lock_duration))

            return 0

    def record_success(self, ip: str) -> None:
        """Clears failure state for IP upon successful authentication."""
        with self._lock:
            if ip in self._records:
                del self._records[ip]


class SessionManager:
    """
    256-bit token session store with TTL expiration and optional persistent
    on-disk storage (SHA-256 token digests) for remembered devices.
    """

    DEFAULT_PERSISTENT_TTL_SECONDS = 2592000  # 30 days

    def __init__(
        self,
        ttl_seconds: int = 86400,
        persistent_ttl_seconds: int = DEFAULT_PERSISTENT_TTL_SECONDS,
        max_sessions: int = 200,
        session_file: Optional[str] = None,
        **kwargs,
    ):
        if "session_ttl_seconds" in kwargs:
            ttl_seconds = kwargs["session_ttl_seconds"]
        if "persistent_session_ttl_seconds" in kwargs:
            persistent_ttl_seconds = kwargs["persistent_session_ttl_seconds"]
        self.ttl_seconds = int(ttl_seconds)
        self.persistent_ttl_seconds = int(persistent_ttl_seconds)
        self.max_sessions = max_sessions
        self.session_file = session_file
        self._lock = threading.Lock()
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._persisted_sessions: Dict[str, Dict[str, Any]] = {}
        if self.session_file:
            self._load_persisted_sessions()

    @staticmethod
    def _hash_token(token: str) -> str:
        """Returns SHA-256 hex digest of a session token for disk storage."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _load_persisted_sessions(self) -> None:
        """Loads non-expired persistent session digests from disk."""
        if not self.session_file or not os.path.exists(self.session_file):
            return
        try:
            with open(self.session_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return
            now = time.time()
            loaded: Dict[str, Dict[str, Any]] = {}
            for token_hash, entry in data.items():
                if not (isinstance(token_hash, str) and isinstance(entry, dict) and isinstance(entry.get("username"), str)):
                    continue
                try:
                    expires = float(entry.get("expires", 0))
                    created = float(entry.get("created", now))
                except (ValueError, TypeError):
                    continue
                if expires >= now:
                    loaded[token_hash] = {
                        "username": entry["username"],
                        "ip": str(entry.get("ip", "")),
                        "created": created,
                        "expires": expires,
                    }
            self._persisted_sessions = loaded
        except Exception as e:
            log.debug("Failed loading persisted sessions from %s: %s", self.session_file, e)

    def _save_persisted_sessions(self) -> None:
        """Atomically writes persistent session digests to disk with 0600 permissions."""
        if not self.session_file:
            return
        try:
            abs_path = os.path.abspath(self.session_file)
            parent = os.path.dirname(abs_path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=".web_sessions_", suffix=".tmp", dir=parent or ".")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    os.fchmod(f.fileno(), 0o600)
                    json.dump(self._persisted_sessions, f, indent=2)
                os.replace(tmp_path, abs_path)
            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise
        except Exception as e:
            log.debug("Failed saving persisted sessions to %s: %s", self.session_file, e)

    def get_session_ttl(self, remember_me: bool = False) -> int:
        """Returns the session TTL in seconds for standard or persistent sessions."""
        return self.persistent_ttl_seconds if remember_me else self.ttl_seconds

    def create_session(self, username: str, ip: str, remember_me: bool = False) -> str:
        """Generates a secure random session token."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        expires = now + self.get_session_ttl(remember_me)
        persisted_dirty = False

        with self._lock:
            # Evict expired sessions
            expired_keys = [k for k, v in self._sessions.items() if v["expires"] < now]
            for k in expired_keys:
                del self._sessions[k]

            expired_hashes = [h for h, v in self._persisted_sessions.items() if v["expires"] < now]
            for h in expired_hashes:
                del self._persisted_sessions[h]
                persisted_dirty = True

            while len(self._sessions) >= self.max_sessions and self._sessions:
                oldest_key = min(self._sessions.keys(), key=lambda k: self._sessions[k]["expires"])
                del self._sessions[oldest_key]
                oldest_hash = self._hash_token(oldest_key)
                if oldest_hash in self._persisted_sessions:
                    del self._persisted_sessions[oldest_hash]
                    persisted_dirty = True

            while len(self._persisted_sessions) >= self.max_sessions and self._persisted_sessions:
                oldest_hash = min(self._persisted_sessions.keys(), key=lambda h: self._persisted_sessions[h]["expires"])
                del self._persisted_sessions[oldest_hash]
                persisted_dirty = True

            entry = {
                "username": username,
                "ip": ip,
                "created": now,
                "expires": expires,
            }
            self._sessions[token] = entry

            if remember_me and self.session_file:
                self._persisted_sessions[self._hash_token(token)] = dict(entry)
                persisted_dirty = True

            if persisted_dirty:
                self._save_persisted_sessions()

        return token

    def validate_session(self, token: Optional[str]) -> Optional[str]:
        """Validates token. Returns username if valid; None if expired or invalid."""
        if not token:
            return None
        now = time.time()
        with self._lock:
            sess = self._sessions.get(token)
            if sess:
                if sess["expires"] < now:
                    del self._sessions[token]
                    token_hash = self._hash_token(token)
                    if token_hash in self._persisted_sessions:
                        del self._persisted_sessions[token_hash]
                        self._save_persisted_sessions()
                    return None
                return sess["username"]

            if self._persisted_sessions:
                token_hash = self._hash_token(token)
                persisted = self._persisted_sessions.get(token_hash)
                if persisted:
                    if persisted["expires"] < now:
                        del self._persisted_sessions[token_hash]
                        self._save_persisted_sessions()
                        return None
                    return persisted["username"]
            return None

    def revoke_session(self, token: str) -> bool:
        """Revokes an active or persisted session."""
        if not token:
            return False
        with self._lock:
            revoked = False
            if token in self._sessions:
                del self._sessions[token]
                revoked = True
            token_hash = self._hash_token(token)
            if token_hash in self._persisted_sessions:
                del self._persisted_sessions[token_hash]
                self._save_persisted_sessions()
                revoked = True
            return revoked


class WebAuthenticator:
    """
    Coordinates password verification, rate-limiting, session state,
    and structured Fail2ban logging.
    """

    def __init__(
        self,
        auth_config: Optional[Dict[str, Any]] = None,
        auth_log_path: Optional[str] = None,
        session_file: Optional[str] = None,
    ):
        self.config = auth_config or {}
        self.enabled = bool(self.config.get("enabled", False))
        self.username = str(self.config.get("username", "admin")).strip()
        self.password_hash = str(self.config.get("password_hash", "")).strip()
        self.auth_log_path = auth_log_path

        self.rate_limiter = AuthRateLimiter(
            max_attempts=int(self.config.get("max_attempts") or self.config.get("max_login_attempts") or 5),
            window_seconds=int(self.config.get("window_seconds") or self.config.get("rate_limit_window") or 600),
            base_delay_seconds=float(self.config.get("base_delay_seconds") or self.config.get("initial_backoff_seconds") or 2.0),
            max_lockout_seconds=float(self.config.get("max_lockout_seconds") or self.config.get("max_backoff_seconds") or 1800.0),
        )
        resolved_session_file = self.config.get("session_file") or session_file
        self.session_manager = SessionManager(
            ttl_seconds=int(self.config.get("session_ttl_seconds") or self.config.get("ttl_seconds") or 86400),
            persistent_ttl_seconds=int(
                self.config.get("persistent_session_ttl_seconds")
                or self.config.get("persistent_ttl_seconds")
                or SessionManager.DEFAULT_PERSISTENT_TTL_SECONDS
            ),
            session_file=resolved_session_file,
        )

    @staticmethod
    def _sanitize_log_field(value: Any, max_len: int = 128) -> str:
        """Strips control chars, newlines, and quotes to prevent Fail2ban log injection."""
        cleaned = "".join(
            ch for ch in str(value or "")
            if ch not in ('"', "\r", "\n", "\\") and ord(ch) >= 0x20 and ord(ch) != 0x7F
        )
        return cleaned[:max_len]

    def log_auth_failure(self, username: str, ip: str, reason: str = "invalid_credentials") -> None:
        """
        Emits standard single-line structured log for Fail2ban parsing.
        Example: 2026-10-20T22:25:00Z [AUTH_FAILURE] user="admin" ip="192.168.1.150" reason="invalid_credentials"
        """
        safe_user = self._sanitize_log_field(username)
        safe_ip = self._sanitize_log_field(ip, max_len=64)
        safe_reason = self._sanitize_log_field(reason, max_len=64)
        iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = f'{iso_time} [AUTH_FAILURE] user="{safe_user}" ip="{safe_ip}" reason="{safe_reason}"'
        print(line, file=sys.stderr, flush=True)

        if self.auth_log_path:
            try:
                parent = os.path.dirname(os.path.abspath(self.auth_log_path))
                if parent and not os.path.exists(parent):
                    os.makedirs(parent, exist_ok=True)
                with open(self.auth_log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception as e:
                log.debug("Failed writing to auth_log_path %s: %s", self.auth_log_path, e)

    def authenticate(
        self,
        username: str,
        password: str,
        client_ip: str,
        remember_me: bool = False,
    ) -> Tuple[bool, Optional[str], Optional[str], int]:
        """
        Authenticates credentials against stored password hash.
        Returns (success, session_token, error_message, retry_after).
        """
        if not self.enabled:
            return True, None, None, 0

        # 1. Pre-hash rate limit check (O(1) gatekeeper)
        allowed, retry_after = self.rate_limiter.check_allowed(client_ip)
        if not allowed:
            self.log_auth_failure(username, client_ip, reason="rate_limited")
            return False, None, f"Too many failed login attempts. Retry in {retry_after}s.", retry_after

        # 2. Constant-time username match
        user_match = secrets.compare_digest(username.strip(), self.username)

        # 3. Verify password hash
        pw_match = PasswordHasher.verify_password(password, self.password_hash)

        if user_match and pw_match:
            self.rate_limiter.record_success(client_ip)
            token = self.session_manager.create_session(self.username, client_ip, remember_me=remember_me)
            return True, token, None, 0
        else:
            lockout = self.rate_limiter.record_failure(client_ip)
            self.log_auth_failure(username, client_ip, reason="invalid_credentials")
            if lockout > 0:
                return False, None, f"Invalid credentials. Account locked for {lockout}s.", lockout
            return False, None, "Invalid username or password.", 0
