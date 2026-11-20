"""
Shared HTTP safety helpers for Alien Hunter.
Enforces URL scheme validation, host/SSRF checks, safe redirect handling,
bounded response reads, and secret redaction for logs.
"""

import ipaddress
import re
from typing import Any, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

_ORIG_URLOPEN = urllib.request.urlopen

_METADATA_IPS = frozenset({"169.254.169.254", "169.254.170.2", "fd00:ec2::254"})
_METADATA_HOSTS = frozenset({"localhost", "localhost.localdomain", "metadata.google.internal", "metadata"})
_SENSITIVE_HEADERS = frozenset({"authorization", "x-api-key", "x-goog-api-key", "cookie", "proxy-authorization"})


def validate_http_url(
    url: str,
    allowed_schemes: Tuple[str, ...] = ("http", "https"),
    expected_host_ip: Optional[str] = None,
    reject_loopback_and_metadata: bool = False,
) -> urllib.parse.ParseResult:
    """Validates URL scheme, hostname, optional peer IP binding, and SSRF targets."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")

    parsed = urllib.parse.urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    allowed = tuple(s.lower() for s in allowed_schemes)
    if scheme not in allowed:
        raise ValueError(f"Disallowed URL scheme: {scheme!r}")

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        raise ValueError("URL missing hostname")

    host_clean = hostname.split("%", 1)[0]

    if expected_host_ip is not None:
        exp_clean = str(expected_host_ip).strip().split("%", 1)[0]
        try:
            host_ip_obj = ipaddress.ip_address(host_clean)
            exp_ip_obj = ipaddress.ip_address(exp_clean)
        except ValueError as exc:
            raise ValueError(f"URL host {hostname!r} must match numeric peer IP {expected_host_ip!r}") from exc
        if host_ip_obj != exp_ip_obj:
            raise ValueError(f"URL host IP {host_ip_obj} does not match expected peer IP {exp_ip_obj}")

    if reject_loopback_and_metadata:
        host_lower = host_clean.lower().rstrip(".")
        if host_lower in _METADATA_HOSTS or host_lower.endswith(".localhost"):
            raise ValueError(f"Disallowed loopback/metadata hostname: {hostname!r}")
        try:
            ip_obj = ipaddress.ip_address(host_clean)
        except ValueError:
            ip_obj = None

        if ip_obj is not None:
            mapped_v4 = getattr(ip_obj, "ipv4_mapped", None)
            check_ip = mapped_v4 if mapped_v4 is not None else ip_obj
            if (
                check_ip.is_loopback
                or check_ip.is_unspecified
                or check_ip.is_multicast
                or str(check_ip) in _METADATA_IPS
                or str(ip_obj) in _METADATA_IPS
            ):
                raise ValueError(f"Disallowed loopback/metadata IP: {hostname!r}")

    return parsed


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Blocks all HTTP 3xx redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"HTTP redirect disabled ({code} -> {newurl})",
            headers,
            fp,
        )


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validates redirect targets, prevents scheme downgrades, and strips cross-origin credentials."""

    def __init__(self, allowed_schemes: Tuple[str, ...] = ("http", "https")):
        self.allowed_schemes = tuple(s.lower() for s in allowed_schemes)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old_parsed = urllib.parse.urlparse(req.full_url)
        resolved_url = urllib.parse.urljoin(req.full_url, newurl)
        new_parsed = urllib.parse.urlparse(resolved_url)

        old_scheme = old_parsed.scheme.lower()
        new_scheme = new_parsed.scheme.lower()
        if new_scheme not in self.allowed_schemes:
            raise urllib.error.HTTPError(
                req.full_url, code, f"Disallowed redirect scheme: {new_scheme}", headers, fp
            )
        if old_scheme == "https" and new_scheme != "https":
            raise urllib.error.HTTPError(
                req.full_url, code, "Blocked HTTPS-to-HTTP redirect downgrade", headers, fp
            )

        new_req = super().redirect_request(req, fp, code, msg, headers, resolved_url)
        if new_req is None:
            return None

        old_origin = (old_scheme, old_parsed.netloc.lower())
        new_origin = (new_scheme, new_parsed.netloc.lower())
        if old_origin != new_origin:
            for hdr_name in list(new_req.headers.keys()):
                low = hdr_name.lower()
                if low in _SENSITIVE_HEADERS or "token" in low or "secret" in low or "key" in low:
                    new_req.remove_header(hdr_name)
            for hdr_name in list(new_req.unredirected_hdrs.keys()):
                low = hdr_name.lower()
                if low in _SENSITIVE_HEADERS or "token" in low or "secret" in low or "key" in low:
                    new_req.unredirected_hdrs.pop(hdr_name, None)

        return new_req


def safe_urlopen(
    req_or_url: Any,
    timeout: float = 10.0,
    allowed_schemes: Tuple[str, ...] = ("http", "https"),
    allow_redirects: bool = False,
    allow_proxies: bool = True,
    expected_host_ip: Optional[str] = None,
    reject_loopback_and_metadata: bool = False,
):
    """Executes URL validation, safe redirect/proxy policies, and opens an HTTP request."""
    url = req_or_url.full_url if hasattr(req_or_url, "full_url") else str(req_or_url)
    validate_http_url(
        url,
        allowed_schemes=allowed_schemes,
        expected_host_ip=expected_host_ip,
        reject_loopback_and_metadata=reject_loopback_and_metadata,
    )

    if urllib.request.urlopen is not _ORIG_URLOPEN:
        return urllib.request.urlopen(req_or_url, timeout=timeout)

    handlers = []
    if not allow_proxies:
        handlers.append(urllib.request.ProxyHandler({}))
    if allow_redirects:
        handlers.append(_SafeRedirectHandler(allowed_schemes=allowed_schemes))
    else:
        handlers.append(_NoRedirectHandler())

    opener = urllib.request.build_opener(*handlers)
    return opener.open(req_or_url, timeout=timeout)


def read_bounded(response: Any, max_bytes: int) -> bytes:
    """Reads up to max_bytes from an HTTP response, raising ValueError if exceeded."""
    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"HTTP response exceeded maximum allowed size of {max_bytes} bytes")
    return data


def redact_url_secrets(url: str) -> str:
    """Masks embedded API keys, bot tokens, and webhook secrets in URLs before logging."""
    if not url:
        return ""
    masked = re.sub(r"([?&](?:key|api_key|token|access_token)=)[^&]+", r"\1***", str(url), flags=re.IGNORECASE)
    masked = re.sub(r"(/bot)[^/]+", r"\1***", masked)
    masked = re.sub(r"(/api/webhooks/\d+/)[^/?\s]+", r"\1***", masked)
    masked = re.sub(r"(/services/[^/\s]+/[^/\s]+/)[^/?\s]+", r"\1***", masked)
    return masked
