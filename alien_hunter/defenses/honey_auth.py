"""
Decoy Honey-Share & Authentication Canary ("HoneyAuthTrap").
Inspects incoming TCP payloads on decoy ports to capture pre-authentication
handshakes (HTTP headers, basic authentication credentials, tooling user-agents,
and raw probe payloads) without exposing real services.
"""

import base64
import socket
from typing import Dict


class HoneyAuthTrap:
    """Inspects pre-authentication handshakes on decoy honeypot connections."""

    @staticmethod
    def inspect_connection(conn: socket.socket, dest_port: int, timeout: float = 0.2) -> Dict[str, str]:
        """
        Reads initial incoming payload from client connection with a short timeout.
        Extracts tooling (User-Agent), requested endpoint, and attempted credentials.
        """
        metadata = {
            "payload_snippet": "",
            "tooling": "",
            "credentials": "",
        }
        try:
            conn.settimeout(timeout)
            data = conn.recv(1024)
            if not data:
                return metadata

            # Check binary protocol signatures first
            if b"SMB" in data[:12]:
                metadata["tooling"] = "SMB Dialect Probe"
                metadata["payload_snippet"] = "SMB Negotiation Request"
                return metadata

            if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03:
                metadata["tooling"] = "TLS/SSL Handshake"
                metadata["payload_snippet"] = "TLS Client Hello"
                return metadata

            try:
                text = data.decode("utf-8", errors="replace")
                lines = text.splitlines()

                # HTTP inspection
                if lines and any(lines[0].startswith(m) for m in ("GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ")):
                    metadata["payload_snippet"] = lines[0].strip()[:100]
                    for line in lines[1:]:
                        line_clean = line.strip()
                        if line_clean.lower().startswith("user-agent:"):
                            metadata["tooling"] = line_clean.split(":", 1)[1].strip()[:120]
                        elif line_clean.lower().startswith("authorization:"):
                            auth_val = line_clean.split(":", 1)[1].strip()
                            if auth_val.lower().startswith("basic "):
                                try:
                                    b64_creds = auth_val.split(" ", 1)[1].strip()
                                    decoded_creds = base64.b64decode(b64_creds).decode("utf-8", errors="replace")
                                    metadata["credentials"] = decoded_creds[:80]
                                except Exception:
                                    metadata["credentials"] = auth_val[:80]
                            else:
                                metadata["credentials"] = auth_val[:80]

                # Text/command probe (Telnet, FTP, SMTP, raw scripts)
                elif lines and lines[0].strip():
                    metadata["payload_snippet"] = lines[0].strip()[:100]
                else:
                    metadata["payload_snippet"] = data[:32].hex()

            except Exception:
                metadata["payload_snippet"] = data[:32].hex()

        except (socket.timeout, BlockingIOError, OSError):
            pass

        return metadata
