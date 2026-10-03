"""
Port Scanner and Security Vulnerability Inspector.
Probes target hosts for open ports, exposed databases, unencrypted protocols,
and unauthenticated web management portals.
"""

import re
import socket
import urllib.request
from typing import List, Tuple, Dict, Optional


SECURITY_PORT_SIGNATURES: Dict[int, Tuple[str, str, str]] = {
    21: ("FTP", "HIGH", "Unencrypted file transfer protocol. Credentials sent in plaintext."),
    22: ("SSH", "LOW", "Secure shell service."),
    23: ("Telnet", "CRITICAL", "Unencrypted legacy remote shell. Vulnerable to interception/tampering."),
    53: ("DNS", "LOW", "Domain Name System."),
    80: ("HTTP", "MEDIUM", "Unencrypted web management portal."),
    135: ("MSRPC", "MEDIUM", "Microsoft Windows RPC endpoint mapper."),
    139: ("NetBIOS-SSN", "MEDIUM", "Legacy Windows NetBIOS/SMB file sharing."),
    443: ("HTTPS", "LOW", "Encrypted web management portal."),
    445: ("SMB", "HIGH", "Direct SMB file sharing. Potential target for remote execution / ransomware."),
    554: ("RTSP", "HIGH", "Real-time streaming protocol. Often used by IP cameras without authentication."),
    3306: ("MySQL", "HIGH", "Database port exposed to local network."),
    3389: ("RDP", "HIGH", "Windows Remote Desktop exposed."),
    5000: ("UPnP/Media", "LOW", "UPnP or network media server."),
    5357: ("WSDAPI", "LOW", "Windows Web Services on Devices (WSDAPI)."),
    5432: ("PostgreSQL", "HIGH", "Database port exposed to local network."),
    5900: ("VNC", "HIGH", "Virtual Network Computing (Remote Desktop). Often weak or no auth."),
    6379: ("Redis", "CRITICAL", "In-memory database. Frequently deployed without passwords!"),
    8008: ("Google Cast", "LOW", "Chromecast / Google Assistant device."),
    8080: ("HTTP-Alt", "MEDIUM", "Alternate HTTP web portal."),
    8443: ("HTTPS-Alt", "LOW", "Alternate HTTPS web portal."),
    9100: ("JetDirect", "MEDIUM", "Raw network printer port."),
    27017: ("MongoDB", "CRITICAL", "NoSQL database. Frequently unauthenticated.")
}


class PortScanner:
    """Probes hosts for open network services and evaluates threat signatures."""

    def __init__(self, timeout: float = 0.3):
        self.timeout = timeout

    def check_port(self, ip: str, port: int) -> bool:
        """Attempts a quick TCP handshake on target IP and port."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            res = s.connect_ex((ip, port))
            s.close()
            return res == 0
        except Exception:
            return False

    def probe_service_banner(self, ip: str, port: int, timeout: float = 0.4) -> Optional[str]:
        """
        Generic, protocol-agnostic banner extractor.
        1. Listens for spontaneous server greetings on connect (SSH, FTP, SMTP, Telnet).
        2. If silent, issues an HTTP probe and extracts Server header and HTML title.
        Zero hardcoded port numbers.
        """
        # 1. Spontaneous server greeting on TCP connect
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                greeting = s.recv(512)
                if greeting:
                    text = greeting.decode("utf-8", errors="ignore").strip()
                    lines = [l.strip() for l in text.splitlines() if l.strip()]
                    if lines:
                        clean = "".join(c for c in lines[0] if 32 <= ord(c) < 127).strip()
                        if clean and len(clean) >= 4:
                            return clean
        except Exception:
            pass

        # 2. Generic HTTP probe
        try:
            url = f"http://{ip}:{port}/"
            req = urllib.request.Request(url, headers={"User-Agent": "AlienHunter/1.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                server = resp.headers.get("Server", "").strip()
                body = resp.read(2048).decode("utf-8", errors="ignore")
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else ""

                parts = []
                if server:
                    parts.append(f"Server: {server}")
                if title:
                    parts.append(f"Title: '{title}'")
                if parts:
                    return "; ".join(parts)
        except Exception:
            pass

        return None

    def scan_host(self, ip: str, deep_scan: bool = False) -> Tuple[List[str], List[str], List[str]]:
        """
        Scans a host for open ports and evaluates potential vulnerabilities.
        Returns (open_ports, threats, service_notes).
        """
        open_ports: List[str] = []
        threats: List[str] = []
        notes: List[str] = []

        ports_to_test = (
            SECURITY_PORT_SIGNATURES.keys()
            if deep_scan
            else [21, 22, 23, 80, 135, 443, 445, 3389, 5357, 5900, 6379, 8080]
        )

        for port in ports_to_test:
            if self.check_port(ip, port):
                service, severity, description = SECURITY_PORT_SIGNATURES.get(
                    port, (f"Port-{port}", "INFO", "")
                )
                open_ports.append(f"{port}/{service}")

                if severity in ("CRITICAL", "HIGH"):
                    threats.append(f"[{severity}] Port {port} ({service}): {description}")

                # Capture service banner on open port
                banner = self.probe_service_banner(ip, port)
                if banner:
                    notes.append(f"Banner ({port}/{service}): {banner}")

        return open_ports, threats, notes
