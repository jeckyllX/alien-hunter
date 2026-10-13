"""
Port Scanner and Security Vulnerability Inspector.
Probes target hosts for open ports, exposed databases, unencrypted protocols,
and unauthenticated web management portals.
Supports flexible port ranges, multi-tier scanning, banner grabbing, and TLS certificate inspection.
"""

from concurrent.futures import ThreadPoolExecutor
import re
import socket
import ssl
import tempfile
import urllib.request
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union


SECURITY_PORT_SIGNATURES: Dict[int, Tuple[str, str, str]] = {
    21: ("FTP", "HIGH", "Unencrypted file transfer protocol. Credentials sent in plaintext."),
    22: ("SSH", "LOW", "Secure shell service."),
    23: ("Telnet", "CRITICAL", "Unencrypted legacy remote shell. Vulnerable to interception/tampering."),
    25: ("SMTP", "MEDIUM", "Simple Mail Transfer Protocol."),
    53: ("DNS", "LOW", "Domain Name System."),
    80: ("HTTP", "MEDIUM", "Unencrypted web management portal."),
    88: ("Kerberos", "LOW", "Kerberos authentication agent."),
    110: ("POP3", "HIGH", "Unencrypted POP3 email retrieval."),
    111: ("RPCBind", "MEDIUM", "Open ONC RPC portmapper."),
    135: ("MSRPC", "MEDIUM", "Microsoft Windows RPC endpoint mapper."),
    139: ("NetBIOS-SSN", "MEDIUM", "Legacy Windows NetBIOS/SMB file sharing."),
    143: ("IMAP", "HIGH", "Unencrypted IMAP email access."),
    161: ("SNMP", "HIGH", "Simple Network Management Protocol. Check for default community strings."),
    389: ("LDAP", "MEDIUM", "Lightweight Directory Access Protocol."),
    443: ("HTTPS", "LOW", "Encrypted web management portal."),
    445: ("SMB", "HIGH", "Direct SMB file sharing. Potential target for remote execution / ransomware."),
    554: ("RTSP", "HIGH", "Real-time streaming protocol. Often used by IP cameras without authentication."),
    636: ("LDAPS", "LOW", "Secure LDAP over TLS."),
    873: ("rsync", "HIGH", "rsync file synchronization daemon. Verify authentication."),
    1433: ("MSSQL", "HIGH", "Microsoft SQL Server database exposed."),
    1521: ("Oracle", "HIGH", "Oracle database listener exposed."),
    1883: ("MQTT", "HIGH", "MQTT IoT message broker. Frequently unauthenticated!"),
    2049: ("NFS", "HIGH", "Network File System export. Check for unauthorized exports."),
    2181: ("ZooKeeper", "HIGH", "Apache ZooKeeper coordination service."),
    2222: ("SSH-Alt", "LOW", "Alternate SSH remote shell port."),
    2375: ("Docker-API", "CRITICAL", "Unencrypted, unauthenticated Docker REST API. Allows root host escape!"),
    2376: ("Docker-TLS", "LOW", "Docker daemon over TLS."),
    3000: ("WebApp-Alt", "MEDIUM", "Common development web server or Grafana portal."),
    3128: ("Squid-Proxy", "MEDIUM", "HTTP proxy server."),
    3306: ("MySQL", "HIGH", "Database port exposed to local network."),
    3389: ("RDP", "HIGH", "Windows Remote Desktop exposed."),
    5000: ("UPnP/Media", "LOW", "UPnP, Docker Registry, or Flask/Python application server."),
    5357: ("WSDAPI", "LOW", "Windows Web Services on Devices (WSDAPI)."),
    5432: ("PostgreSQL", "HIGH", "Database port exposed to local network."),
    5672: ("RabbitMQ", "MEDIUM", "AMQP message broker."),
    5900: ("VNC", "HIGH", "Virtual Network Computing (Remote Desktop). Often weak or no auth."),
    6379: ("Redis", "CRITICAL", "In-memory database. Frequently deployed without passwords!"),
    6443: ("K8s-API", "HIGH", "Kubernetes secure API server."),
    8000: ("HTTP-Dev", "MEDIUM", "Development HTTP service."),
    8008: ("Google Cast", "LOW", "Chromecast / Google Assistant device."),
    8080: ("HTTP-Alt", "MEDIUM", "Alternate HTTP web portal."),
    8081: ("HTTP-Alt2", "MEDIUM", "Secondary HTTP web service."),
    8123: ("HomeAssistant", "LOW", "Home Assistant smart home portal."),
    8443: ("HTTPS-Alt", "LOW", "Alternate HTTPS web portal."),
    8888: ("Jupyter/HTTP", "MEDIUM", "Jupyter notebook or alternate web application."),
    9000: ("Portainer/Sonar", "MEDIUM", "Management dashboard port."),
    9092: ("Kafka", "MEDIUM", "Apache Kafka messaging broker."),
    9100: ("JetDirect", "MEDIUM", "Raw network printer port."),
    9200: ("Elasticsearch", "CRITICAL", "Elasticsearch REST API. Frequently unauthenticated!"),
    10000: ("Webmin", "HIGH", "Webmin system administration portal."),
    11211: ("Memcached", "CRITICAL", "Memcached cache daemon. Prone to unauthenticated dumps/DDoS amplification."),
    27017: ("MongoDB", "CRITICAL", "NoSQL database. Frequently unauthenticated!"),
}

FAST_PORTS: List[int] = [
    21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 5000, 5357, 5900, 6379, 8080
]

DEEP_PORTS: List[int] = sorted(list(set(FAST_PORTS) | set(SECURITY_PORT_SIGNATURES.keys()) | {
    25, 81, 88, 110, 111, 143, 161, 389, 465, 514, 515, 587, 631, 636, 873, 902, 993, 995,
    1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2181, 2222, 2375, 2376, 3000, 3128,
    3268, 3306, 4369, 5001, 5060, 5222, 5432, 5672, 5984, 5985, 5986, 6000, 6443, 6667, 7001,
    8000, 8008, 8081, 8088, 8123, 8443, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418,
    9999, 10000, 11211, 27017, 50000
}))


def parse_port_specs(specs: Union[str, Iterable[int], Iterable[str]]) -> List[int]:
    """
    Parses flexible port specifications into a sorted, deduplicated list of valid port numbers.
    Supports formats like:
      - "80"
      - "80,443,8080"
      - "1-1024"
      - "22,80,8000-8080,9000"
      - [80, 443, 8080]
      - ["80", "443-445"]
    """
    if isinstance(specs, (list, tuple, set)):
        raw_str = ",".join(str(s) for s in specs)
    else:
        raw_str = str(specs)

    parsed_ports: Set[int] = set()
    tokens = [t.strip() for t in raw_str.split(",") if t.strip()]

    for token in tokens:
        if "-" in token:
            parts = token.split("-", 1)
            try:
                start_p = int(parts[0].strip())
                end_p = int(parts[1].strip())
                if 1 <= start_p <= 65535 and 1 <= end_p <= 65535:
                    low = min(start_p, end_p)
                    high = max(start_p, end_p)
                    parsed_ports.update(range(low, high + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    parsed_ports.add(p)
            except ValueError:
                continue

    return sorted(list(parsed_ports))


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

    def probe_tls_certificate(self, ip: str, port: int, timeout: float = 0.8) -> Optional[str]:
        """
        Extracts TLS certificate Common Name (CN) and Subject Alternative Names (SANs)
        using standard library SSL primitives without external dependencies.
        """
        try:
            pem_cert = ssl.get_server_certificate((ip, port), timeout=timeout)
            if not pem_cert:
                return None

            with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                tf.write(pem_cert)
                tf.flush()
                tmp_path = tf.name

            try:
                # Use standard library decode cert
                cert_info = getattr(ssl, "_ssl", None)
                if cert_info and hasattr(cert_info, "_test_decode_cert"):
                    decoded = cert_info._test_decode_cert(tmp_path)
                    subject = decoded.get("subject", ())
                    cn = ""
                    for rdn in subject:
                        for key, val in rdn:
                            if key == "commonName":
                                cn = val
                                break
                    sans = [entry[1] for entry in decoded.get("subjectAltName", ()) if len(entry) >= 2]
                    parts = []
                    if cn:
                        parts.append(f"CN: {cn}")
                    if sans:
                        sans_preview = ", ".join(sans[:3])
                        parts.append(f"SANs: {sans_preview}")
                    if parts:
                        return f"TLS Cert ({'; '.join(parts)})"
            finally:
                import os
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        except Exception:
            pass

        return None

    def scan_host(
        self,
        ip: str,
        deep_scan: bool = False,
        ports: Optional[Iterable[int]] = None,
        max_workers: int = 24,
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        Scans a host for open ports and evaluates potential vulnerabilities.
        Supports custom ports, deep scan lists, or default fast scan lists.
        Executes probes concurrently using thread pooling for low latency.
        Returns (open_ports, threats, service_notes).
        """
        open_ports: List[str] = []
        threats: List[str] = []
        notes: List[str] = []

        if ports is not None:
            ports_to_test = sorted(list(set(ports)))
        elif deep_scan:
            ports_to_test = DEEP_PORTS
        else:
            ports_to_test = FAST_PORTS

        if not ports_to_test:
            return open_ports, threats, notes

        # Concurrent port availability check
        discovered_open: List[int] = []
        workers = min(max_workers, len(ports_to_test))
        if workers > 1:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                results = executor.map(lambda p: (p, self.check_port(ip, p)), ports_to_test)
                for port, is_open in results:
                    if is_open:
                        discovered_open.append(port)
        else:
            for port in ports_to_test:
                if self.check_port(ip, port):
                    discovered_open.append(port)

        discovered_open.sort()

        for port in discovered_open:
            # Check signatures or fallback to IANA service resolution
            if port in SECURITY_PORT_SIGNATURES:
                service, severity, description = SECURITY_PORT_SIGNATURES[port]
            else:
                try:
                    service = socket.getservbyport(port, "tcp").upper()
                    severity = "INFO"
                    description = f"Standard {service} service."
                except (OSError, socket.error):
                    service = f"Port-{port}"
                    severity = "INFO"
                    description = "Custom or unregistered TCP service."

            open_ports.append(f"{port}/{service}")

            if severity in ("CRITICAL", "HIGH"):
                threats.append(f"[{severity}] Port {port} ({service}): {description}")

            # 1. Capture service banner
            banner = self.probe_service_banner(ip, port)
            if banner:
                notes.append(f"Banner ({port}/{service}): {banner}")

            # 2. Inspect TLS certificate on encrypted or common TLS ports
            if port in (443, 8443, 6443, 2376, 9443, 993, 995, 465) or "HTTPS" in service:
                tls_info = self.probe_tls_certificate(ip, port)
                if tls_info:
                    notes.append(f"{tls_info} [{port}]")

        return open_ports, threats, notes
