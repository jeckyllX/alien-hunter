"""
Port Scanner and Security Vulnerability Inspector.
Probes target hosts for open ports, exposed databases, unencrypted protocols,
and unauthenticated web management portals.
Supports flexible port ranges, multi-tier scanning, banner grabbing, and TLS certificate inspection.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import os
import re
import socket
import ssl
import tempfile
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union


@dataclass(frozen=True)
class PortServiceDefinition:
    """Declarative definition of a known network port service and security rating."""
    port: int
    service: str
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str = ""
    is_tls: bool = False
    in_fast_tier: bool = False


# Declarative catalog of known security-relevant services
PORT_SERVICE_CATALOG: Tuple[PortServiceDefinition, ...] = (
    # Core Remote Access & File Transfer
    PortServiceDefinition(21, "FTP", "HIGH", "Unencrypted file transfer protocol. Credentials sent in plaintext.", in_fast_tier=True),
    PortServiceDefinition(22, "SSH", "LOW", "Secure shell service.", in_fast_tier=True),
    PortServiceDefinition(23, "Telnet", "CRITICAL", "Unencrypted legacy remote shell. Vulnerable to interception/tampering.", in_fast_tier=True),
    PortServiceDefinition(25, "SMTP", "MEDIUM", "Simple Mail Transfer Protocol."),
    PortServiceDefinition(53, "DNS", "LOW", "Domain Name System.", in_fast_tier=True),
    PortServiceDefinition(80, "HTTP", "MEDIUM", "Unencrypted web management portal.", in_fast_tier=True),
    PortServiceDefinition(81, "HTTP-Alt", "MEDIUM", "Alternate HTTP web portal."),
    PortServiceDefinition(88, "Kerberos", "LOW", "Kerberos authentication agent."),
    PortServiceDefinition(110, "POP3", "HIGH", "Unencrypted POP3 email retrieval."),
    PortServiceDefinition(111, "RPCBind", "MEDIUM", "Open ONC RPC portmapper."),
    PortServiceDefinition(135, "MSRPC", "MEDIUM", "Microsoft Windows RPC endpoint mapper.", in_fast_tier=True),
    PortServiceDefinition(139, "NetBIOS-SSN", "MEDIUM", "Legacy Windows NetBIOS/SMB file sharing.", in_fast_tier=True),
    PortServiceDefinition(143, "IMAP", "HIGH", "Unencrypted IMAP email access."),
    PortServiceDefinition(161, "SNMP", "HIGH", "Simple Network Management Protocol. Check for default community strings."),
    PortServiceDefinition(389, "LDAP", "MEDIUM", "Lightweight Directory Access Protocol."),
    PortServiceDefinition(443, "HTTPS", "LOW", "Encrypted web management portal.", is_tls=True, in_fast_tier=True),
    PortServiceDefinition(445, "SMB", "HIGH", "Direct SMB file sharing. Potential target for remote execution / ransomware.", in_fast_tier=True),
    PortServiceDefinition(465, "SMTPS", "LOW", "SMTP over TLS.", is_tls=True),
    PortServiceDefinition(514, "Syslog", "MEDIUM", "Syslog remote logging service."),
    PortServiceDefinition(515, "LPD", "LOW", "Line Printer Daemon service."),
    PortServiceDefinition(554, "RTSP", "HIGH", "Real-time streaming protocol. Often used by IP cameras without authentication."),
    PortServiceDefinition(587, "Submission", "LOW", "Mail submission port over TLS."),
    PortServiceDefinition(631, "CUPS", "LOW", "Common Unix Printing System."),
    PortServiceDefinition(636, "LDAPS", "LOW", "Secure LDAP over TLS.", is_tls=True),
    PortServiceDefinition(873, "rsync", "HIGH", "rsync file synchronization daemon. Verify authentication."),
    PortServiceDefinition(902, "VMware-ESXi", "LOW", "VMware ESXi management server."),
    PortServiceDefinition(993, "IMAPS", "LOW", "IMAP over TLS.", is_tls=True),
    PortServiceDefinition(995, "POP3S", "LOW", "POP3 over TLS.", is_tls=True),
    PortServiceDefinition(1080, "SOCKS", "MEDIUM", "SOCKS proxy service."),
    PortServiceDefinition(1194, "OpenVPN", "LOW", "OpenVPN tunnel daemon."),
    PortServiceDefinition(1433, "MSSQL", "HIGH", "Microsoft SQL Server database exposed."),
    PortServiceDefinition(1521, "Oracle", "HIGH", "Oracle database listener exposed."),
    PortServiceDefinition(1723, "PPTP", "HIGH", "Legacy PPTP VPN tunnel. Known cryptographic weaknesses."),
    PortServiceDefinition(1883, "MQTT", "HIGH", "MQTT IoT message broker. Frequently unauthenticated!"),
    PortServiceDefinition(2049, "NFS", "HIGH", "Network File System export. Check for unauthorized exports."),
    PortServiceDefinition(2181, "ZooKeeper", "HIGH", "Apache ZooKeeper coordination service."),
    PortServiceDefinition(2222, "SSH-Alt", "LOW", "Alternate SSH remote shell port."),
    PortServiceDefinition(2375, "Docker-API", "CRITICAL", "Unencrypted, unauthenticated Docker REST API. Allows root host escape!"),
    PortServiceDefinition(2376, "Docker-TLS", "LOW", "Docker daemon over TLS.", is_tls=True),
    PortServiceDefinition(3000, "WebApp-Alt", "MEDIUM", "Common development web server or Grafana portal."),
    PortServiceDefinition(3128, "Squid-Proxy", "MEDIUM", "HTTP proxy server."),
    PortServiceDefinition(3268, "Global-Catalog", "LOW", "Active Directory Global Catalog."),
    PortServiceDefinition(3306, "MySQL", "HIGH", "Database port exposed to local network."),
    PortServiceDefinition(3389, "RDP", "HIGH", "Windows Remote Desktop exposed.", in_fast_tier=True),
    PortServiceDefinition(4369, "Erlang-EPMD", "LOW", "Erlang Port Mapper Daemon."),
    PortServiceDefinition(5000, "UPnP/Media", "LOW", "UPnP, Docker Registry, or Flask/Python application server.", in_fast_tier=True),
    PortServiceDefinition(5001, "Synology-HTTP", "LOW", "Synology DSM web portal."),
    PortServiceDefinition(5060, "SIP", "LOW", "Session Initiation Protocol for VoIP."),
    PortServiceDefinition(5222, "XMPP", "LOW", "XMPP instant messaging service."),
    PortServiceDefinition(5357, "WSDAPI", "LOW", "Windows Web Services on Devices (WSDAPI).", in_fast_tier=True),
    PortServiceDefinition(5432, "PostgreSQL", "HIGH", "Database port exposed to local network."),
    PortServiceDefinition(5672, "RabbitMQ", "MEDIUM", "AMQP message broker."),
    PortServiceDefinition(5900, "VNC", "HIGH", "Virtual Network Computing (Remote Desktop). Often weak or no auth.", in_fast_tier=True),
    PortServiceDefinition(5984, "CouchDB", "MEDIUM", "CouchDB database."),
    PortServiceDefinition(5985, "WinRM-HTTP", "MEDIUM", "Windows Remote Management over HTTP."),
    PortServiceDefinition(5986, "WinRM-HTTPS", "LOW", "Windows Remote Management over HTTPS.", is_tls=True),
    PortServiceDefinition(6000, "X11", "HIGH", "X11 Window System display server."),
    PortServiceDefinition(6379, "Redis", "CRITICAL", "In-memory database. Frequently deployed without passwords!", in_fast_tier=True),
    PortServiceDefinition(6443, "K8s-API", "HIGH", "Kubernetes secure API server.", is_tls=True),
    PortServiceDefinition(6667, "IRC", "LOW", "Internet Relay Chat daemon."),
    PortServiceDefinition(7001, "WebLogic", "HIGH", "Oracle WebLogic application server."),
    PortServiceDefinition(8000, "HTTP-Dev", "MEDIUM", "Development HTTP service."),
    PortServiceDefinition(8008, "Google Cast", "LOW", "Chromecast / Google Assistant device."),
    PortServiceDefinition(8080, "HTTP-Alt", "MEDIUM", "Alternate HTTP web portal.", in_fast_tier=True),
    PortServiceDefinition(8081, "HTTP-Alt2", "MEDIUM", "Secondary HTTP web service."),
    PortServiceDefinition(8088, "Hadoop-YARN", "HIGH", "Hadoop YARN ResourceManager portal."),
    PortServiceDefinition(8123, "HomeAssistant", "LOW", "Home Assistant smart home portal."),
    PortServiceDefinition(8443, "HTTPS-Alt", "LOW", "Alternate HTTPS web portal.", is_tls=True),
    PortServiceDefinition(9443, "HTTPS-Alt2", "LOW", "Secondary HTTPS web management portal.", is_tls=True),
    PortServiceDefinition(8888, "Jupyter/HTTP", "MEDIUM", "Jupyter notebook or alternate web application."),
    PortServiceDefinition(9000, "Portainer/Sonar", "MEDIUM", "Management dashboard port."),
    PortServiceDefinition(9042, "Cassandra", "MEDIUM", "Apache Cassandra native protocol."),
    PortServiceDefinition(9090, "Prometheus", "LOW", "Prometheus metrics dashboard."),
    PortServiceDefinition(9092, "Kafka", "MEDIUM", "Apache Kafka messaging broker."),
    PortServiceDefinition(9100, "JetDirect", "MEDIUM", "Raw network printer port."),
    PortServiceDefinition(9200, "Elasticsearch", "CRITICAL", "Elasticsearch REST API. Frequently unauthenticated!"),
    PortServiceDefinition(9300, "ES-Node", "MEDIUM", "Elasticsearch node communication port."),
    PortServiceDefinition(9418, "Git", "LOW", "Git pack transfer service."),
    PortServiceDefinition(9999, "UrBackup", "LOW", "UrBackup client port."),
    PortServiceDefinition(10000, "Webmin", "HIGH", "Webmin system administration portal."),
    PortServiceDefinition(11211, "Memcached", "CRITICAL", "Memcached cache daemon. Prone to unauthenticated dumps/DDoS amplification."),
    PortServiceDefinition(27017, "MongoDB", "CRITICAL", "NoSQL database. Frequently unauthenticated!"),
    PortServiceDefinition(50000, "SAP", "MEDIUM", "SAP management interface."),
)

# Registry index mappings for fast lookup
PORT_REGISTRY: Dict[int, PortServiceDefinition] = {p.port: p for p in PORT_SERVICE_CATALOG}

# Security threat mapping for backwards compatibility and threat reporting
SECURITY_PORT_SIGNATURES: Dict[int, Tuple[str, str, str]] = {
    p.port: (p.service, p.severity, p.description)
    for p in PORT_SERVICE_CATALOG
    if p.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
}

# Tiered port lists
FAST_PORTS: List[int] = sorted([p.port for p in PORT_SERVICE_CATALOG if p.in_fast_tier])
DEEP_PORTS: List[int] = sorted([p.port for p in PORT_SERVICE_CATALOG])


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
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((ip, port)) == 0
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
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as s:
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
            host_str = f"[{ip}]" if ":" in ip else ip
            url = f"http://{host_str}:{port}/"
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

    @staticmethod
    def _parse_decoded_cert(decoded: Dict[str, Any]) -> Optional[str]:
        """Extracts Common Name (CN) and Subject Alternative Names (SANs) from decoded cert dict."""
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
        return f"TLS Cert ({'; '.join(parts)})" if parts else None

    def probe_tls_certificate(self, ip: str, port: int, timeout: float = 0.8) -> Optional[str]:
        """
        Extracts TLS certificate Common Name (CN) and Subject Alternative Names (SANs)
        using standard library SSL primitives without external dependencies.
        """
        tmp_path = None
        try:
            pem_cert = ssl.get_server_certificate((ip, port), timeout=timeout)
            if not pem_cert:
                return None

            with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                tf.write(pem_cert)
                tf.flush()
                tmp_path = tf.name

            cert_info = getattr(ssl, "_ssl", None)
            if cert_info and hasattr(cert_info, "_test_decode_cert"):
                decoded = cert_info._test_decode_cert(tmp_path)
                return self._parse_decoded_cert(decoded)
        except Exception:
            pass
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
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
            # Check catalog or fallback to IANA service resolution
            descriptor = PORT_REGISTRY.get(port)
            if descriptor:
                service = descriptor.service
                severity = descriptor.severity
                description = descriptor.description
                is_tls = descriptor.is_tls
            else:
                try:
                    service = socket.getservbyport(port, "tcp").upper()
                    severity = "INFO"
                    description = f"Standard {service} service."
                except (OSError, socket.error):
                    service = f"Port-{port}"
                    severity = "INFO"
                    description = "Custom or unregistered TCP service."
                is_tls = "HTTPS" in service or "SSL" in service or "TLS" in service

            open_ports.append(f"{port}/{service}")

            if severity in ("CRITICAL", "HIGH"):
                threats.append(f"[{severity}] Port {port} ({service}): {description}")

            # 1. Capture service greeting / HTTP banner
            banner = self.probe_service_banner(ip, port)
            if banner:
                notes.append(f"Banner ({port}/{service}): {banner}")

            # 2. Inspect TLS certificate on encrypted or common TLS ports
            if is_tls:
                tls_info = self.probe_tls_certificate(ip, port)
                if tls_info:
                    notes.append(f"{tls_info} [{port}]")

        return open_ports, threats, notes
