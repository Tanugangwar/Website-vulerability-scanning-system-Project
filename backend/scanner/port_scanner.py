"""
Port Scanner
==============
Scans common network ports on the target host using socket connections.

How it works:
    1. Extracts the hostname from the URL.
    2. Attempts TCP connections to a list of well-known ports.
    3. Reports open ports that may expose services to attackers.
"""

import socket
from urllib.parse import urlparse


class PortScanner:
    """Scans common ports on a target host."""

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 8080: "HTTP Proxy", 8443: "HTTPS Alt",
    }

    def scan(self, url):
        vulnerabilities = []
        hostname = urlparse(url).hostname
        open_ports = []

        for port, service in self.COMMON_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    open_ports.append((port, service))
            except (socket.error, OSError):
                continue

        # Flag risky open ports
        risky = {21: "HIGH", 23: "HIGH", 25: "MEDIUM", 445: "HIGH",
                 3306: "HIGH", 3389: "HIGH", 5432: "HIGH"}
        for port, service in open_ports:
            severity = risky.get(port, "LOW")
            if port in risky:
                vulnerabilities.append({
                    "type": "Risky Open Port",
                    "severity": severity,
                    "description": f"Port {port} ({service}) is open. This service should not be publicly accessible.",
                    "fix": f"Close port {port} or restrict access using a firewall. If needed, use a VPN.",
                })
            else:
                vulnerabilities.append({
                    "type": "Open Port Detected",
                    "severity": "INFO",
                    "description": f"Port {port} ({service}) is open.",
                    "fix": "Ensure only necessary ports are open. Review firewall rules.",
                })

        return vulnerabilities
