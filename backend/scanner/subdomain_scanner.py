"""
Subdomain Scanner
==================
Discovers subdomains of the target domain using a wordlist.

How it works:
    1. Extracts the base domain from the URL.
    2. Prepends common subdomain prefixes (www, mail, admin, etc.).
    3. Attempts DNS resolution for each subdomain.
    4. Reports found subdomains — useful for discovering attack surface.
"""

import socket
from urllib.parse import urlparse


class SubdomainScanner:
    """Discovers subdomains via DNS resolution."""

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "blog", "dev",
        "staging", "test", "api", "app", "portal",
        "vpn", "remote", "webmail", "ns1", "ns2",
        "cdn", "static", "media", "docs", "support",
        "shop", "store", "m", "mobile",
    ]

    def scan(self, url):
        vulnerabilities = []
        domain = urlparse(url).hostname
        # Remove 'www.' prefix if present
        if domain and domain.startswith("www."):
            domain = domain[4:]

        found = []
        for sub in self.COMMON_SUBDOMAINS:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
            except socket.gaierror:
                continue

        if found:
            vulnerabilities.append({
                "type": "Subdomains Discovered",
                "severity": "INFO",
                "description": f"Found {len(found)} subdomains: {', '.join(found)}. Each subdomain increases the attack surface.",
                "fix": "Audit all subdomains. Ensure unused subdomains are removed and all active ones are secured.",
            })

        return vulnerabilities
