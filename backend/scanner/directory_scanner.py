"""
Directory Scanner
==================
Checks for common exposed directories and files on the target server.

How it works:
    1. Appends common directory paths to the base URL.
    2. Sends HTTP HEAD requests to each path.
    3. If the server responds with 200 OK, the directory/file exists.
    4. Exposed admin panels, backups, or config files are flagged.
"""

import requests
from urllib.parse import urljoin


class DirectoryScanner:
    """Brute-forces common directory and file paths."""

    COMMON_PATHS = [
        "/admin", "/admin/login", "/administrator",
        "/login", "/wp-admin", "/wp-login.php",
        "/phpmyadmin", "/cpanel", "/webmail",
        "/.env", "/config.php", "/config.yml",
        "/backup", "/backup.zip", "/db.sql",
        "/robots.txt", "/sitemap.xml", "/.git",
        "/.git/HEAD", "/server-status", "/server-info",
        "/.htaccess", "/web.config", "/crossdomain.xml",
    ]

    def scan(self, url):
        vulnerabilities = []
        sensitive = {
            "/.env": "HIGH", "/config.php": "HIGH", "/config.yml": "HIGH",
            "/db.sql": "HIGH", "/backup.zip": "HIGH", "/.git": "HIGH",
            "/.git/HEAD": "HIGH", "/.htaccess": "MEDIUM",
            "/phpmyadmin": "HIGH", "/server-status": "MEDIUM",
            "/server-info": "MEDIUM", "/web.config": "MEDIUM",
        }

        for path in self.COMMON_PATHS:
            try:
                test_url = urljoin(url, path)
                resp = requests.head(test_url, timeout=5, verify=False, allow_redirects=False)
                if resp.status_code == 200:
                    severity = sensitive.get(path, "LOW")
                    vulnerabilities.append({
                        "type": "Exposed Path",
                        "severity": severity,
                        "description": f"Path '{path}' is publicly accessible (HTTP 200). This may expose sensitive data or admin interfaces.",
                        "fix": f"Restrict access to '{path}' using authentication, firewall rules, or server configuration. Remove unnecessary files.",
                    })
            except requests.RequestException:
                continue

        return vulnerabilities
