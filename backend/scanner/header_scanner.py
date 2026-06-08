"""
HTTP Security Header Scanner
=============================
Analyzes HTTP response headers for missing or misconfigured security headers.

How it works:
    1. Sends an HTTP GET request to the target URL.
    2. Reads all response headers.
    3. Compares them against a list of recommended security headers.
    4. Reports missing or weak headers with severity and fix recommendations.

Security headers checked:
    - Content-Security-Policy (CSP): Prevents XSS, data injection attacks.
    - X-Frame-Options: Prevents clickjacking by controlling iframe embedding.
    - X-XSS-Protection: Legacy browser XSS filter toggle.
    - X-Content-Type-Options: Prevents MIME-type sniffing.
    - Strict-Transport-Security (HSTS): Forces HTTPS connections.
    - Referrer-Policy: Controls referrer information in requests.
    - Permissions-Policy: Controls browser feature access.
"""

import requests


class HeaderScanner:
    """Scans a website's HTTP response for missing security headers."""

    # Each entry: header_name -> (severity, description, recommended_fix)
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": "HIGH",
            "description": (
                "Content-Security-Policy (CSP) header is missing. "
                "CSP helps prevent Cross-Site Scripting (XSS) and data injection "
                "attacks by specifying which content sources are allowed."
            ),
            "fix": (
                "Add a Content-Security-Policy header. Example: "
                "Content-Security-Policy: default-src 'self'; script-src 'self'"
            ),
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": (
                "X-Frame-Options header is missing. Without it, the site can be "
                "embedded in an iframe on a malicious page, enabling clickjacking attacks."
            ),
            "fix": (
                "Add X-Frame-Options header with value DENY or SAMEORIGIN. "
                "Example: X-Frame-Options: DENY"
            ),
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "description": (
                "X-XSS-Protection header is missing. While modern browsers have "
                "built-in XSS filters, this header provides an extra layer for older browsers."
            ),
            "fix": "Add X-XSS-Protection: 1; mode=block",
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "description": (
                "X-Content-Type-Options header is missing. Without 'nosniff', browsers "
                "may MIME-sniff responses, potentially executing malicious content."
            ),
            "fix": "Add X-Content-Type-Options: nosniff",
        },
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "description": (
                "HTTP Strict Transport Security (HSTS) header is missing. HSTS ensures "
                "browsers always connect via HTTPS, preventing downgrade attacks."
            ),
            "fix": (
                "Add Strict-Transport-Security header. Example: "
                "Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": (
                "Referrer-Policy header is missing. This header controls how much "
                "referrer information is sent with requests, protecting user privacy."
            ),
            "fix": "Add Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": (
                "Permissions-Policy header is missing. This header controls which "
                "browser features (camera, microphone, geolocation) the page can use."
            ),
            "fix": (
                "Add Permissions-Policy header. Example: "
                "Permissions-Policy: camera=(), microphone=(), geolocation=()"
            ),
        },
    }

    def scan(self, url: str, response: requests.Response = None) -> list[dict]:
        """
        Scan the target URL for missing security headers.

        Args:
            url: The target URL to scan.
            response: Optional pre-fetched response object. If not provided,
                      a new request is made.

        Returns:
            A list of vulnerability dictionaries, each containing:
                - type: "Missing Security Header"
                - header: The missing header name
                - severity: HIGH / MEDIUM / LOW
                - description: What the issue is
                - fix: How to fix it
        """
        vulnerabilities = []

        try:
            if response is None:
                response = requests.get(url, timeout=10, verify=False)

            headers = response.headers

            for header_name, details in self.SECURITY_HEADERS.items():
                if header_name not in headers:
                    vulnerabilities.append({
                        "type": "Missing Security Header",
                        "header": header_name,
                        "severity": details["severity"],
                        "description": details["description"],
                        "fix": details["fix"],
                    })

            # Check for information disclosure headers
            server = headers.get("Server", "")
            if server:
                vulnerabilities.append({
                    "type": "Information Disclosure",
                    "header": "Server",
                    "severity": "LOW",
                    "description": (
                        f"Server header exposes server software: '{server}'. "
                        "Attackers can use this to find known vulnerabilities."
                    ),
                    "fix": "Remove or obfuscate the Server header in your web server configuration.",
                })

            x_powered_by = headers.get("X-Powered-By", "")
            if x_powered_by:
                vulnerabilities.append({
                    "type": "Information Disclosure",
                    "header": "X-Powered-By",
                    "severity": "LOW",
                    "description": (
                        f"X-Powered-By header exposes technology stack: '{x_powered_by}'. "
                        "This helps attackers fingerprint the application."
                    ),
                    "fix": "Remove the X-Powered-By header from server responses.",
                })

        except requests.RequestException as e:
            vulnerabilities.append({
                "type": "Connection Error",
                "header": "N/A",
                "severity": "INFO",
                "description": f"Could not connect to scan headers: {str(e)}",
                "fix": "Verify the URL is accessible and try again.",
            })

        return vulnerabilities
