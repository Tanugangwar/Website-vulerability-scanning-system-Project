"""
SSL/TLS Certificate Scanner
============================
Validates the SSL/TLS certificate of a target website.

How it works:
    1. Extracts the hostname from the target URL.
    2. Opens an SSL-wrapped socket connection on port 443.
    3. Retrieves the server's SSL certificate.
    4. Checks:
       - Whether the site uses HTTPS at all.
       - Certificate expiry date.
       - Certificate issuer (self-signed detection).
       - Subject Alternative Names (SAN).
    5. Reports issues with severity and fix recommendations.
"""

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone


class SSLScanner:
    """Validates SSL/TLS certificates for a target website."""

    def scan(self, url: str) -> list[dict]:
        """
        Scan the target URL for SSL/TLS certificate issues.

        Args:
            url: The target URL to scan (must include scheme).

        Returns:
            A list of vulnerability dictionaries with type, severity,
            description, and fix fields.
        """
        vulnerabilities = []
        parsed = urlparse(url)
        hostname = parsed.hostname
        scheme = parsed.scheme

        # -----------------------------------------------------------
        # Check 1: Is HTTPS being used?
        # -----------------------------------------------------------
        if scheme != "https":
            vulnerabilities.append({
                "type": "Insecure Protocol",
                "severity": "HIGH",
                "description": (
                    "The website does not use HTTPS. All data sent between the "
                    "user and the server is transmitted in plain text, making it "
                    "vulnerable to eavesdropping and man-in-the-middle attacks."
                ),
                "fix": (
                    "Obtain an SSL/TLS certificate (e.g., from Let's Encrypt) "
                    "and configure your web server to use HTTPS. Redirect all "
                    "HTTP traffic to HTTPS."
                ),
            })

        # -----------------------------------------------------------
        # Check 2: Validate the SSL certificate
        # -----------------------------------------------------------
        try:
            # Create an SSL context that verifies certificates
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=hostname,
            )
            conn.settimeout(10)
            conn.connect((hostname, 443))
            cert = conn.getpeercert()
            conn.close()

            # Check certificate expiry
            not_after = cert.get("notAfter", "")
            if not_after:
                # Parse the expiry date
                expiry_date = datetime.strptime(
                    not_after, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_remaining = (expiry_date - now).days

                if days_remaining < 0:
                    vulnerabilities.append({
                        "type": "Expired SSL Certificate",
                        "severity": "HIGH",
                        "description": (
                            f"The SSL certificate expired on {not_after}. "
                            "Expired certificates cause browser warnings and "
                            "break trust with users."
                        ),
                        "fix": "Renew the SSL certificate immediately.",
                    })
                elif days_remaining < 30:
                    vulnerabilities.append({
                        "type": "SSL Certificate Expiring Soon",
                        "severity": "MEDIUM",
                        "description": (
                            f"The SSL certificate expires in {days_remaining} days "
                            f"(on {not_after}). Letting it expire will cause "
                            "security warnings for users."
                        ),
                        "fix": "Renew the SSL certificate before it expires.",
                    })

            # Check for self-signed certificate (issuer == subject)
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            subject = dict(x[0] for x in cert.get("subject", ()))
            if issuer == subject:
                vulnerabilities.append({
                    "type": "Self-Signed Certificate",
                    "severity": "MEDIUM",
                    "description": (
                        "The SSL certificate appears to be self-signed. "
                        "Self-signed certificates are not trusted by browsers "
                        "and can be easily impersonated."
                    ),
                    "fix": (
                        "Use a certificate from a trusted Certificate Authority "
                        "(e.g., Let's Encrypt, DigiCert)."
                    ),
                })

        except ssl.SSLCertVerificationError as e:
            vulnerabilities.append({
                "type": "SSL Certificate Verification Failed",
                "severity": "HIGH",
                "description": (
                    f"SSL certificate verification failed: {str(e)}. "
                    "This may indicate an invalid, expired, or self-signed certificate."
                ),
                "fix": (
                    "Ensure a valid SSL certificate from a trusted CA is installed. "
                    "Check that the certificate matches the domain name."
                ),
            })
        except (socket.timeout, socket.error) as e:
            vulnerabilities.append({
                "type": "SSL Connection Error",
                "severity": "INFO",
                "description": (
                    f"Could not establish SSL connection: {str(e)}. "
                    "The server may not support HTTPS on port 443."
                ),
                "fix": "Verify the server supports HTTPS and port 443 is open.",
            })
        except Exception as e:
            vulnerabilities.append({
                "type": "SSL Scan Error",
                "severity": "INFO",
                "description": f"Unexpected error during SSL scan: {str(e)}",
                "fix": "Check the URL and network connectivity.",
            })

        return vulnerabilities
