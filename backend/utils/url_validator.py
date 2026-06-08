"""
URL Validator
==============
Validates and normalizes user-supplied URLs before scanning.

Checks:
    - URL is not empty
    - Has a valid scheme (http or https)
    - Has a valid hostname
    - Is a properly formed URL
"""

from urllib.parse import urlparse
import re


def validate_url(url: str) -> tuple[bool, str, str]:
    """
    Validate and normalize a URL.

    Args:
        url: The raw URL string from user input.

    Returns:
        A tuple of (is_valid, normalized_url, error_message).
        If valid, error_message is empty.
    """
    if not url or not url.strip():
        return False, "", "URL cannot be empty."

    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "", "Could not parse the URL."

    # Must have a scheme
    if parsed.scheme not in ("http", "https"):
        return False, "", "URL must use http or https protocol."

    # Must have a hostname
    if not parsed.hostname:
        return False, "", "URL must include a valid hostname."

    # Basic hostname format check
    hostname = parsed.hostname
    hostname_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    )
    # Allow IP addresses too
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if not hostname_pattern.match(hostname) and not ip_pattern.match(hostname):
        if hostname != "localhost":
            return False, "", f"Invalid hostname: '{hostname}'."

    return True, url, ""
