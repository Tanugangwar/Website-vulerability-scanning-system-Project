"""
XSS (Cross-Site Scripting) Scanner
====================================
Tests for reflected XSS vulnerabilities in web forms.

How it works:
    1. Parses the HTML of the target page using BeautifulSoup.
    2. Finds all <form> elements and their <input> fields.
    3. For each form, submits a set of XSS test payloads.
    4. Checks if the payload is reflected (appears) in the response body.
    5. If reflected without encoding, it indicates a potential XSS vulnerability.

What is XSS?
    Cross-Site Scripting (XSS) is a vulnerability where an attacker can inject
    malicious scripts into web pages viewed by other users. There are three types:
    - Reflected XSS: The malicious script comes from the current HTTP request.
    - Stored XSS: The malicious script is stored on the server (e.g., in a database).
    - DOM-based XSS: The vulnerability is in client-side code rather than server-side.

    This scanner focuses on Reflected XSS — the most common and easiest to detect.

ETHICAL NOTE:
    Only scan websites you own or have explicit permission to test.
    These payloads are harmless test strings, not actual attacks.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class XSSScanner:
    """Tests web forms for reflected XSS vulnerabilities."""

    # Harmless XSS test payloads — these will not cause damage
    # but their reflection in the response indicates a vulnerability.
    PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "';alert(1);//",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
    ]

    def scan(self, url: str, response: requests.Response = None) -> list[dict]:
        """
        Scan the target URL for reflected XSS vulnerabilities.

        Args:
            url: The target URL to scan.
            response: Optional pre-fetched response object.

        Returns:
            A list of vulnerability dictionaries.
        """
        vulnerabilities = []

        try:
            if response is None:
                response = requests.get(url, timeout=10, verify=False)

            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            if not forms:
                return vulnerabilities

            for form_index, form in enumerate(forms):
                form_details = self._extract_form_details(form, url)

                # Test each payload against each form
                for payload in self.PAYLOADS:
                    result = self._test_payload(form_details, payload)
                    if result:
                        vulnerabilities.append({
                            "type": "Reflected XSS Vulnerability",
                            "severity": "HIGH",
                            "description": (
                                f"Form #{form_index + 1} (action: {form_details['action']}) "
                                f"reflects user input without sanitization. "
                                f"Payload '{payload}' was found in the response body."
                            ),
                            "fix": (
                                "Sanitize and encode all user inputs before rendering them "
                                "in HTML. Use output encoding functions appropriate for the "
                                "context (HTML, JavaScript, URL, CSS). Implement a strong "
                                "Content-Security-Policy header."
                            ),
                        })
                        # Only report once per form to avoid flooding
                        break

        except requests.RequestException as e:
            vulnerabilities.append({
                "type": "XSS Scan Error",
                "severity": "INFO",
                "description": f"Could not complete XSS scan: {str(e)}",
                "fix": "Verify the URL is accessible and try again.",
            })

        return vulnerabilities

    def _extract_form_details(self, form, base_url: str) -> dict:
        """
        Extract details from an HTML <form> element.

        Args:
            form: A BeautifulSoup <form> tag.
            base_url: The base URL for resolving relative action URLs.

        Returns:
            A dictionary with action URL, method, and list of input fields.
        """
        action = form.get("action", "")
        method = form.get("method", "get").lower()

        # Resolve relative URLs
        action_url = urljoin(base_url, action)

        # Collect all input fields
        inputs = []
        for input_tag in form.find_all(["input", "textarea", "select"]):
            input_name = input_tag.get("name", "")
            input_type = input_tag.get("type", "text")
            input_value = input_tag.get("value", "")
            if input_name:
                inputs.append({
                    "name": input_name,
                    "type": input_type,
                    "value": input_value,
                })

        return {
            "action": action_url,
            "method": method,
            "inputs": inputs,
        }

    def _test_payload(self, form_details: dict, payload: str) -> bool:
        """
        Submit a form with an XSS payload and check if it's reflected.

        Args:
            form_details: Dictionary with form action, method, and inputs.
            payload: The XSS test payload string.

        Returns:
            True if the payload is reflected in the response, False otherwise.
        """
        try:
            # Build form data with the payload injected into each field
            data = {}
            for input_field in form_details["inputs"]:
                if input_field["type"] in ("text", "search", "email", "url", "tel", ""):
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = input_field["value"]

            # Submit the form
            if form_details["method"] == "post":
                resp = requests.post(
                    form_details["action"],
                    data=data,
                    timeout=10,
                    verify=False,
                )
            else:
                resp = requests.get(
                    form_details["action"],
                    params=data,
                    timeout=10,
                    verify=False,
                )

            # Check if the payload is reflected in the response
            return payload in resp.text

        except requests.RequestException:
            return False
