"""
SQL Injection Scanner
======================
Tests web forms for basic SQL injection vulnerabilities.

How it works:
    1. Parses HTML forms on the target page.
    2. Injects common SQL injection payloads into form inputs.
    3. Checks the response for database error messages.
    4. Error messages indicate the input reached the database unsanitized.

ETHICAL NOTE: Only scan websites you own or have permission to test.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re


class SQLiScanner:
    """Tests web forms for SQL injection vulnerabilities."""

    PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        '" OR "1"="1',
        "1' ORDER BY 1--",
        "1 UNION SELECT NULL--",
        "admin'--",
        "1 OR 1=1",
    ]

    ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"postgresql.*error",
        r"sqlite3\.OperationalError",
        r"ora-\d{5}",
        r"SQLSTATE\[",
        r"syntax error at or near",
    ]

    def scan(self, url, response=None):
        vulnerabilities = []
        try:
            if response is None:
                response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            if not forms:
                return vulnerabilities
            for idx, form in enumerate(forms):
                details = self._extract_form(form, url)
                for payload in self.PAYLOADS:
                    is_vuln, err = self._test(details, payload)
                    if is_vuln:
                        vulnerabilities.append({
                            "type": "SQL Injection Vulnerability",
                            "severity": "HIGH",
                            "description": f"Form #{idx+1} (action: {details['action']}) vulnerable. Payload '{payload}' triggered: '{err}'",
                            "fix": "Use parameterized queries / prepared statements. Use an ORM. Validate all user inputs.",
                        })
                        break
        except requests.RequestException as e:
            vulnerabilities.append({
                "type": "SQLi Scan Error", "severity": "INFO",
                "description": f"Could not complete SQLi scan: {e}",
                "fix": "Verify the URL is accessible.",
            })
        return vulnerabilities

    def _extract_form(self, form, base_url):
        action = urljoin(base_url, form.get("action", ""))
        method = form.get("method", "get").lower()
        inputs = []
        for tag in form.find_all(["input", "textarea"]):
            name = tag.get("name", "")
            if name:
                inputs.append({"name": name, "type": tag.get("type", "text"), "value": tag.get("value", "")})
        return {"action": action, "method": method, "inputs": inputs}

    def _test(self, form_details, payload):
        try:
            data = {}
            for f in form_details["inputs"]:
                data[f["name"]] = payload if f["type"] in ("text","search","email","password","") else f["value"]
            if form_details["method"] == "post":
                resp = requests.post(form_details["action"], data=data, timeout=10, verify=False)
            else:
                resp = requests.get(form_details["action"], params=data, timeout=10, verify=False)
            for pattern in self.ERROR_PATTERNS:
                m = re.search(pattern, resp.text.lower(), re.IGNORECASE)
                if m:
                    return True, m.group(0)
            return False, ""
        except requests.RequestException:
            return False, ""
