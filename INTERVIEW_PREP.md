# 🎤 Interview Preparation — Website Vulnerability Scanner

## 📝 Project Explanation (Simple Terms)

> "I built a web-based tool that checks websites for security problems. You enter a URL, the system connects to that website, analyzes its configuration and code, and generates a report telling you what's wrong and how to fix it. Think of it like a health checkup — but for websites."

### How does it work step by step?

1. **User enters a URL** in the web interface.
2. **Frontend sends the URL** to the Flask backend via a REST API call.
3. **Backend validates the URL** and passes it to the Vulnerability Analyzer.
4. **The Analyzer runs multiple scanners** — each one checks for a specific type of vulnerability.
5. **Results are aggregated**, scored (0–100), and graded (A–F).
6. **Results are saved** to a SQLite database and returned as JSON.
7. **Frontend renders** the results as cards sorted by severity.
8. **User can download** a PDF report.

---

## ❓ Common Viva Questions & Answers

### Q1: What is XSS (Cross-Site Scripting)?

**Answer:** XSS is a vulnerability where an attacker injects malicious JavaScript code into a web page that other users view. There are three types:
- **Reflected XSS:** The malicious script comes from the URL or form input and is immediately reflected in the response.
- **Stored XSS:** The script is saved in the database and shown to all users who view that page.
- **DOM-based XSS:** The vulnerability exists in client-side JavaScript code.

**Example:** If a search page shows "Results for: [your input]" without sanitization, an attacker can input `<script>alert('hacked')</script>` and the browser will execute it.

**Prevention:** Sanitize and encode all user input. Use Content-Security-Policy headers. Use frameworks that auto-escape output (React, Angular).

---

### Q2: What is SQL Injection?

**Answer:** SQL Injection is an attack where malicious SQL code is inserted through user input fields to manipulate database queries.

**Example:** A login form with the query:
```sql
SELECT * FROM users WHERE username = '{input}' AND password = '{input}'
```
If the attacker enters `' OR '1'='1` as the username, the query becomes:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''
```
This always returns true, bypassing authentication.

**Prevention:** Use parameterized queries (prepared statements), ORMs, input validation, and least-privilege database accounts.

---

### Q3: How does your scanner detect XSS?

**Answer:** My scanner:
1. Parses the HTML page and finds all `<form>` elements.
2. Extracts form action URLs, methods, and input fields.
3. Fills each text input with XSS payloads like `<script>alert(1)</script>`.
4. Submits the form and checks if the payload appears unchanged in the response.
5. If the payload is reflected without encoding, the form is vulnerable to Reflected XSS.

---

### Q4: How does your scanner detect SQL Injection?

**Answer:** My scanner:
1. Finds forms on the page.
2. Injects SQL payloads like `' OR '1'='1` into form inputs.
3. Submits the form and checks the response for database error messages.
4. Error messages like "SQL syntax error" or "unclosed quotation mark" indicate that the input reached the database without sanitization.

---

### Q5: What are HTTP security headers and why do they matter?

**Answer:**
- **Content-Security-Policy (CSP):** Tells the browser which sources of content are allowed, preventing XSS.
- **X-Frame-Options:** Prevents the page from being embedded in iframes, stopping clickjacking attacks.
- **Strict-Transport-Security (HSTS):** Forces browsers to always use HTTPS.
- **X-Content-Type-Options:** Prevents MIME-type sniffing, which could execute malicious files.

These headers add defense-in-depth — even if application code has bugs, headers provide an extra security layer.

---

### Q6: What is SSL/TLS and why check the certificate?

**Answer:** SSL/TLS encrypts data between the browser and server, preventing eavesdropping. My scanner checks:
- **Is HTTPS used?** HTTP transmits data in plain text.
- **Is the certificate valid?** Expired or self-signed certs break trust.
- **When does it expire?** Advance warning prevents outages.

---

### Q7: What is the architecture of your system?

**Answer:** I use a modular MVC-like architecture:
- **Frontend (View):** HTML/CSS/JS — handles UI and user interaction.
- **Flask Routes (Controller):** Receives API requests and returns JSON responses.
- **Scanner Engine (Model):** Seven independent scanner modules, each testing for a specific vulnerability type.
- **Database:** SQLite stores scan history.
- **Report Generator:** Creates PDF and JSON reports.

The key design pattern is the **Strategy Pattern** — the VulnerabilityAnalyzer orchestrates multiple scanner strategies that all follow the same interface (`scan(url) → list of vulnerabilities`).

---

### Q8: What are the limitations of your system?

**Answer:**
1. **Only detects Reflected XSS** — not Stored or DOM-based XSS.
2. **Only error-based SQLi** — cannot detect blind or time-based injection.
3. **Limited Deep Scan** — Cannot easily scan complex single-page apps (SPAs) without a headless browser.
4. **May trigger rate limiting** — aggressive scanning could get blocked.
5. **False positives possible** — results need manual verification.

---

### Q9: What is clickjacking?

**Answer:** Clickjacking is an attack where a malicious site loads your website in an invisible iframe and tricks users into clicking on it, unknowingly performing actions on your site (like transferring money or changing settings).

**Prevention:** Set `X-Frame-Options: DENY` to prevent iframe embedding.

---

### Q10: What technologies did you use and why?

**Answer:**
- **Flask:** Lightweight Python framework, perfect for REST APIs without overhead.
- **BeautifulSoup:** Robust HTML parser for extracting forms and input fields.
- **requests:** Simple HTTP library for sending web requests.
- **ssl + socket:** Built-in Python modules for certificate validation and port scanning.
- **fpdf2:** Pure Python PDF generation without external dependencies.
- **SQLite:** Zero-configuration file-based database, ideal for local storage.

---

### Q11: How is the vulnerability score calculated?

**Answer:** The score starts at 100 and subtracts points per vulnerability:
- HIGH: −25 points
- MEDIUM: −10 points
- LOW: −3 points
- INFO: 0 points

The minimum score is 0. Letter grades: A (90+), B (75+), C (60+), D (40+), F (below 40).

---

### Q12: How would you improve this project?

**Answer:**
1. Add **authenticated scanning** (support for scanning pages behind a login).
2. Implement **Blind SQL Injection** detection (time-based).
3. Add **DOM-based XSS** detection using a headless browser (like Selenium or Playwright).
4. Implement **full site crawling** to scan multiple pages automatically.
5. Use **OWASP ZAP API** for more professional-grade scanning.
6. Add **scheduling** for periodic automated scans.

---

## 🔑 Key Terms Glossary

| Term | Definition |
|------|-----------|
| XSS | Cross-Site Scripting — injecting scripts into web pages |
| SQLi | SQL Injection — manipulating database queries via input |
| CSP | Content-Security-Policy header |
| HSTS | HTTP Strict Transport Security |
| CORS | Cross-Origin Resource Sharing |
| OWASP | Open Web Application Security Project |
| CVE | Common Vulnerabilities and Exposures |
| MITM | Man-in-the-Middle attack |
| SSL/TLS | Encryption protocols for web traffic |
| Clickjacking | Tricking users into clicking hidden UI elements |
