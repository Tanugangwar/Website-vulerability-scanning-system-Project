# Website Vulnerability Scanning System 🛡️

A comprehensive, modular Software Engineering project designed to scan and analyze websites for common security vulnerabilities. This system provides a clean architecture, a premium modern UI, and detailed reporting.

## 🚀 Features

### 🟢 Core Scanners (Must Have)
- **URL Validation**: Ensures the target URL is reachable and properly formatted.
- **Security Header Analysis**: Detects missing headers like `Content-Security-Policy`, `X-Frame-Options`, `X-XSS-Protection`, and `Strict-Transport-Security`.
- **SSL/TLS Validation**: Checks for HTTPS usage and validates SSL certificates (expiry, issuer).

### 🟡 Intermediate Scanners
- **XSS Detection**: Analyzes forms and parameters for reflected Cross-Site Scripting (XSS) risks.
- **SQL Injection Detection**: Scans for potential SQLi vulnerabilities using common payloads.
- **Form Analysis**: Detects input fields and potential CSRF risks.

### 🔴 Advanced Features
- **Port Scanning**: Identifies open ports (FTP, SSH, SQL, etc.) that might expose the server.
- **Directory Brute-forcing**: Discovers hidden directories using common wordlists.
- **Subdomain Discovery**: Finds subdomains associated with the target host.

### 📊 Reporting & History
- **Security Score & Grade**: Computes an overall security rating from A to F.
- **PDF Report Generation**: Download a structured professional PDF report of the scan findings.
- **Scan History**: Logged-in users can view their past scans and scores.

## ⚙️ Tech Stack

- **Backend**: Python 3.x, Flask (Blueprint-based Modular Architecture)
- **Database**: SQLite3 (Users and Scan History)
- **Frontend**: HTML5, Vanilla CSS3 (Glassmorphism), JavaScript (ES6, Fetch API)
- **Libraries**: `requests`, `BeautifulSoup4`, `fpdf2`, `cryptography`

## 🏗️ System Architecture

The project follows a **Clean Modular Architecture**:
1. **User Interface**: Modern responsive dashboard for input and visualization.
2. **Backend API**: Flask routes organized into Blueprints (`auth_routes`, `scan_routes`).
3. **Scanner Engine**: A central `VulnerabilityAnalyzer` orchestrating specialized modules.
4. **Vulnerability Analyzer**: Individual classes for Header, SSL, XSS, SQLi, Port, and Directory scanning.
5. **Report Generator**: Utility to create JSON and PDF reports.
6. **Database Module**: Unified handler for SQLite persistence.

## 📁 Project Structure

```text
├── backend/
│   ├── database/       # SQLite logic and DB files
│   ├── routes/         # Flask blueprints (auth, scan)
│   ├── scanner/        # Core scanning modules
│   ├── utils/          # Helpers (validation, reporting)
├── frontend/
│   ├── app.js          # Core frontend logic
│   ├── styles.css      # Premium glassmorphism UI
│   ├── index.html      # Main Dashboard
│   └── ...             # Auth pages (login, signup)
├── reports/            # Generated PDF/JSON reports
├── database/           # SQLite database storage
├── app.py              # Main entry point
├── requirements.txt    # Project dependencies
└── README.md           # Documentation
```

## 🛠️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd website-vulnerability-scanner
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the system**:
   Navigate to `http://127.0.0.1:5000` in your web browser.

## 🔐 Ethical Guidelines
**IMPORTANT**: This system is for **educational and authorized testing only**. 
- Only scan websites you own or have explicit permission to test.
- Do not use this tool for aggressive scanning or illegal activities.

---
**Author**: [Tanu gangwar/Github]  
**License**: MIT
