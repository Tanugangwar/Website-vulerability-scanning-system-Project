"""
Report Generator
=================
Generates vulnerability reports in JSON and PDF formats.

The PDF report includes:
    - Scan summary with score and grade
    - A table of all vulnerabilities with severity, description, and fix
    - Timestamp and target URL
"""

import json
import os
from datetime import datetime, timezone

from fpdf import FPDF


class ReportGenerator:
    """Generates scan reports in JSON and PDF formats."""

    REPORTS_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "reports"
    )

    def __init__(self):
        os.makedirs(self.REPORTS_DIR, exist_ok=True)

    def generate_json(self, scan_result: dict) -> str:
        """Save scan results as a JSON file and return the file path."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        hostname = scan_result.get("hostname", "unknown")
        filename = f"report_{hostname}_{timestamp}.json"
        filepath = os.path.join(self.REPORTS_DIR, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(scan_result, f, indent=2, ensure_ascii=False)

        return filepath

    def generate_pdf(self, scan_result: dict) -> str:
        """Generate a PDF report and return the file path."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        hostname = scan_result.get("hostname", "unknown")
        filename = f"report_{hostname}_{timestamp}.pdf"
        filepath = os.path.join(self.REPORTS_DIR, filename)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 15, "Vulnerability Scan Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(5)

        # Scan info
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, f"Target: {scan_result.get('url', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Scan Time: {scan_result.get('scan_time', 0)}s", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Score and grade
        score = scan_result.get("score", 0)
        grade = scan_result.get("grade", "?")
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"Security Score: {score}/100 (Grade: {grade})", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Summary
        summary = scan_result.get("summary", {})
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, f"HIGH: {summary.get('HIGH', 0)}  |  MEDIUM: {summary.get('MEDIUM', 0)}  |  LOW: {summary.get('LOW', 0)}  |  INFO: {summary.get('INFO', 0)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        # Vulnerabilities
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Vulnerabilities Found:", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        vulns = scan_result.get("vulnerabilities", [])
        if not vulns:
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 8, "No vulnerabilities detected.", new_x="LMARGIN", new_y="NEXT")
        else:
            for i, vuln in enumerate(vulns, 1):
                sev = vuln.get("severity", "INFO")
                vtype = vuln.get("type", "Unknown")
                desc = vuln.get("description", "")
                fix = vuln.get("fix", "")

                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(0, 8, f"{i}. [{sev}] {vtype}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 10)
                pdf.multi_cell(0, 6, f"   Description: {desc}")
                pdf.multi_cell(0, 6, f"   Fix: {fix}")
                pdf.ln(3)

        pdf.output(filepath)
        return filepath
