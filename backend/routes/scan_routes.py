"""
Scan Routes (Flask Blueprint)
==============================
API endpoints for the vulnerability scanner.

Endpoints:
    POST /api/scan        - Start a new vulnerability scan
    GET  /api/history     - Get scan history
    GET  /api/scan/<id>   - Get a specific scan result
    GET  /api/report/<id> - Download PDF report for a scan
"""

import os
from flask import Blueprint, request, jsonify, send_file, session

from backend.utils.url_validator import validate_url
from backend.utils.report_generator import ReportGenerator
from backend.scanner.vulnerability_analyzer import VulnerabilityAnalyzer
from backend.database.db import Database

scan_bp = Blueprint("scan", __name__)
analyzer = VulnerabilityAnalyzer()
report_gen = ReportGenerator()
db = Database()


@scan_bp.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Start a vulnerability scan.

    Expected JSON body:
        {
            "url": "https://example.com",
            "options": {
                "headers": true,
                "ssl": true,
                "xss": true,
                "sqli": true,
                "ports": false,
                "directories": false,
                "subdomains": false
            }
        }

    Returns:
        JSON with scan results, score, grade, and vulnerabilities.
    """
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL is required."}), 400

    raw_url = data["url"]
    is_valid, normalized_url, error_msg = validate_url(raw_url)

    if not is_valid:
        return jsonify({"error": error_msg}), 400

    scan_options = data.get("options", {})

    try:
        # Get user_id from session if available
        user_id = session.get("user_id")
        
        result = analyzer.analyze(normalized_url, scan_options)
        # Save to database
        scan_id = db.save_scan(result, user_id=user_id)
        result["id"] = scan_id
        # Save JSON report
        report_gen.generate_json(result)

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


@scan_bp.route("/api/history", methods=["GET"])
def get_history():
    """Get recent scan history."""
    try:
        user_id = session.get("user_id")
        history = db.get_history(user_id=user_id)
        return jsonify(history), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scan_bp.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Get a specific scan result by ID."""
    result = db.get_scan(scan_id)
    if result:
        return jsonify(result), 200
    return jsonify({"error": "Scan not found."}), 404


@scan_bp.route("/api/report/<int:scan_id>", methods=["GET"])
def download_report(scan_id):
    """Generate and download a PDF report for a scan."""
    result = db.get_scan(scan_id)
    if not result:
        return jsonify({"error": "Scan not found."}), 404

    try:
        pdf_path = report_gen.generate_pdf(result)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=os.path.basename(pdf_path),
            mimetype="application/pdf",
        )
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500
