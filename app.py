"""
Website Vulnerability Scanning System — Main Entry Point
========================================================
This script initializes the Flask application, registers blueprints,
and handles static file serving.

Project Architecture:
- Frontend: HTML/CSS/JS (Glassmorphism UI)
- Backend: Flask API
- Scanner Engine: Modular classes for specific vulns
- Database: SQLite for scan history
"""

import os
from flask import Flask, send_from_directory
from flask_cors import CORS

# Import modular routes (Blueprints)
# Note: We will create/refine these below
from backend.routes.scan_routes import scan_bp
from backend.routes.auth_routes import auth_bp

def create_app():
    app = Flask(__name__, 
                static_folder='frontend', 
                template_folder='frontend',
                static_url_path='')
    
    app.secret_key = os.environ.get('SECRET_KEY', 'vulnerability_scanner_secret_2024')
    
    # Enable CORS for development
    CORS(app)

    # Register Blueprints
    app.register_blueprint(scan_bp)
    app.register_blueprint(auth_bp)

    # Route for serving the frontend entry point
    @app.route('/')
    def index():
        return send_from_directory('frontend', 'index.html')

    # Catch-all to serve other static files from frontend
    @app.route('/<path:path>')
    def serve_static(path):
        return send_from_directory('frontend', path)

    return app

if __name__ == '__main__':
    # Ensure necessary directories exist
    os.makedirs('database', exist_ok=True)
    os.makedirs('reports', exist_ok=True)

    app = create_app()
    
    print("--------------------------------------------------")
    print("Website Vulnerability Scanning System is starting...")
    print("Access the UI at: http://127.0.0.1:5000")
    print("--------------------------------------------------")
    
    app.run(debug=True, port=5000)
