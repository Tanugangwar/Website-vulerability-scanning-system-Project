"""
Authentication Routes (Flask Blueprint)
=======================================
API endpoints for user signup, login, and session management.
"""

from flask import Blueprint, request, jsonify, session
from backend.database.db import Database

auth_bp = Blueprint("auth", __name__)
db = Database()

@auth_bp.route("/api/auth/signup", methods=["POST"])
def signup():
    """Register a new user."""
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    username = data["username"]
    password = data["password"]
    
    user_id = db.create_user(username, password)
    if user_id:
        return jsonify({"message": "User created successfully", "user_id": user_id}), 201
    else:
        return jsonify({"error": "Username already exists"}), 409

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate a user and start a session."""
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    user = db.authenticate_user(data["username"], data["password"])
    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return jsonify({"message": "Login successful", "user": user}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    """Clear the user session."""
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

@auth_bp.route("/api/auth/status", methods=["GET"])
def status():
    """Check if the user is logged in."""
    if "user_id" in session:
        return jsonify({
            "is_logged_in": True,
            "username": session["username"]
        }), 200
    return jsonify({"is_logged_in": False}), 200
