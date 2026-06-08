"""
Database Module
================
Unified SQLite database for storing scan history and user authentication.
"""

import sqlite3
import json
import os
import hashlib
from datetime import datetime, timezone


class Database:
    """Manages scan history and user storage using SQLite."""

    DB_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "database", "vulnerability_scanner.db"
    )

    def __init__(self):
        os.makedirs(os.path.dirname(self.DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(self.DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        """Create the necessary tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Scans Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                hostname TEXT,
                scan_time REAL,
                score INTEGER,
                grade TEXT,
                total_vulnerabilities INTEGER,
                summary TEXT,
                vulnerabilities TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        self.conn.commit()

    # --- User Management ---

    def create_user(self, username, password):
        """Create a new user with a hashed password."""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        try:
            cursor = self.conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, datetime.now(timezone.utc).isoformat())
            )
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None # Username already exists

    def authenticate_user(self, username, password):
        """Verify user credentials."""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        row = self.conn.execute(
            "SELECT id, username FROM users WHERE username = ? AND password_hash = ?",
            (username, password_hash)
        ).fetchone()
        return dict(row) if row else None

    # --- Scan Management ---

    def save_scan(self, scan_result: dict, user_id: int = None) -> int:
        """Save a scan result and return its ID."""
        cursor = self.conn.execute(
            """INSERT INTO scans
               (user_id, url, hostname, scan_time, score, grade,
                total_vulnerabilities, summary, vulnerabilities, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                scan_result.get("url", ""),
                scan_result.get("hostname", ""),
                scan_result.get("scan_time", 0),
                scan_result.get("score", 0),
                scan_result.get("grade", "?"),
                scan_result.get("total_vulnerabilities", 0),
                json.dumps(scan_result.get("summary", {})),
                json.dumps(scan_result.get("vulnerabilities", [])),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_history(self, user_id: int = None, limit: int = 20) -> list[dict]:
        """Retrieve recent scan history."""
        if user_id:
            rows = self.conn.execute(
                "SELECT id, url, hostname, score, grade, total_vulnerabilities, created_at FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT id, url, hostname, score, grade, total_vulnerabilities, created_at FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> dict | None:
        """Retrieve a full scan result by ID."""
        row = self.conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row:
            result = dict(row)
            result["summary"] = json.loads(result["summary"])
            result["vulnerabilities"] = json.loads(result["vulnerabilities"])
            return result
        return None

    def close(self):
        self.conn.close()
