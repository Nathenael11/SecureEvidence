# -*- coding: utf-8 -*-
"""
SecureEvidence: Persistent User Store
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import sqlite3
import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
import bcrypt

from backend.config import settings

DB_FILE = os.path.join(settings.BASE_DIR, "users.db")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

VALID_ROLES = {"investigator", "analyst", "court_auditor", "system_admin"}

def get_db_path(db_path: Optional[str] = None) -> str:
    return db_path or os.getenv("USER_DB_PATH") or DB_FILE

def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_user_db(db_path: Optional[str] = None):
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    created_at TEXT NOT NULL,
                    public_key TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS token_denylist (
                    jti TEXT PRIMARY KEY,
                    revoked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    family_id TEXT NOT NULL,
                    is_used INTEGER DEFAULT 0,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS verification_stats (
                    key TEXT PRIMARY KEY,
                    count INTEGER DEFAULT 0
                )
            """)
    finally:
        conn.close()

def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def create_user(
    username: str,
    full_name: str,
    role: str,
    password: str,
    public_key: Optional[str] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of: {VALID_ROLES}")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    
    init_user_db(db_path)
    pw_hash = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()
    
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO users (username, full_name, role, password_hash, is_active, failed_attempts, created_at, public_key)
                VALUES (?, ?, ?, ?, 1, 0, ?, ?)
            """, (username, full_name, role, pw_hash, now, public_key))
            user_id = cursor.lastrowid
            return {
                "id": user_id,
                "username": username,
                "full_name": full_name,
                "role": role,
                "is_active": True,
                "created_at": now
            }
    finally:
        conn.close()

def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()

def update_user_lockout(username: str, failed_attempts: int, locked_until: Optional[str], db_path: Optional[str] = None):
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                (failed_attempts, locked_until, username)
            )
    finally:
        conn.close()

def reset_failed_attempts(username: str, db_path: Optional[str] = None):
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
                (username,)
            )
    finally:
        conn.close()

def is_account_locked(user: Dict[str, Any]) -> bool:
    locked_until_str = user.get("locked_until")
    if not locked_until_str:
        return False
    try:
        locked_until = datetime.fromisoformat(locked_until_str)
        if datetime.now(timezone.utc) < locked_until:
            return True
    except Exception:
        pass
    return False

def authenticate_user(username: str, password: str, db_path: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    user = get_user_by_username(username, db_path)
    if not user:
        verify_password("dummy_password_constant_time", "$2b$12$e80yvH.KzU2P2n9j8wM4vebMhDqCkWd36H7I6yU0q7jI98eL7E0gS")
        return False, None, "Invalid credentials."

    if not user.get("is_active", 1):
        return False, None, "Account is disabled."

    if is_account_locked(user):
        return False, None, "Account temporarily locked due to excessive failed attempts. Please try again later."

    valid = verify_password(password, user["password_hash"])
    if not valid:
        attempts = user.get("failed_attempts", 0) + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            lockout_time = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            locked_until = lockout_time.isoformat()
        update_user_lockout(username, attempts, locked_until, db_path)
        return False, None, "Invalid credentials."

    reset_failed_attempts(username, db_path)
    return True, user, "Authentication successful."

def seed_demo_accounts_if_needed(db_path: Optional[str] = None) -> Dict[str, str]:
    init_user_db(db_path)
    demo_accounts = [
        ("demo_investigator", "INSA Senior Investigator", "investigator"),
        ("demo_analyst", "INSA Forensic Analyst", "analyst"),
        ("demo_auditor", "Federal High Court Auditor", "court_auditor"),
        ("demo_admin", "INSA System Administrator", "system_admin"),
    ]
    
    generated_passwords = {}
    for username, full_name, role in demo_accounts:
        existing = get_user_by_username(username, db_path)
        if not existing:
            pw = "DemoTestPassword123!" if settings.DEMO_MODE else (secrets.token_urlsafe(12) + "!A1")
            create_user(username, full_name, role, pw, db_path=db_path)
            generated_passwords[username] = pw
        elif settings.DEMO_MODE and not verify_password("DemoTestPassword123!", existing["password_hash"]):
            conn = get_connection(db_path)
            try:
                with conn:
                    conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                                 (hash_password("DemoTestPassword123!"), username))
            finally:
                conn.close()
            generated_passwords[username] = "DemoTestPassword123!"
        else:
            generated_passwords[username] = "DemoTestPassword123!" if settings.DEMO_MODE else "********"
    return generated_passwords

def save_refresh_token(token_hash: str, username: str, family_id: str, expires_at: str, db_path: Optional[str] = None):
    """Store refresh token in DB for rotation and reuse tracking."""
    init_user_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO refresh_tokens (token_hash, username, family_id, is_used, expires_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
                (token_hash, username, family_id, expires_at, now)
            )
    finally:
        conn.close()

def is_refresh_token_used(token_hash: str, db_path: Optional[str] = None) -> bool:
    """Check if a refresh token has already been exchanged (reuse detection)."""
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT is_used FROM refresh_tokens WHERE token_hash = ?", (token_hash,))
        row = cur.fetchone()
        if not row:
            return False
        return bool(row["is_used"])
    finally:
        conn.close()

def mark_refresh_token_used(token_hash: str, db_path: Optional[str] = None):
    """Mark a refresh token as consumed upon rotation."""
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("UPDATE refresh_tokens SET is_used = 1 WHERE token_hash = ?", (token_hash,))
    finally:
        conn.close()

def revoke_token_family(family_id: str, db_path: Optional[str] = None):
    """Revoke all tokens in a family upon detecting refresh token reuse."""
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("UPDATE refresh_tokens SET is_used = 1 WHERE family_id = ?", (family_id,))
    finally:
        conn.close()

def inc_verification_stat(key: str, db_path: Optional[str] = None):
    """Increment persistent verification counter in SQLite."""
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO verification_stats (key, count) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET count = count + 1",
                (key,)
            )
    finally:
        conn.close()

def get_verification_stats(db_path: Optional[str] = None) -> Dict[str, int]:
    """Retrieve persistent verification counts."""
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT key, count FROM verification_stats")
        stats = {"total_queries": 0, "successful_verifications": 0, "mismatches_detected": 0}
        for row in cur.fetchall():
            if row["key"] in stats:
                stats[row["key"]] = row["count"]
        return stats
    finally:
        conn.close()

def add_token_to_denylist(jti: str, expires_at: str, db_path: Optional[str] = None):
    init_user_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO token_denylist (jti, revoked_at, expires_at) VALUES (?, ?, ?)",
                (jti, now, expires_at)
            )
    finally:
        conn.close()

def is_token_denylisted(jti: str, db_path: Optional[str] = None) -> bool:
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("SELECT 1 FROM token_denylist WHERE jti = ?", (jti,))
        return cursor.fetchone() is not None
    finally:
        conn.close()
