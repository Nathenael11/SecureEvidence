# -*- coding: utf-8 -*-
"""
SecureEvidence: Persistent User Store
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import sqlite3
import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple, Set
import bcrypt
import json

from backend.config import settings

DB_FILE = os.path.join(settings.BASE_DIR, "users.db")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

VALID_ROLES = {"investigator", "analyst", "court_auditor", "system_admin"}

_INITIALIZED_DBS: Set[str] = set()

def get_db_path(db_path: Optional[str] = None) -> str:
    return db_path or os.getenv("USER_DB_PATH") or DB_FILE

def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_user_db(db_path: Optional[str] = None):
    path = get_db_path(db_path)
    if path in _INITIALIZED_DBS:
        return
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
                    locked_ip TEXT,
                    created_at TEXT NOT NULL,
                    public_key TEXT
                )
            """)
            # Ensure locked_ip column exists in case table was created previously
            cur = conn.execute("PRAGMA table_info(users)")
            cols = {row[1] for row in cur.fetchall()}
            if "locked_ip" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN locked_ip TEXT;")

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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    limiter_name TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rate_limits ON rate_limits(limiter_name, client_ip, timestamp);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_flags (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS stream_engine_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS stream_engine_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS stream_engine_windows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    window_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
        _INITIALIZED_DBS.add(path)
    finally:
        conn.close()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
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

def update_user_lockout(
    username: str,
    failed_attempts: int,
    locked_until: Optional[str],
    client_ip: Optional[str] = None,
    db_path: Optional[str] = None
):
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ?, locked_ip = ? WHERE username = ?",
                (failed_attempts, locked_until, client_ip, username)
            )
    finally:
        conn.close()

def reset_failed_attempts(username: str, db_path: Optional[str] = None):
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, locked_ip = NULL WHERE username = ?",
                (username,)
            )
    finally:
        conn.close()

def is_account_locked(user: Dict[str, Any], client_ip: Optional[str] = None) -> bool:
    locked_until_str = user.get("locked_until")
    if not locked_until_str:
        return False
    try:
        locked_until = datetime.fromisoformat(locked_until_str)
        if datetime.now(timezone.utc) < locked_until:
            locked_ip = user.get("locked_ip")
            # If an attacker IP caused the lockout, do not lock out the legitimate user from another IP
            if locked_ip and client_ip and client_ip != locked_ip:
                return False
            return True
        else:
            reset_failed_attempts(user["username"])
    except Exception:
        pass
    return False

def authenticate_user(
    username: str,
    password: str,
    client_ip: Optional[str] = None,
    db_path: Optional[str] = None
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    user = get_user_by_username(username, db_path)
    if not user:
        verify_password("dummy_password_constant_time", "$2b$12$e80yvH.KzU2P2n9j8wM4vebMhDqCkWd36H7I6yU0q7jI98eL7E0gS")
        return False, None, "Invalid credentials."

    if not user.get("is_active", 1):
        return False, None, "Account is disabled."

    if is_account_locked(user, client_ip=client_ip):
        return False, None, "Account temporarily locked due to excessive failed attempts. Please try again later."

    valid = verify_password(password, user["password_hash"])
    if not valid:
        attempts = user.get("failed_attempts", 0) + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            lockout_time = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            locked_until = lockout_time.isoformat()
        update_user_lockout(username, attempts, locked_until, client_ip=client_ip, db_path=db_path)
        return False, None, "Invalid credentials."

    reset_failed_attempts(username, db_path)
    return True, user, "Authentication successful."

def seed_demo_accounts_if_needed(db_path: Optional[str] = None) -> Dict[str, str]:
    init_user_db(db_path)
    demo_accounts = [
        ("demo_investigator", "Senior Investigator", "investigator"),
        ("demo_analyst", "Forensic Analyst", "analyst"),
        ("demo_auditor", "Federal High Court Auditor", "court_auditor"),
        ("demo_admin", "System Administrator", "system_admin"),
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

def cleanup_expired_tokens(db_path: Optional[str] = None) -> int:
    """Prune expired tokens from token_denylist and refresh_tokens to prevent unbounded growth."""
    init_user_db(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        with conn:
            cur1 = conn.execute("DELETE FROM token_denylist WHERE expires_at < ?", (now_iso,))
            cur2 = conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now_iso,))
            return (cur1.rowcount or 0) + (cur2.rowcount or 0)
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
            # Clean up expired tokens periodically on denylist insert
            conn.execute("DELETE FROM token_denylist WHERE expires_at < ?", (now,))
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

def set_system_flag(key: str, value: str, db_path: Optional[str] = None):
    """Persist arbitrary system flags across worker processes and restarts."""
    init_user_db(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO system_flags (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, str(value), now_iso)
            )
    finally:
        conn.close()

def get_system_flag(key: str, default: Optional[str] = None, db_path: Optional[str] = None) -> Optional[str]:
    """Retrieve persistent system flag."""
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT value FROM system_flags WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else default
    finally:
        conn.close()

def save_stream_state(events_scored: int, threats_detected: int, is_running: bool, rate: int, db_path: Optional[str] = None) -> None:
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("INSERT OR REPLACE INTO stream_engine_state (key, value) VALUES ('events_scored', ?)", (str(events_scored),))
            conn.execute("INSERT OR REPLACE INTO stream_engine_state (key, value) VALUES ('threats_detected', ?)", (str(threats_detected),))
            conn.execute("INSERT OR REPLACE INTO stream_engine_state (key, value) VALUES ('is_running', ?)", ("1" if is_running else "0",))
            conn.execute("INSERT OR REPLACE INTO stream_engine_state (key, value) VALUES ('rate', ?)", (str(rate),))
    finally:
        conn.close()

def load_stream_state(db_path: Optional[str] = None) -> Dict[str, Any]:
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT key, value FROM stream_engine_state")
        rows = {row["key"]: row["value"] for row in cur.fetchall()}
        return {
            "events_scored": int(rows.get("events_scored", 0)),
            "threats_detected": int(rows.get("threats_detected", 0)),
            "is_running": rows.get("is_running") == "1",
            "rate": int(rows.get("rate", 200)),
        }
    except Exception:
        return {"events_scored": 0, "threats_detected": 0, "is_running": False, "rate": 200}
    finally:
        conn.close()

def record_stream_alert(alert: Dict[str, Any], max_records: int = 200, db_path: Optional[str] = None) -> None:
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO stream_engine_alerts (alert_json, created_at) VALUES (?, ?)",
                (json.dumps(alert), alert.get("scored_at") or datetime.now(timezone.utc).isoformat())
            )
            conn.execute("""
                DELETE FROM stream_engine_alerts
                WHERE id NOT IN (
                    SELECT id FROM stream_engine_alerts ORDER BY id DESC LIMIT ?
                )
            """, (max_records,))
    finally:
        conn.close()

def get_stream_alerts(limit: int = 50, threats_only: bool = False, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT alert_json FROM stream_engine_alerts ORDER BY id DESC LIMIT ?", (max(limit * 2, 200),))
        rows = cur.fetchall()
        alerts = []
        for r in rows:
            try:
                a = json.loads(r["alert_json"])
                if threats_only and not (a.get("is_threat") or a.get("predicted_class") != "BENIGN"):
                    continue
                alerts.append(a)
                if len(alerts) >= limit:
                    break
            except Exception:
                continue
        return alerts
    finally:
        conn.close()

def record_stream_window(window: Dict[str, Any], max_records: int = 20, db_path: Optional[str] = None) -> None:
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO stream_engine_windows (window_json, created_at) VALUES (?, ?)",
                (json.dumps(window), window.get("window_end") or datetime.now(timezone.utc).isoformat())
            )
            conn.execute("""
                DELETE FROM stream_engine_windows
                WHERE id NOT IN (
                    SELECT id FROM stream_engine_windows ORDER BY id DESC LIMIT ?
                )
            """, (max_records,))
    finally:
        conn.close()

def get_stream_windows(limit: int = 20, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    init_user_db(db_path)
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT window_json FROM stream_engine_windows ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        windows = []
        for r in rows:
            try:
                windows.append(json.loads(r["window_json"]))
            except Exception:
                continue
        return windows
    finally:
        conn.close()

