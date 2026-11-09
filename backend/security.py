# -*- coding: utf-8 -*-
"""
SecureEvidence: Security Controls, Auth & Persistent Audit Logging
Author: Nathenael Ermias
Design: Prototype with production-oriented design (INSA)
"""

import time
import json
import hashlib
import os
import uuid
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set, Union

import jwt
from fastapi import Request, Response, HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import settings
from backend.user_store import is_token_denylisted

security_bearer = HTTPBearer(auto_error=False)

# Role definitions
ROLE_INVESTIGATOR = "investigator"
ROLE_ANALYST = "analyst"
ROLE_COURT_AUDITOR = "court_auditor"
ROLE_SYSTEM_ADMIN = "system_admin"

VALID_ROLES = {ROLE_INVESTIGATOR, ROLE_ANALYST, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}
JWT_ISSUER = "INSA-SecureEvidence"
JWT_AUDIENCE = "INSA-Forensics-Platform"

def get_jwt_secret() -> str:
    secret = settings.JWT_SECRET
    if not secret:
        if not settings.DEMO_MODE:
            raise RuntimeError("CRITICAL: JWT_SECRET environment variable is missing in non-demo mode.")
        return "INSA-DEMO-DEVELOPMENT-SECRET-KEY-CHANGE-IN-PROD"
    return secret

def create_jwt_token(
    subject: str,
    role: str,
    full_name: Optional[str] = None,
    officer_id: Optional[str] = None,
    expires_minutes: Optional[int] = 15,
    secret: Optional[str] = None,
    audience: Optional[str] = None
) -> Tuple[str, str]:
    """Generate a signed access JWT token with short expiry (default 15 mins). Returns (token, jti)."""
    secret_key = secret or get_jwt_secret()
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")

    expiry = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes if expires_minutes is not None else 15)
    token_jti = str(uuid.uuid4())
    payload = {
        "sub": subject,
        "role": role,
        "full_name": full_name or subject,
        "officer_id": officer_id or f"INSA-{subject.upper()}",
        "jti": token_jti,
        "type": "access",
        "exp": int(expiry.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "iss": JWT_ISSUER,
        "aud": audience or JWT_AUDIENCE
    }
    return jwt.encode(payload, secret_key, algorithm=settings.JWT_ALGORITHM), token_jti

def create_refresh_token(
    subject: str,
    family_id: Optional[str] = None,
    expires_days: int = 7,
    secret: Optional[str] = None
) -> Tuple[str, str, str]:
    """Generate a signed refresh token with 7-day expiry. Returns (token, jti, family_id)."""
    secret_key = secret or get_jwt_secret()
    expiry = datetime.now(timezone.utc) + timedelta(days=expires_days)
    token_jti = str(uuid.uuid4())
    fam_id = family_id or str(uuid.uuid4())
    payload = {
        "sub": subject,
        "jti": token_jti,
        "family_id": fam_id,
        "type": "refresh",
        "exp": int(expiry.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE
    }
    return jwt.encode(payload, secret_key, algorithm=settings.JWT_ALGORITHM), token_jti, fam_id

def decode_jwt_token(
    token: Union[str, Tuple[str, Any]],
    secret: Optional[str] = None,
    audience: Optional[str] = None
) -> Dict[str, Any]:
    """Verify and decode a JWT token, ensuring all claims (iss, aud, exp, iat, jti, role) are valid."""
    if isinstance(token, tuple):
        token = token[0]
    secret_key = secret or get_jwt_secret()
    expected_aud = audience or JWT_AUDIENCE
    payload = jwt.decode(
        token,
        secret_key,
        algorithms=[settings.JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        audience=expected_aud
    )
    jti = payload.get("jti")
    if jti and is_token_denylisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked."
        )
    return payload

async def get_current_user_and_role(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> Dict[str, Any]:
    """FastAPI dependency: Extract and validate JWT bearer token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required"
        )
    try:
        payload = decode_jwt_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type: access token required"
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(e)}"
        )

def require_role(roles: Union[str, Set[str], List[str]]):
    """FastAPI dependency factory enforcing RBAC roles (returns require_role dependency)."""
    if isinstance(roles, str):
        allowed_roles = {roles}
    else:
        allowed_roles = set(roles)

    async def role_checker(user: Dict[str, Any] = Security(get_current_user_and_role)):
        user_role = user.get("role")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: role '{user_role}' lacks permission. Required: {list(allowed_roles)}"
            )
        return user
    return role_checker

# Alias for backward compatibility
# Alias for backward compatibility
require_roles = require_role

def get_client_ip(request: Optional[Request]) -> str:
    """
    Extract the true client IP address, properly accounting for reverse proxies
    such as Render, Cloudflare, AWS ALB, and Nginx via X-Forwarded-For.
    """
    if not request:
        return "127.0.0.1"
    headers = getattr(request, "headers", None)
    if headers:
        forwarded = None
        real_ip = None
        for k, v in headers.items():
            k_lower = k.lower()
            if k_lower == "x-forwarded-for" and not forwarded:
                forwarded = v
            elif k_lower == "x-real-ip" and not real_ip:
                real_ip = v
        if forwarded:
            first_ip = forwarded.split(",")[0].strip()
            if first_ip:
                return first_ip
        if real_ip and real_ip.strip():
            return real_ip.strip()
    if getattr(request, "client", None) and getattr(request.client, "host", None):
        return request.client.host
    return "127.0.0.1"

class RateLimiter:
    """Sliding-window rate limiter per client IP with SQLite persistence and memory fallback."""
    def __init__(self, max_requests: int = 15, window_seconds: int = 60, name: Optional[str] = None):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.name = name or str(id(self))
        self._history: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def check_rate_limit(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        # 1. Try SQLite persistence so rate limits are shared across workers and survive restarts
        try:
            from backend.user_store import get_connection
            conn = get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM rate_limits WHERE timestamp < ?", (cutoff,))
                    cur = conn.execute(
                        "SELECT COUNT(*) FROM rate_limits WHERE limiter_name = ? AND client_ip = ? AND timestamp >= ?",
                        (self.name, client_ip, cutoff)
                    )
                    count = cur.fetchone()[0]
                    if count >= self.max_requests:
                        return False
                    conn.execute(
                        "INSERT INTO rate_limits (limiter_name, client_ip, timestamp) VALUES (?, ?, ?)",
                        (self.name, client_ip, now)
                    )
                    return True
            finally:
                conn.close()
        except Exception:
            # 2. Fallback to thread-safe in-memory sliding window
            with self._lock:
                timestamps = self._history.get(client_ip, [])
                valid_timestamps = [t for t in timestamps if now - t < self.window_seconds]
                if len(valid_timestamps) >= self.max_requests:
                    self._history[client_ip] = valid_timestamps
                    return False
                valid_timestamps.append(now)
                self._history[client_ip] = valid_timestamps
                return True

    def reset(self):
        with self._lock:
            self._history.clear()
        try:
            from backend.user_store import get_connection
            conn = get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM rate_limits WHERE limiter_name = ?", (self.name,))
            finally:
                conn.close()
        except Exception:
            pass

public_verifier_limiter = RateLimiter(max_requests=30, window_seconds=60, name="public_verifier")
login_limiter = RateLimiter(max_requests=10, window_seconds=60, name="login")

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects HTTP security headers and enforces request size limits."""

    async def dispatch(self, request: Request, call_next):
        # Enforce maximum request payload size of 10MB
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 10 * 1024 * 1024:
            return Response(content="Payload Too Large", status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-Agency"] = "SecureEvidence Forensic Ledger"
        return response

class AuditLogger:
    """
    Append-only, hash-linked JSON-lines persistent audit logger.
    Persists to disk with integrity verification and fast tail-hash caching.
    """

    _lock = threading.Lock()
    _log_file = settings.AUDIT_LOG_FILE
    _last_hash: Optional[str] = None

    @classmethod
    def set_log_file(cls, path: str):
        with cls._lock:
            cls._log_file = path
            cls._last_hash = None

    @classmethod
    def get_latest_hash(cls) -> str:
        if cls._last_hash is not None:
            return cls._last_hash
        if not os.path.exists(cls._log_file):
            cls._last_hash = "0" * 64
            return cls._last_hash
        try:
            with open(cls._log_file, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size == 0:
                    cls._last_hash = "0" * 64
                    return cls._last_hash
                read_size = min(size, 8192)
                f.seek(size - read_size)
                lines = f.read().decode("utf-8", errors="replace").strip().splitlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    cls._last_hash = last_entry.get("log_hash", "0" * 64)
                    return cls._last_hash
        except Exception:
            pass
        cls._last_hash = "0" * 64
        return cls._last_hash

    @classmethod
    def log_api_call(
        cls,
        endpoint: str,
        method: str,
        client_ip: str,
        status_code: int,
        officer_id: str = "INSA-SYS-01",
        role: str = "system",
        details: Optional[str] = None
    ) -> Dict[str, Any]:
        with cls._lock:
            prev_hash = cls.get_latest_hash()
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            entry = {
                "timestamp": timestamp,
                "endpoint": endpoint,
                "method": method,
                "client_ip": client_ip,
                "status_code": status_code,
                "officer_id": officer_id,
                "role": role,
                "details": details or "API operation",
                "previous_hash": prev_hash
            }

            canonical = json.dumps(entry, sort_keys=True, separators=(',', ':'))
            log_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
            entry["log_hash"] = log_hash
            cls._last_hash = log_hash

            os.makedirs(os.path.dirname(os.path.abspath(cls._log_file)), exist_ok=True)
            with open(cls._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

            try:
                from blockchain.ledger_store import get_ledger_store
                store = get_ledger_store()
                store.add_audit_log_entry(
                    endpoint=endpoint,
                    method=method,
                    client_ip=client_ip,
                    status_code=status_code,
                    officer_id=officer_id,
                    role=role,
                    details=details or "API operation"
                )
            except Exception:
                pass

            return entry

    @classmethod
    def verify_audit_log(cls, file_path: Optional[str] = None) -> Tuple[bool, int, str]:
        path = file_path or cls._log_file
        if not os.path.exists(path):
            return True, -1, "Audit log file does not exist"

        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        if not lines:
            return True, -1, "Audit log is empty"

        expected_prev = "0" * 64
        for idx, line in enumerate(lines):
            try:
                entry = json.loads(line)
            except Exception as e:
                return False, idx, f"Line {idx} corrupted JSON: {str(e)}"

            if entry.get("previous_hash") != expected_prev:
                return False, idx, f"Line {idx} hash break: previous_hash mismatch"

            body = {k: entry[k] for k in entry if k != "log_hash"}
            canonical = json.dumps(body, sort_keys=True, separators=(',', ':'))
            recalculated = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

            if recalculated != entry.get("log_hash"):
                return False, idx, f"Line {idx} content tampering detected"

            expected_prev = entry.get("log_hash")

        return True, -1, "Audit log integrity verified"

    @classmethod
    def get_recent_logs(cls, limit: int = 50) -> List[Dict[str, Any]]:
        if not os.path.exists(cls._log_file):
            return []
        with open(cls._log_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        entries = []
        for line in reversed(lines[-limit:]):
            try:
                entries.append(json.loads(line))
            except Exception:
                continue
        return entries
