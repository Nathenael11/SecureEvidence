# -*- coding: utf-8 -*-
"""
Unit and Integration Tests for Authentication, Lockout, RBAC & Token Lifecycles
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import os
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.user_store import (
    init_user_db,
    create_user,
    authenticate_user,
    get_user_by_username,
    is_account_locked,
    add_token_to_denylist,
    is_token_denylisted,
    MAX_FAILED_ATTEMPTS
)
from backend.security import (
    create_jwt_token,
    decode_jwt_token,
    create_refresh_token,
    login_limiter,
    public_verifier_limiter,
    AuditLogger,
    RateLimiter,
    ROLE_ANALYST,
    ROLE_INVESTIGATOR
)
import json

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_users():
    login_limiter.reset()
    public_verifier_limiter.reset()
    init_user_db()
    # Create test users if not present
    for role in ["analyst", "investigator", "court_auditor", "system_admin"]:
        uname = f"test_{role}"
        if not get_user_by_username(uname):
            create_user(uname, f"Test {role.title()}", role, "SecretPassword123!")

def test_password_length_enforcement():
    with pytest.raises(ValueError):
        create_user("short_user", "Short User", "analyst", "short123")

def test_successful_login():
    res = client.post("/auth/login", json={
        "username": "test_analyst",
        "password": "SecretPassword123!"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "analyst"
    assert "refresh_token" in res.cookies

def test_failed_login_and_lockout():
    uname = "lockout_user"
    if not get_user_by_username(uname):
        create_user(uname, "Lockout User", "analyst", "SecretPassword123!")
    
    # 5 consecutive failed attempts
    for i in range(MAX_FAILED_ATTEMPTS):
        res = client.post("/auth/login", json={
            "username": uname,
            "password": "WrongPassword123!"
        })
        assert res.status_code == 401
    
    user = get_user_by_username(uname)
    assert is_account_locked(user) is True

    # 6th attempt should be blocked due to lockout
    res_locked = client.post("/auth/login", json={
        "username": uname,
        "password": "SecretPassword123!"
    })
    assert res_locked.status_code == 401
    assert "locked" in res_locked.json()["detail"].lower()

def test_token_denylist_and_revocation():
    token, jti = create_jwt_token(subject="test_analyst", role="analyst")
    # Decode works initially
    decoded = decode_jwt_token(token)
    assert decoded["sub"] == "test_analyst"

    # Add to denylist
    add_token_to_denylist(jti, "2030-01-01T00:00:00Z")
    assert is_token_denylisted(jti) is True

    # Decode should now raise revoked
    with pytest.raises(Exception):
        decode_jwt_token(token)

def test_rbac_audit_log_access():
    # Analyst cannot view audit-logs (requires court_auditor or system_admin)
    login_analyst = client.post("/auth/login", json={
        "username": "test_analyst",
        "password": "SecretPassword123!"
    }).json()
    token_analyst = login_analyst["access_token"]

    res_forbidden = client.get("/audit-logs", headers={"Authorization": f"Bearer {token_analyst}"})
    assert res_forbidden.status_code == 403

    # Court auditor can view audit-logs
    login_auditor = client.post("/auth/login", json={
        "username": "test_court_auditor",
        "password": "SecretPassword123!"
    }).json()
    token_auditor = login_auditor["access_token"]

    res_allowed = client.get("/audit-logs", headers={"Authorization": f"Bearer {token_auditor}"})
    assert res_allowed.status_code == 200
    assert "audit_trail" in res_allowed.json()

def test_auth_me_endpoint():
    login_res = client.post("/auth/login", json={
        "username": "test_investigator",
        "password": "SecretPassword123!"
    }).json()
    token = login_res["access_token"]

    res_me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_me.status_code == 200
    me_data = res_me.json()
    assert me_data["username"] == "test_investigator"
    assert me_data["role"] == "investigator"

def test_route_enumeration_auth():
    """Verify that every route in the application either enforces auth or is in the explicit public allowlist."""
    public_endpoints = {
        "/",
        "/health",
        "/evidence/verify-public",
        "/auth/login",
        "/auth/token",
        "/auth/refresh",
        "/auth/logout",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/openapi.json"
    }

    for route in app.routes:
        if hasattr(route, "path") and not route.path.startswith("/static"):
            path = route.path
            if path not in public_endpoints:
                # Test calling without token -> must receive 401 Unauthorized
                methods = getattr(route, "methods", ["GET"])
                for method in methods:
                    if method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        res = client.request(method, path)
                        assert res.status_code in [401, 403], f"Route {method} {path} is not secured! Got {res.status_code}"

def test_role_matrix_restrictions():
    """Verify role permissions matrix:
       - Analyst: Can /detect, cannot /evidence/store, cannot /audit-logs
       - Investigator: Can /detect, can /evidence/store, cannot /audit-logs
       - Court Auditor: Cannot /detect, cannot /evidence/store, can /audit-logs
    """
    # 1. Analyst
    analyst_token = client.post("/auth/login", json={"username": "test_analyst", "password": "SecretPassword123!"}).json()["access_token"]
    res_detect = client.post("/detect", json={"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1"}, headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_detect.status_code != 403 # Role allowed

    res_store = client.post("/evidence/store", json={"case_id": "TEST", "incident_type": "Test", "target_asset": "Server", "evidence_payload": {}}, headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_store.status_code == 403 # Analyst forbidden from storing

    # 2. Investigator
    inv_token = client.post("/auth/login", json={"username": "test_investigator", "password": "SecretPassword123!"}).json()["access_token"]
    res_inv_store = client.post("/evidence/store", json={"case_id": "TEST", "incident_type": "Test", "target_asset": "Server", "evidence_payload": {"test": 1}}, headers={"Authorization": f"Bearer {inv_token}"})
    assert res_inv_store.status_code != 403 # Investigator allowed

    res_inv_audit = client.get("/audit-logs", headers={"Authorization": f"Bearer {inv_token}"})
    assert res_inv_audit.status_code == 403 # Investigator forbidden from audit logs

    # 3. Court Auditor
    auditor_token = client.post("/auth/login", json={"username": "test_court_auditor", "password": "SecretPassword123!"}).json()["access_token"]
    res_aud_detect = client.post("/detect", json={"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1"}, headers={"Authorization": f"Bearer {auditor_token}"})
    assert res_aud_detect.status_code == 403 # Auditor forbidden from running detection

def test_identity_from_token_override():
    """Verify that investigator name passed in request body cannot spoof the authenticated user."""
    inv_token = client.post("/auth/login", json={"username": "test_investigator", "password": "SecretPassword123!"}).json()["access_token"]
    res = client.post("/evidence/store", json={
        "case_id": "INSA-TEST-9999",
        "incident_type": "IdentityTest",
        "target_asset": "CoreSwitch",
        "evidence_payload": {"metric": 100},
        "investigator": "Spoofed Imposter Officer" # Attempted spoof
    }, headers={"Authorization": f"Bearer {inv_token}"})
    assert res.status_code == 200
    receipt = res.json()
    # The actual investigator recorded must match the authenticated token (Test Investigator), not Spoofed Imposter
    assert receipt["investigator"] in ("Test Investigator", "Test Senior Investigator")
    assert receipt["investigator"] != "Spoofed Imposter Officer"

def test_refresh_token_rotation_and_logout_revocation():
    """Verify refresh token rotation invalidates the old token, and logout revokes active tokens."""
    login_res = client.post("/auth/login", json={"username": "test_investigator", "password": "SecretPassword123!"})
    assert login_res.status_code == 200
    cookies = login_res.cookies
    old_refresh = cookies.get("refresh_token")
    assert old_refresh is not None

    # Refresh token with custom CSRF header
    refresh_res = client.post("/auth/refresh", cookies={"refresh_token": old_refresh}, headers={"X-Requested-With": "XMLHttpRequest"})
    assert refresh_res.status_code == 200
    new_data = refresh_res.json()
    assert "access_token" in new_data
    new_refresh = refresh_res.cookies.get("refresh_token")
    assert new_refresh is not None
    assert new_refresh != old_refresh

    # Replaying old refresh token must now fail (rotation denylist)
    replay_res = client.post("/auth/refresh", cookies={"refresh_token": old_refresh}, headers={"X-Requested-With": "XMLHttpRequest"})
    assert replay_res.status_code == 401

    # Logout revokes the access and refresh token
    access_token = new_data["access_token"]
    logout_res = client.post("/auth/logout", headers={"Authorization": f"Bearer {access_token}"}, cookies={"refresh_token": new_refresh})
    assert logout_res.status_code == 200

    # Denylisted access token must be rejected
    me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_res.status_code == 401

def test_token_claims_validation_expired_wrong_issuer_audience_tampered():
    """Verify rejection of expired, wrong issuer, wrong audience, and tampered tokens."""
    import jwt
    from datetime import datetime, timezone, timedelta
    from backend.security import get_jwt_secret, JWT_ISSUER, JWT_AUDIENCE

    secret = get_jwt_secret()

    # 1. Expired token
    expired_payload = {
        "sub": "test_analyst", "role": "analyst", "type": "access",
        "exp": int((datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()),
        "iat": int((datetime.now(timezone.utc) - timedelta(minutes=20)).timestamp()),
        "iss": JWT_ISSUER, "aud": JWT_AUDIENCE, "jti": "exp-123"
    }
    exp_token = jwt.encode(expired_payload, secret, algorithm="HS256")
    res_exp = client.get("/auth/me", headers={"Authorization": f"Bearer {exp_token}"})
    assert res_exp.status_code == 401

    # 2. Wrong issuer
    bad_iss_payload = dict(expired_payload, exp=int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()), iss="Fake-Issuer")
    bad_iss_token = jwt.encode(bad_iss_payload, secret, algorithm="HS256")
    res_iss = client.get("/auth/me", headers={"Authorization": f"Bearer {bad_iss_token}"})
    assert res_iss.status_code == 401

    # 3. Wrong audience
    bad_aud_payload = dict(expired_payload, exp=int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()), aud="Foreign-Audience")
    bad_aud_token = jwt.encode(bad_aud_payload, secret, algorithm="HS256")
    res_aud = client.get("/auth/me", headers={"Authorization": f"Bearer {bad_aud_token}"})
    assert res_aud.status_code == 401

    # 4. Tampered token signature
    good_token, _ = create_jwt_token("test_analyst", "analyst")
    tampered_token = good_token[:-4] + ("A" if good_token[-1] != "A" else "B")
    res_tamp = client.get("/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res_tamp.status_code == 401

def test_startup_failure_without_jwt_secret_when_demo_false():
    """Assert runtime error is raised by backend startup when DEMO_MODE=false and JWT_SECRET is missing."""
    import subprocess
    import sys
    env = os.environ.copy()
    env["DEMO_MODE"] = "false"
    env["JWT_SECRET"] = ""
    proc = subprocess.run(
        [sys.executable, "-c", "import backend.config"],
        env=env,
        capture_output=True,
        text=True
    )
    assert proc.returncode != 0
    assert "CRITICAL CONFIGURATION ERROR" in proc.stderr

def test_auth_jwt_and_rbac():
    """Verify JWT creation, decoding, expiration, and role validation."""
    token, _ = create_jwt_token("analyst_user", ROLE_ANALYST, expires_minutes=15)
    payload = decode_jwt_token(token)
    assert payload["sub"] == "analyst_user"
    assert payload["role"] == ROLE_ANALYST

    expired_token, _ = create_jwt_token("expired_user", ROLE_INVESTIGATOR, expires_minutes=-5)
    with pytest.raises(Exception):
        decode_jwt_token(expired_token)

def test_rate_limiter():
    """Verify rate limiter blocks after threshold."""
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    ip = "192.168.1.100"

    assert limiter.check_rate_limit(ip) is True
    assert limiter.check_rate_limit(ip) is True
    assert limiter.check_rate_limit(ip) is True
    assert limiter.check_rate_limit(ip) is False

def test_persistent_audit_log_and_tamper_detection(tmp_path):
    """Verify append-only hash linking in AuditLogger and verify_audit_log detection."""
    test_log_file = str(tmp_path / "test_audit.jsonl")
    AuditLogger.set_log_file(test_log_file)

    assert AuditLogger.verify_audit_log(test_log_file)[0] is True
    assert AuditLogger.verify_audit_log(test_log_file)[1] == -1

    AuditLogger.log_api_call("/test1", "GET", "127.0.0.1", 200, details="Call 1")
    AuditLogger.log_api_call("/test2", "POST", "127.0.0.1", 200, details="Call 2")
    AuditLogger.log_api_call("/test3", "POST", "127.0.0.1", 200, details="Call 3")
    AuditLogger.log_api_call("/test4", "GET", "127.0.0.1", 200, details="Call 4")

    is_valid, broken_idx, msg = AuditLogger.verify_audit_log(test_log_file)
    assert is_valid is True
    assert broken_idx == -1

    with open(test_log_file, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f]

    lines[2]["details"] = "Hacker modified this line"

    with open(test_log_file, "w", encoding="utf-8") as f:
        for entry in lines:
            f.write(json.dumps(entry) + "\n")

    is_valid_tamp, broken_idx_tamp, reason_tamp = AuditLogger.verify_audit_log(test_log_file)
    assert is_valid_tamp is False
    assert broken_idx_tamp == 2
    assert "content tampering" in reason_tamp


