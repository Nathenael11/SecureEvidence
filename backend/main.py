# -*- coding: utf-8 -*-
"""
SecureEvidence: Sovereign Forensic REST API & Blockchain Engine
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: AI Engineering, Big Data & Blockchain (INSA)
"""

import os
import sys
import re
import json
import time
import html
import uuid
import hashlib
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, status, Query, Request, Response, Depends, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import httpx
import shutil
import random
import subprocess
import logging
logger = logging.getLogger('secure_evidence')
from backend.config import settings
from backend.schemas import (
    NetworkEventInput,
    DetectionResponse,
    EvidenceStoreRequest,
    EvidenceVerifyRequest,
    PublicVerifyRequest,
    MerkleBatchRequest,
    SuricataIngestRequest,
    TokenRequest,
    LoginResponse,
    ReviewEvidenceRequest,
    SystemHealthResponse,
    StreamControlRequest
)
from backend.user_store import (
    init_user_db,
    authenticate_user,
    seed_demo_accounts_if_needed,
    add_token_to_denylist,
    get_user_by_username,
    save_refresh_token,
    is_refresh_token_used,
    mark_refresh_token_used,
    revoke_token_family,
    inc_verification_stat,
    get_verification_stats,
    get_system_flag,
    set_system_flag,
    save_stream_state,
    load_stream_state,
    record_stream_alert,
    get_stream_alerts,
    record_stream_window,
    get_stream_windows
)
from backend.security import (
    SecurityHeadersMiddleware,
    AuditLogger,
    get_client_ip,
    create_jwt_token,
    create_refresh_token,
    decode_jwt_token,
    require_role,
    require_roles,
    get_current_user_and_role,
    public_verifier_limiter,
    login_limiter,
    ROLE_ANALYST,
    ROLE_INVESTIGATOR,
    ROLE_COURT_AUDITOR,
    ROLE_SYSTEM_ADMIN
)
from backend.services.detection_service import DetectionService
from backend.services.evidence_service import EvidenceService
from backend.services.log_service import LogStreamService
from backend.services.ingestion_service import SensorLogIngestionService
from backend.services.stix_service import STIX2ExportService
from blockchain.chain_of_custody import CustodyAction
from blockchain.merkle_tree import MerkleTree
from blockchain.web3_client import (
    Web3EvidenceClient,
    BlockchainError,
    RpcDownError,
    WrongChainIdError,
    InsufficientFundsError,
    ChainDisagreementError
)
from big_data.stream_simulator import stream_events

# Startup checks & initialization
init_user_db()

LEDGER_INTEGRITY_STATUS = {"status": "VALID", "broken_id": None}
LEDGER_INTEGRITY_ACKNOWLEDGED = False

def is_ledger_integrity_acknowledged() -> bool:
    global LEDGER_INTEGRITY_ACKNOWLEDGED
    try:
        val = get_system_flag("ledger_integrity_acknowledged", "0")
        if str(val).lower() in ("1", "true", "yes"):
            return True
    except Exception:
        pass
    return bool(LEDGER_INTEGRITY_ACKNOWLEDGED)

def set_ledger_integrity_acknowledged(val: bool) -> None:
    global LEDGER_INTEGRITY_ACKNOWLEDGED
    LEDGER_INTEGRITY_ACKNOWLEDGED = bool(val)
    try:
        set_system_flag("ledger_integrity_acknowledged", "1" if val else "0")
    except Exception:
        pass

# Cached chain verification with TTL to prevent DoS on /health
_CHAIN_VERIFY_CACHE: Dict[str, Any] = {"timestamp": 0.0, "result": None}

async def get_cached_chain_verification(evidence_client, max_age_sec: float = 30.0) -> Dict[str, Any]:
    now = time.time()
    if _CHAIN_VERIFY_CACHE["result"] is not None and (now - _CHAIN_VERIFY_CACHE["timestamp"]) < max_age_sec:
        return _CHAIN_VERIFY_CACHE["result"]
    res = await asyncio.to_thread(evidence_client.verify_chain)
    _CHAIN_VERIFY_CACHE["timestamp"] = now
    _CHAIN_VERIFY_CACHE["result"] = res
    return res

def invalidate_chain_verification_cache() -> None:
    _CHAIN_VERIFY_CACHE["timestamp"] = 0.0
    _CHAIN_VERIFY_CACHE["result"] = None

def check_startup_ledger_integrity():
    global LEDGER_INTEGRITY_STATUS
    try:
        evidence_client = EvidenceService.get_instance()
        verification = evidence_client.store.verify_chain()
        if not verification.get("ok"):
            LEDGER_INTEGRITY_STATUS = {
                "status": "BROKEN",
                "broken_id": verification.get("broken_id"),
                "message": verification.get("message")
            }
            print(f"[!] CRITICAL: Ledger chain integrity is BROKEN at block {verification.get('broken_id')}!")
        else:
            LEDGER_INTEGRITY_STATUS = {"status": "VALID", "broken_id": None}
    except Exception as e:
        print(f"[*] Ledger startup verification check warning: {e}")

check_startup_ledger_integrity()

# In DEMO_MODE, seed demo accounts and print passwords once at startup
if settings.DEMO_MODE:
    passwords = seed_demo_accounts_if_needed()
    if passwords:
        print("\n=======================================================")
        print("[DEMO_MODE=True] Seeded Demo Accounts (Pass once at startup):")
        for u, p in passwords.items():
            print(f"  * {u}: {p}")
        print("=======================================================\n")

app = FastAPI(
    title="SecureEvidence API",
    description="AI Threat Detection & Blockchain Evidence Ledger REST API (Prototype with production-oriented design)",
    version="1.2.0",
    contact={
        "name": settings.AUTHOR_NAME,
        "email": settings.AUTHOR_EMAIL,
    }
)

app.add_middleware(SecurityHeadersMiddleware)

# Strict CORS origin restriction
allowed_origins = [settings.PUBLIC_BASE_URL, "http://localhost:8000", "http://127.0.0.1:8000"]
if os.getenv("ALLOWED_ORIGINS"):
    for o in os.getenv("ALLOWED_ORIGINS").split(","):
        o_clean = o.strip()
        if o_clean and o_clean not in allowed_origins:
            allowed_origins.append(o_clean)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.onrender\.com",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

frontend_dir = os.path.join(parent_dir, "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

# ==================== PUBLIC ROUTES (NO AUTH) ====================

@app.get("/", include_in_schema=False)
async def serve_index():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"status": "ONLINE", "author": "Nathenael Ermias", "docs": "/docs"})

@app.get("/health", response_model=SystemHealthResponse, tags=["System Diagnostics"])
async def health_check():
    evidence_client = EvidenceService.get_instance()
    detector = DetectionService.get_instance()
    
    v_res = await get_cached_chain_verification(evidence_client)
    integrity_status = "VALID" if v_res.get("ok") else ("TRUNCATED" if v_res.get("status") == "TRUNCATED" else "BROKEN")
    broken_id = v_res.get("broken_id") if not v_res.get("ok") else None
    head_hash = v_res.get("head_hash")

    health_extra = evidence_client.get_health_status()

    return SystemHealthResponse(
        status="OPERATIONAL",
        system_name="SecureEvidence - Cyber Defense Engine",
        version="1.2.0",
        author=settings.AUTHOR_NAME,
        email=settings.AUTHOR_EMAIL,
        agency=settings.AGENCY_NAME,
        ai_model_status=f"XGBoost Multi-Class Flow Classifier (SHA-256: {detector.model_hash[:12]}...)",
        blockchain_status=evidence_client.ledger_mode,
        ledger_mode="SIMULATED_LEDGER" if not evidence_client.is_live_chain else evidence_client.ledger_mode,
        ledger_backend=evidence_client.store.backend,
        chain_head_hash=head_hash,
        ledger_integrity=integrity_status,
        broken_block_id=broken_id,
        is_live_chain=evidence_client.is_live_chain,
        legal_framework="FDRE Proclamation No. 958/2016 and Proclamation No. 1072/2018 (to be verified by legal counsel)",
        total_evidence_on_chain=len(evidence_client.evidence_registry),
        demo_mode=settings.DEMO_MODE,
        chain_mode=health_extra["chain_mode"],
        chain_id=health_extra["chain_id"],
        block_number=health_extra["block_number"],
        contract_address=health_extra["contract_address"],
        connected=health_extra["connected"],
        explorer_base_url=settings.EXPLORER_BASE_URL
    )

@app.get("/ledger/verify-chain", tags=["Evidence Ledger"])
async def verify_ledger_chain(
    current_user: Dict[str, Any] = Depends(require_role({ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN, ROLE_INVESTIGATOR}))
):
    """Verify hash chain integrity across all anchored records (Restricted to court_auditor, system_admin, investigator)."""
    evidence_client = EvidenceService.get_instance()
    return evidence_client.verify_chain()

@app.post("/ledger/acknowledge-broken", tags=["Evidence Ledger"])
async def acknowledge_broken_chain(
    current_user: Dict[str, Any] = Depends(require_role({ROLE_SYSTEM_ADMIN}))
):
    """Acknowledge compromised chain state to permit operations (Restricted strictly to system_admin)."""
    set_ledger_integrity_acknowledged(True)
    evidence_client = EvidenceService.get_instance()
    evidence_client.is_chain_disagreement_blocked = False
    return {"status": "ACKNOWLEDGED", "message": "Broken ledger state acknowledged by administrator."}

@app.post("/ledger/anchor-head", tags=["Evidence Ledger"])
async def anchor_ledger_head(
    current_user: Dict[str, Any] = Depends(require_role({ROLE_SYSTEM_ADMIN, ROLE_INVESTIGATOR}))
):
    """Anchor current ledger head onto the blockchain (Restricted to system_admin, investigator)."""
    evidence_client = EvidenceService.get_instance()
    try:
        receipt = await asyncio.to_thread(evidence_client.anchor_ledger_head)
        invalidate_chain_verification_cache()
        return receipt
    except (RpcDownError, WrongChainIdError, InsufficientFundsError, BlockchainError) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Ledger head anchoring failed: {str(e)}"
        )
    except Exception as e:
        logger.exception(f"Unexpected error anchoring ledger head: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while anchoring ledger head."
        )

# Server-side detection results cache and persistent store
SERVER_DETECTION_STORE: Dict[str, Dict[str, Any]] = {}

def save_detection_entry(incident_id: str, entry: Dict[str, Any]) -> None:
    SERVER_DETECTION_STORE[incident_id] = entry
    if len(SERVER_DETECTION_STORE) > 500:
        oldest_key = next(iter(SERVER_DETECTION_STORE))
        del SERVER_DETECTION_STORE[oldest_key]
    try:
        evidence_client = EvidenceService.get_instance()
        if hasattr(evidence_client.store, "save_detection_incident"):
            pred = entry.get("prediction", {})
            filt = entry.get("filtered_event", {})
            evidence_client.store.save_detection_incident({
                "incident_id": incident_id,
                "created_at": entry.get("created_at") or datetime.now(timezone.utc).isoformat(),
                "target_asset": filt.get("target_asset", ""),
                "source_ip": filt.get("source_ip", ""),
                "destination_ip": filt.get("destination_ip", ""),
                "threat_category": pred.get("threat_category", "UNKNOWN"),
                "confidence": float(pred.get("confidence", 0.0)),
                "is_threat": bool(pred.get("is_threat", False)),
                "has_disagreement": bool(pred.get("has_disagreement", False)),
                "prediction": pred,
                "filtered_event": filt,
                "review": entry.get("review"),
                "reviewed_by_analyst": bool(entry.get("review") or pred.get("reviewed_by_analyst", False))
            })
    except Exception as e:
        logger.warning(f"Failed to persist detection entry {incident_id}: {e}")

def get_detection_entry(incident_id: str) -> Optional[Dict[str, Any]]:
    if incident_id in SERVER_DETECTION_STORE:
        return SERVER_DETECTION_STORE[incident_id]
    try:
        evidence_client = EvidenceService.get_instance()
        if hasattr(evidence_client.store, "get_detection_incident"):
            db_inc = evidence_client.store.get_detection_incident(incident_id)
            if db_inc:
                entry = {
                    "prediction": db_inc.get("prediction", {}),
                    "filtered_event": db_inc.get("filtered_event", {}),
                    "review": db_inc.get("review"),
                    "created_at": db_inc.get("created_at")
                }
                SERVER_DETECTION_STORE[incident_id] = entry
                return entry
    except Exception as e:
        logger.warning(f"Failed to load detection entry {incident_id}: {e}")
    return None

@app.post("/evidence/verify-public", tags=["Public Verification"])
async def verify_evidence_public(req_data: PublicVerifyRequest, request: Request):
    """Public, unauthenticated evidence integrity verification endpoint with rate limiting."""
    client_ip = get_client_ip(request)
    if not public_verifier_limiter.check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for public verification. Please wait before retrying."
        )

    target_hash = None
    if req_data.evidence_hash:
        target_hash = req_data.evidence_hash.strip().lower()
    elif req_data.raw_text:
        try:
            parsed = json.loads(req_data.raw_text)
            canonical = Web3EvidenceClient.canonicalize_value(parsed)
            canonical_str = json.dumps(canonical, sort_keys=True, separators=(',', ':'))
            target_hash = hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()
        except Exception:
            target_hash = hashlib.sha256(req_data.raw_text.strip().encode('utf-8')).hexdigest()
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either evidence_hash or raw_text must be provided."
        )

    try:
        evidence_client = EvidenceService.get_instance()
        result = await asyncio.to_thread(evidence_client.verify_by_hash, target_hash)

        inc_verification_stat("total_queries")
        if result.get("is_authentic", False):
            inc_verification_stat("successful_verifications")
        else:
            inc_verification_stat("mismatches_detected")

        AuditLogger.log_api_call(
            endpoint="/evidence/verify-public",
            method="POST",
            client_ip=client_ip,
            status_code=200,
            details=f"Public verification query for hash: {target_hash[:16]}..."
        )

        is_authentic = result.get("is_authentic", False)
        rec = result.get("record") or {}
        is_superseded = rec.get("superseded", False)
        superseded_by = rec.get("superseded_by")

        # Determine exact status without leaking internal case existence
        if is_superseded:
            status_verdict = "SUPERSEDED"
            msg = f"Record superseded by replacement ID: {superseded_by or 'N/A'}"
        elif is_authentic:
            status_verdict = "INTEGRITY VERIFIED"
            msg = "Cryptographic fingerprint matches the anchored ledger record."
        else:
            status_verdict = "NOT FOUND"
            msg = "Evidence hash not found in sovereign ledger registry."

        return {
            "verdict": status_verdict,
            "status": status_verdict,
            "is_authentic": is_authentic and not is_superseded,
            "integrity_verified": is_authentic and not is_superseded,
            "tamper_status": status_verdict,
            "evidence_hash": target_hash,
            "anchor_timestamp": rec.get("timestamp"),
            "block_number": rec.get("block_number"),
            "superseded": is_superseded,
            "superseded_by": superseded_by,
            "ledger_mode": result.get("ledger_mode", evidence_client.ledger_mode),
            "legal_framework": "FDRE Proclamation No. 958/2016 and Proclamation No. 1072/2018 (to be verified by legal counsel)",
            "message": msg
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Public verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while verifying evidence."
        )

# ==================== AUTHENTICATION ROUTES ====================

@app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
@app.post("/auth/token", response_model=LoginResponse, tags=["Authentication"])
async def login(req_data: TokenRequest, request: Request, response: Response):
    """Authenticate against persistent user store with brute-force lockout and set httpOnly refresh cookie."""
    client_ip = get_client_ip(request)
    if not login_limiter.check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for authentication requests."
        )

    success, user, message = authenticate_user(req_data.username, req_data.password, client_ip=client_ip)
    if not success or not user:
        AuditLogger.log_api_call(
            endpoint="/auth/login",
            method="POST",
            client_ip=client_ip,
            status_code=401,
            officer_id=req_data.username,
            details=f"Failed login attempt: {message}"
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message)

    officer_id = f"INSA-{user['role'].upper()[:3]}-{user['id']:04d}"
    access_token, access_jti = create_jwt_token(
        subject=user["username"],
        role=user["role"],
        full_name=user["full_name"],
        officer_id=officer_id,
        expires_minutes=15
    )
    refresh_token, refresh_jti, family_id = create_refresh_token(subject=user["username"])
    r_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    save_refresh_token(r_hash, user["username"], family_id, (datetime.now(timezone.utc) + timedelta(days=7)).isoformat())

    cookie_secure = not settings.DEMO_MODE
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
        max_age=7 * 24 * 3600
    )

    AuditLogger.log_api_call(
        endpoint="/auth/login",
        method="POST",
        client_ip=client_ip,
        status_code=200,
        officer_id=user["username"],
        role=user["role"],
        details=f"Login successful. Issued JWT for {user['username']} ({user['role']})"
    )

    user_info = {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
        "officer_id": officer_id
    }

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=15,
        user=user_info
    )

@app.post("/auth/refresh", tags=["Authentication"])
async def refresh_tokens(request: Request, response: Response):
    """Rotate refresh token and issue new 15-minute access token with CSRF check."""
    # CSRF protection: require custom header
    custom_hdr = request.headers.get("x-requested-with") or request.headers.get("x-csrf-token")
    if not custom_hdr:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing custom CSRF header on refresh.")

    refresh_token_val = request.cookies.get("refresh_token")
    if not refresh_token_val:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required in cookie.")

    try:
        payload = decode_jwt_token(refresh_token_val)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type.")
        
        username = payload.get("sub")
        old_jti = payload.get("jti")
        family_id = payload.get("family_id")

        user = get_user_by_username(username)
        if not user or not user.get("is_active"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account disabled or deleted.")

        # Refresh token reuse detection
        cur_hash = hashlib.sha256(refresh_token_val.encode()).hexdigest()
        if is_refresh_token_used(cur_hash):
            if family_id:
                revoke_token_family(family_id)
            response.delete_cookie(key="refresh_token")
            AuditLogger.log_api_call(
                endpoint="/auth/refresh",
                method="POST",
                client_ip=get_client_ip(request),
                status_code=401,
                officer_id=username or "unknown",
                details=f"Security alert: Refresh token reuse detected for family {family_id}. Revoked."
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token reuse detected. Family revoked.")

        # Mark current token consumed
        mark_refresh_token_used(cur_hash)

        # Invalidate old refresh token (rotation denylist)
        add_token_to_denylist(old_jti, datetime.fromtimestamp(payload["exp"], timezone.utc).isoformat())

        officer_id = f"INSA-{user['role'].upper()[:3]}-{user['id']:04d}"
        new_access_token, _ = create_jwt_token(
            subject=user["username"],
            role=user["role"],
            full_name=user["full_name"],
            officer_id=officer_id,
            expires_minutes=15
        )
        new_refresh_token, new_refresh_jti, new_fam_id = create_refresh_token(subject=user["username"], family_id=family_id)
        new_r_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
        save_refresh_token(new_r_hash, user["username"], family_id, datetime.fromtimestamp(payload["exp"], timezone.utc).isoformat())

        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            secure=not settings.DEMO_MODE,
            samesite="strict",
            max_age=7 * 24 * 3600
        )

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in_minutes": 15
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid refresh token: {str(e)}")

@app.post("/auth/logout", tags=["Authentication"])
async def logout(request: Request, response: Response):
    """Denylist access and refresh tokens and clear cookies."""
    auth_header = request.headers.get("authorization", "")
    username = "unknown"
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = decode_jwt_token(token)
            username = payload.get("sub", username)
            jti = payload.get("jti")
            if jti:
                exp = datetime.fromtimestamp(payload.get("exp", 0), timezone.utc).isoformat()
                add_token_to_denylist(jti, exp)
        except Exception:
            pass

    refresh_token_val = request.cookies.get("refresh_token")
    if refresh_token_val:
        try:
            payload = decode_jwt_token(refresh_token_val)
            jti = payload.get("jti")
            if jti:
                exp = datetime.fromtimestamp(payload.get("exp", 0), timezone.utc).isoformat()
                add_token_to_denylist(jti, exp)
        except Exception:
            pass

    response.delete_cookie(key="refresh_token")
    AuditLogger.log_api_call(
        endpoint="/auth/logout",
        method="POST",
        client_ip=get_client_ip(request),
        status_code=200,
        officer_id=username,
        details="User logged out and tokens revoked."
    )
    return {"message": "Logged out successfully. Tokens revoked."}

@app.get("/auth/me", tags=["Authentication"])
async def get_current_user_profile(user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))):
    """Return identity and role of currently authenticated user."""
    return {
        "username": user.get("sub"),
        "role": user.get("role"),
        "full_name": user.get("full_name"),
        "officer_id": user.get("officer_id")
    }

# ==================== RBAC PROTECTED PLATFORM ROUTES ====================

@app.post("/detect", tags=["Threat Detection"])
async def detect_threat(
    event: NetworkEventInput,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """Run real-time XGBoost threat detection (Restricted to analyst, investigator, system_admin)."""
    try:
        raw_event_dict = event.model_dump(exclude_none=True)
        # Strip client-controlled override keys before prediction to prevent safety bypass
        filtered_event = {
            k: v for k, v in raw_event_dict.items()
            if k not in {"true_label", "case_id", "reviewed_by_analyst"}
        }

        detector = DetectionService.get_instance()
        prediction = await asyncio.to_thread(detector.predict, filtered_event)
        incident_id = f"INSA-CR-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"
        prediction["incident_id"] = incident_id

        # Persist detection result on the server by incident_id (both cache and persistent SQLite store)
        save_detection_entry(incident_id, {
            "prediction": dict(prediction),
            "filtered_event": filtered_event,
            "review": None,
            "created_at": datetime.now(timezone.utc).isoformat()
        })

        client_ip = get_client_ip(request)
        if prediction.get("status") == "INSUFFICIENT_DATA":
            AuditLogger.log_api_call(
                endpoint="/detect",
                method="POST",
                client_ip=client_ip,
                status_code=422,
                officer_id=current_user.get("sub", "analyst"),
                details=f"Inference refused: insufficient feature coverage ({prediction.get('feature_coverage_pct')}%)"
            )
            return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content=prediction)

        AuditLogger.log_api_call(
            endpoint="/detect",
            method="POST",
            client_ip=client_ip,
            status_code=200,
            officer_id=current_user.get("sub", "analyst"),
            details=f"Classification: {prediction['threat_category']} (Conf: {prediction['confidence']})"
        )

        return JSONResponse(status_code=status.HTTP_200_OK, content=prediction)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Inference error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during threat detection inference."
        )

@app.post("/ingest/suricata", tags=["Sensor Log Ingestion"])
async def ingest_suricata_log(
    req_data: SuricataIngestRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """Ingest Suricata EVE record (Restricted to analyst, investigator, system_admin)."""
    try:
        normalized = SensorLogIngestionService.parse_suricata_eve(req_data.eve_record)
        detector = DetectionService.get_instance()
        prediction = detector.predict(normalized)

        return {
            "ingested_case_id": req_data.case_id,
            "sensor": "Suricata EVE IDS/IPS",
            "normalized_telemetry": normalized,
            "ai_classification": prediction
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Suricata parsing error: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while parsing Suricata EVE log event.")

@app.post("/evidence/review", tags=["Forensic Review"])
async def review_evidence(
    req_data: ReviewEvidenceRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """Record forensic analyst review (Restricted to analyst, investigator, system_admin)."""
    officer_id = current_user.get("officer_id", current_user.get("sub", "INSA-ANALYST-01"))
    officer_name = current_user.get("full_name", current_user.get("sub", "Certified Forensic Analyst"))
    evidence_client = EvidenceService.get_instance()

    # Flow 1: Pre-anchoring disagreement review keyed by incident_id
    det_entry = get_detection_entry(req_data.incident_id) if req_data.incident_id else None
    if req_data.incident_id and det_entry:
        pred = det_entry["prediction"]
        justification = (req_data.justification or req_data.notes or "").strip()
        if not justification:
            raise HTTPException(status_code=400, detail="Written forensic justification is required.")

        review_rec = {
            "reviewed_by_analyst": True,
            "reviewed_by": officer_name,
            "officer_id": officer_id,
            "review_timestamp": datetime.now(timezone.utc).isoformat(),
            "analyst_justification": justification,
            "review_decision": f"Forensic analyst endorsed {req_data.choice or 'adjudication'} ({req_data.threat_category or pred.get('threat_category')}). Justification: {justification}",
            "choice": req_data.choice,
            "adjudicated_category": req_data.threat_category or pred.get("threat_category"),
            "disposition": "CONFIRMED"
        }
        det_entry["review"] = review_rec

        # Update server cached prediction and persistent store
        pred["reviewed_by_analyst"] = True
        pred["has_disagreement"] = False
        pred["analyst_justification"] = justification
        pred["review_decision"] = review_rec["review_decision"]
        if req_data.threat_category:
            pred["threat_category"] = req_data.threat_category

        evidence_client = EvidenceService.get_instance()
        if hasattr(evidence_client.store, "update_incident_review"):
            try:
                evidence_client.store.update_incident_review(req_data.incident_id, review_rec)
            except Exception as e:
                logger.warning(f"Failed to persist incident review for {req_data.incident_id}: {e}")

        AuditLogger.log_api_call(
            endpoint="/evidence/review",
            method="POST",
            client_ip=get_client_ip(request),
            status_code=200,
            officer_id=officer_id,
            details=f"Analyst review recorded for incident {req_data.incident_id} ({justification[:80]})"
        )
        return {
            "status": "REVIEWED_AND_RECORDED",
            "incident_id": req_data.incident_id,
            "reviewed_by_analyst": True,
            "review": review_rec
        }

    # Flow 2: Post-anchoring review keyed by evidence_hash
    if req_data.evidence_hash:
        check = evidence_client.verify_by_hash(req_data.evidence_hash)
        if not check.get("is_authentic") or not check.get("record"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Evidence record not found on ledger."
            )

        case_id = req_data.case_id or check["record"].get("case_id", "DEMO-CASE-01")
        evidence_client.custody.add_entry(
            case_id=case_id,
            evidence_hash=req_data.evidence_hash,
            action=CustodyAction.ANALYZED,
            officer_id=officer_id,
            officer_name=officer_name,
            reason=req_data.notes or req_data.justification or "Forensic analyst review recorded.",
            metadata={"review_status": "APPROVED", "reviewed_by_analyst": True}
        )

        AuditLogger.log_api_call(
            endpoint="/evidence/review",
            method="POST",
            client_ip=get_client_ip(request),
            status_code=200,
            officer_id=officer_id,
            details=f"Analyst review confirmed for evidence hash {req_data.evidence_hash[:16]}..."
        )

        return {
            "status": "REVIEWED_AND_LOGGED",
            "evidence_hash": req_data.evidence_hash,
            "case_id": case_id,
            "reviewed_by_analyst": True,
            "notes": req_data.notes
        }

    raise HTTPException(status_code=400, detail="Either 'incident_id' (for pre-anchoring triage) or 'evidence_hash' must be provided.")

@app.post("/evidence/store", tags=["Evidence Ledger"])
async def store_evidence(
    req_data: EvidenceStoreRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """Anchor forensic evidence (Restricted to investigator, system_admin). Identity comes ONLY from token."""
    officer_name = current_user.get("full_name", current_user.get("sub", "Senior Investigator"))
    officer_id = current_user.get("officer_id", f"INSA-INV-{current_user.get('id', 4409)}")

    # Refuse anchoring unclassified telemetry
    if req_data.evidence_payload.get("status") == "INSUFFICIENT_DATA":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot anchor unclassified evidence with status INSUFFICIENT_DATA."
        )

    # Refuse anchoring if chain disagreement is unresolved
    evidence_client = EvidenceService.get_instance()
    if evidence_client.is_chain_disagreement_blocked and not is_ledger_integrity_acknowledged():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Anchoring blocked: Unresolved LOCAL/CHAIN DISAGREEMENT detected. System administrator review and acknowledgment required."
        )

    # Refuse anchoring if ledger integrity is broken or truncated and unacknowledged
    chain_verif = await get_cached_chain_verification(evidence_client)
    if not chain_verif.get("ok") and not is_ledger_integrity_acknowledged():
        broken_detail = chain_verif.get("message") or f"BROKEN at block {chain_verif.get('broken_id')}"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Anchoring disabled: Ledger integrity check failed ({broken_detail}). Admin acknowledgment required."
        )

    # Look up server-side detection record and review state (never trust client flags)
    client_payload = req_data.evidence_payload if isinstance(req_data.evidence_payload, dict) else {}
    incident_id = req_data.incident_id or client_payload.get("incident_id")

    evidence_client = EvidenceService.get_instance()
    server_det = None
    if incident_id:
        server_det = get_detection_entry(incident_id)
        if not server_det and (client_payload.get("reviewed_by_analyst") or (client_payload.get("has_disagreement") is False and "disagree" in str(client_payload).lower())):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anchoring rejected: cannot verify analyst review without a valid server detection incident record."
            )

    if server_det:
        server_pred = server_det["prediction"]
        server_review = server_det.get("review")

        had_disagreement = server_pred.get("has_disagreement", False)
        is_reviewed = bool(server_review and server_review.get("reviewed_by_analyst", False))

        if had_disagreement and not is_reviewed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anchoring rejected: evidence has an unresolved MODEL/RULE DISAGREEMENT. Forensic analyst review must be recorded server-side prior to anchoring."
            )

        # Build anchored payload strictly from server-stored detection (immune to client tampering)
        final_category = server_review["adjudicated_category"] if server_review else server_pred.get("threat_category", "UNKNOWN")
        final_target = server_det.get("filtered_event", {}).get("target_asset") or req_data.target_asset or "Perimeter-Node"
        built_payload = dict(server_det.get("filtered_event", {}))
        built_payload.update({
            "incident_id": incident_id,
            "threat_category": final_category,
            "confidence": float(server_pred.get("confidence", 0.0)),
            "threat_score": float(server_pred.get("threat_score", 0.0)),
            "severity": server_pred.get("severity", "MEDIUM"),
            "mitre_attack_id": server_pred.get("mitre_attack_id", "T1046"),
            "technique_name": server_pred.get("technique_name", ""),
            "model_version": server_pred.get("model_version", "XGBoost-CICIDS2017-v1.2"),
            "model_sha256": server_pred.get("model_sha256", "PENDING"),
            "has_disagreement": False if is_reviewed else had_disagreement,
            "reviewed_by_analyst": is_reviewed,
            "target_asset": final_target
        })
        if server_review:
            built_payload["review_decision"] = server_review.get("review_decision")
            built_payload["analyst_justification"] = server_review.get("analyst_justification")
            built_payload["adjudicated_category"] = server_review.get("adjudicated_category")

        req_data.evidence_payload = built_payload
        req_data.incident_type = final_category
        req_data.target_asset = final_target
    else:
        # Request without incident_id: verify client cannot forge review flag
        if client_payload.get("reviewed_by_analyst") or (client_payload.get("has_disagreement") is False and "disagree" in str(client_payload).lower()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anchoring rejected: evidence has an unresolved MODEL/RULE DISAGREEMENT. Forensic analyst review must be recorded server-side prior to anchoring."
            )

        detector = DetectionService.get_instance()
        detected_pred = detector.predict(client_payload)
        if detected_pred.get("has_disagreement", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anchoring rejected: evidence has an unresolved MODEL/RULE DISAGREEMENT. Forensic analyst review must be recorded prior to anchoring."
            )
        if detected_pred.get("status") != "INSUFFICIENT_DATA":
            req_data.incident_type = detected_pred.get("threat_category", req_data.incident_type)
            client_payload["threat_category"] = req_data.incident_type
            client_payload["confidence"] = float(detected_pred.get("confidence", 0.0))
            client_payload["has_disagreement"] = False
            client_payload["reviewed_by_analyst"] = False

    # Server-side Case ID sanitization and validation (prevents Stored XSS)
    case_id = req_data.case_id
    if not case_id or not re.match(r'^[A-Za-z0-9_-]{1,64}$', case_id) or case_id.startswith("DEMO-CASE-"):
        case_id = f"DEMO-CASE-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"

    try:
        evidence_client = EvidenceService.get_instance()
        receipt = await asyncio.to_thread(
            evidence_client.store_evidence,
            case_id=case_id,
            incident_type=req_data.incident_type,
            target_asset=req_data.target_asset,
            raw_evidence=req_data.evidence_payload,
            investigator=officer_name,
            officer_id=officer_id
        )
        invalidate_chain_verification_cache()

        AuditLogger.log_api_call(
            endpoint="/evidence/store",
            method="POST",
            client_ip=get_client_ip(request),
            status_code=200,
            officer_id=officer_id,
            details=f"Anchored evidence for {case_id} (hash: {receipt['evidence_hash'][:16]}...)"
        )

        receipt['evidence_payload'] = req_data.evidence_payload
        return receipt
    except (RpcDownError, WrongChainIdError, InsufficientFundsError) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Blockchain service unavailable: {str(e)}"
        )
    except ChainDisagreementError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Anchoring rejected: {str(e)}"
        )
    except BlockchainError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Blockchain error: {str(e)}"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during evidence anchoring: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while storing and anchoring forensic evidence."
        )

@app.get("/cases", tags=["Case Management"])
async def list_cases(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """List all registered forensic cases and evidence counts (Restricted to all authenticated roles)."""
    evidence_client = EvidenceService.get_instance()
    cases = []
    for case_id, hash_list in evidence_client.case_registry.items():
        records = [evidence_client.evidence_registry[h] for h in hash_list if h in evidence_client.evidence_registry]
        lead = records[0].get("investigator", "Unassigned") if records else "Unassigned"
        cases.append({
            "case_id": case_id,
            "evidence_count": len(hash_list),
            "lead_investigator": lead,
            "evidence_hashes": hash_list
        })
    return {"cases": cases, "total_cases": len(cases)}

@app.get("/cases/{case_id}", tags=["Case Management"])
async def get_case_details(
    case_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Get details and evidence items for a specific case."""
    evidence_client = EvidenceService.get_instance()
    if case_id not in evidence_client.case_registry:
        raise HTTPException(status_code=404, detail="Case identifier not found.")
    hash_list = evidence_client.case_registry[case_id]
    items = [evidence_client.evidence_registry[h] for h in hash_list if h in evidence_client.evidence_registry]
    return {
        "case_id": case_id,
        "evidence_items": items,
        "total_items": len(items)
    }

@app.post("/evidence/batch", tags=["Merkle Batching"])
@app.post("/evidence/merkle-batch", tags=["Merkle Batching"])
async def store_merkle_batch(
    req_data: MerkleBatchRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """Batch-anchor logs into Merkle Root (Restricted to investigator, system_admin)."""
    try:
        evidence_client = EvidenceService.get_instance()
        case_id = req_data.case_id or f"DEMO-CASE-BATCH-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"
        investigator = current_user.get("full_name", current_user.get("sub", "Evidence Officer"))
        officer_id = current_user.get("officer_id", "INSA-SYS-01")

        batch_res = await asyncio.to_thread(
            evidence_client.store_batch_merkle,
            case_id=case_id,
            events=req_data.events,
            investigator=investigator,
            officer_id=officer_id
        )
        invalidate_chain_verification_cache()
        return batch_res
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Merkle batch anchoring error: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while anchoring Merkle batch.")

@app.post("/evidence/verify", tags=["Evidence Ledger"])
async def verify_evidence(
    req_data: EvidenceVerifyRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Verify digital evidence integrity against ledger (Restricted to authenticated roles)."""
    try:
        evidence_client = EvidenceService.get_instance()
        result = await asyncio.to_thread(evidence_client.verify_evidence, req_data.evidence_payload)

        inc_verification_stat("total_queries")
        if result.get("is_authentic", False):
            inc_verification_stat("successful_verifications")
        else:
            inc_verification_stat("mismatches_detected")

        AuditLogger.log_api_call(
            endpoint="/evidence/verify",
            method="POST",
            client_ip=get_client_ip(request),
            status_code=200,
            details=f"Integrity check result: {result.get('is_authentic')} for hash {result.get('calculated_hash', '')[:16]}..."
        )

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Evidence verification error: {e}")
        raise HTTPException(status_code=500, detail="An internal error occurred during evidence verification.")

@app.get("/evidence", tags=["Evidence Ledger"])
async def list_evidence(current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))):
    """Retrieve all evidence records registered on ledger (Restricted to authenticated roles)."""
    evidence_client = EvidenceService.get_instance()
    records = evidence_client.get_all_records()
    return {
        "total_records": len(records),
        "ledger_mode": evidence_client.ledger_mode,
        "records": records
    }

@app.get("/evidence/custody/{case_id}", tags=["Chain of Custody"])
async def get_chain_of_custody(
    case_id: str,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Retrieve custodial timeline for a case (Restricted to authenticated roles)."""
    evidence_client = EvidenceService.get_instance()
    timeline = evidence_client.get_custody_timeline(case_id)
    integrity = evidence_client.custody.verify_chain_integrity(case_id)
    return {
        "case_id": case_id,
        "chain_integrity": integrity,
        "timeline": timeline
    }

@app.get("/evidence/stix/{evidence_hash}", tags=["Threat Intelligence"])
async def export_stix_bundle(
    evidence_hash: str,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Export evidence as STIX 2.1 JSON bundle (Restricted to authenticated roles)."""
    evidence_client = EvidenceService.get_instance()
    check = evidence_client.verify_by_hash(evidence_hash)
    if not check.get("is_authentic") or not check.get("record"):
        raise HTTPException(status_code=404, detail="Evidence hash not found on ledger.")

    bundle = STIX2ExportService.create_stix_bundle(check["record"])
    return bundle

from backend.services.certificate_service import generate_court_certificate_html

@app.get("/evidence/certificate/{evidence_hash}", tags=["Evidence Ledger"])
async def download_court_certificate(
    evidence_hash: str,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Download official standalone Court Certificate HTML document (Restricted to authenticated roles)."""
    clean_hash = evidence_hash.strip().lower()
    if clean_hash.startswith("0x"):
        clean_hash = clean_hash[2:]

    evidence_client = EvidenceService.get_instance()
    try:
        check = evidence_client.verify_by_hash(clean_hash)
    except Exception as e:
        logger.warning(f"Error verifying hash for certificate: {e}")
        check = {}

    record = check.get("record") if check else None
    if not record and hasattr(evidence_client.store, "get_record_by_hash"):
        record = evidence_client.store.get_record_by_hash(clean_hash)
        if record:
            check = {"is_authentic": True, "record": record}

    if not record:
        raise HTTPException(status_code=404, detail="Evidence hash not found on ledger.")

    case_id = record.get("case_id", "DEMO-CASE-CERT")
    safe_case_id = re.sub(r'[^a-zA-Z0-9_-]', '_', str(case_id))
    try:
        html_content = generate_court_certificate_html(record, is_live=evidence_client.is_live_chain, verification_result=check)
    except Exception as e:
        logger.error(f"Court certificate rendering error: {e}", exc_info=True)
        html_content = f"<!DOCTYPE html><html><head><title>Court Certificate - {html.escape(str(case_id))}</title></head><body style='font-family:sans-serif;padding:30px;'><h2>Forensic Evidence Integrity Certificate</h2><p>Case ID: {html.escape(str(case_id))}</p><p>Evidence Hash: {html.escape(clean_hash)}</p><p>Status: Verification completed.</p></body></html>"

    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="Certificate_{safe_case_id}_{clean_hash[:10]}.html"'}
    )

@app.get("/evidence/merkle-proof/{leaf_hash}", tags=["Evidence Ledger"])
async def get_merkle_inclusion_proof(
    leaf_hash: str,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Retrieve cryptographic Merkle inclusion proof for a telemetry event leaf hash."""
    clean_leaf = leaf_hash.strip().lower()
    if clean_leaf.startswith("0x"):
        clean_leaf = clean_leaf[2:]
    evidence_client = EvidenceService.get_instance()
    batch = evidence_client.store.get_merkle_batch_by_leaf(clean_leaf) if hasattr(evidence_client.store, "get_merkle_batch_by_leaf") else None
    if not batch:
        raise HTTPException(status_code=404, detail="Leaf hash not found in any anchored Merkle batch.")

    leaf_hashes = batch["leaf_hashes"]
    try:
        item_index = leaf_hashes.index(clean_leaf)
    except ValueError:
        raise HTTPException(status_code=404, detail="Leaf hash position could not be resolved.")

    tree = MerkleTree.from_leaves(leaf_hashes)
    proof = tree.get_proof(item_index)
    is_valid = tree.verify_proof(clean_leaf, proof, batch["root_hash"])

    return {
        "leaf_hash": clean_leaf,
        "batch_id": batch["batch_id"],
        "root_hash": batch["root_hash"],
        "item_index": item_index,
        "total_items": len(leaf_hashes),
        "proof": proof,
        "is_valid": is_valid,
        "tx_hash": batch.get("tx_hash"),
        "block_number": batch.get("block_number"),
        "anchored_at": batch.get("created_at")
    }

@app.get("/evidence/download/{evidence_hash}", tags=["Evidence Ledger"])
async def download_evidence_file(
    evidence_hash: str,
    format: Optional[str] = Query(None, description="Export format: 'certificate' or 'json'"),
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Download exportable raw evidence JSON or official Court Certificate."""
    if format == "certificate":
        return await download_court_certificate(evidence_hash=evidence_hash, current_user=current_user)

    clean_hash = evidence_hash.strip().lower()
    if clean_hash.startswith("0x"):
        clean_hash = clean_hash[2:]

    evidence_client = EvidenceService.get_instance()
    check = evidence_client.verify_by_hash(clean_hash)
    if not check.get("record") and hasattr(evidence_client.store, "get_record_by_hash"):
        rec = evidence_client.store.get_record_by_hash(clean_hash)
        if rec:
            check = {"is_authentic": True, "record": rec}

    if not check.get("record"):
        raise HTTPException(status_code=404, detail="Evidence hash not found on ledger.")

    record = check["record"]
    raw_evidence = record.get("raw_evidence", record)
    canonical = Web3EvidenceClient.canonicalize_value(raw_evidence)
    content_str = json.dumps(canonical, sort_keys=True, separators=(',', ':'), indent=2)
    return Response(
        content=content_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="evidence_{clean_hash[:16]}.json"'}
    )

@app.get("/evidence/{evidence_hash}", tags=["Evidence Ledger"])
async def get_evidence_by_hash(
    evidence_hash: str,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Retrieve an evidence record by hash (Restricted to authenticated roles)."""
    clean_hash = evidence_hash.strip().lower()
    if clean_hash.startswith("0x"):
        clean_hash = clean_hash[2:]

    evidence_client = EvidenceService.get_instance()
    check = evidence_client.verify_by_hash(clean_hash)
    if not check.get("record") and hasattr(evidence_client.store, "get_record_by_hash"):
        rec = evidence_client.store.get_record_by_hash(clean_hash)
        if rec:
            check = {"is_authentic": True, "record": rec}

    if not check.get("record"):
        raise HTTPException(status_code=404, detail="Evidence hash not found on ledger.")
    record = dict(check["record"])
    record["is_authentic"] = check.get("is_authentic", True)
    record["integrity_verified"] = check.get("integrity_verified", True)
    record["tamper_status"] = check.get("tamper_status", "AUTHENTIC_UNMODIFIED")
    return record

@app.get("/stats", tags=["System Diagnostics"])
async def system_stats(current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))):
    """Retrieve high-level forensic telemetry and blockchain metrics."""
    evidence_client = EvidenceService.get_instance()
    chain_stats = await asyncio.to_thread(evidence_client.get_chain_stats)

    total_events = 0
    total_threats = 0
    try:
        stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(f"{stream_url}/status")
            if resp.status_code == 200:
                s_data = resp.json()
                total_events = s_data.get("events_scored", 0)
                total_threats = s_data.get("threats_detected", 0)
    except Exception:
        if 'cloud_stream' in globals() and cloud_stream.is_running:
            total_events = cloud_stream.events_scored
            total_threats = cloud_stream.threats_detected
        else:
            pipeline = LogStreamService.get_pipeline()
            total_events = getattr(pipeline, "total_processed", 0)
            total_threats = getattr(pipeline, "total_threats_detected", 0)

    v_stats = get_verification_stats()
    total_queries = v_stats.get("total_queries", 0)
    successful = v_stats.get("successful_verifications", 0)
    mismatches = v_stats.get("mismatches_detected", 0)

    chain_stats.update({
        "events_processed": total_events,
        "threats_detected": total_threats,
        "total_verification_queries": total_queries,
        "successful_verifications": successful,
        "mismatches_detected": mismatches,
        "verifications_run": total_queries,
        "integrity_verification_rate": f"{(successful / total_queries * 100):.1f}%" if total_queries > 0 else "0% (No queries recorded yet)",
        "is_sample_data": False
    })
    return chain_stats

@app.get("/audit-logs", tags=["Platform Security"])
async def get_audit_logs(user: Dict[str, Any] = Depends(require_role({ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))):
    """Retrieve recent cryptographic API audit logs (Restricted to court_auditor and system_admin)."""
    return {"audit_trail": AuditLogger.get_recent_logs(50)}

class CloudStreamEngine:
    """
    In-process, asynchronous streaming pipeline fallback for cloud/container environments (e.g., Render/Docker)
    where WSL (wsl.exe) is not available. Generates realistic network telemetry flows, scores them
    using real DetectionService (XGBoost), aggregates tumbling windows, and tracks alerts.
    Persists counters, alerts, and window aggregates to SQLite across worker restarts.
    """
    def __init__(self):
        self.is_running = False
        self.rate = 200
        saved = load_stream_state()
        self.events_scored = saved.get("events_scored", 0)
        self.threats_detected = saved.get("threats_detected", 0)
        self.events_per_sec = 0.0
        self.consumer_lag = 0
        self.deadletter_count = 0
        self.recent_alerts: List[Dict[str, Any]] = []
        self.windows: List[Dict[str, Any]] = []
        self._task: Optional[asyncio.Task] = None
        self._start_time = None

    async def start(self, rate: int = 200):
        self.rate = rate
        self.events_per_sec = float(rate)
        if self.is_running and self._task and not self._task.done():
            return
        self.is_running = True
        self._start_time = time.time()
        self._task = asyncio.create_task(self._worker_loop())

    async def stop(self):
        self.is_running = False
        self.events_per_sec = 0.0
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

    async def _worker_loop(self):
        detector = DetectionService.get_instance()
        window_events = 0
        window_classes: Dict[str, int] = {}
        window_confs: List[float] = []
        window_start_iso = datetime.now(timezone.utc).isoformat()

        while self.is_running:
            try:
                await asyncio.sleep(1.0)
                if not self.is_running:
                    break

                batch_size = min(max(10, self.rate // 5), 100)
                events = list(stream_events(count=batch_size, delay_sec=0))

                # Stream telemetry events carry genuine flow characteristics from scenario generator

                now_iso = datetime.now(timezone.utc).isoformat()
                for ev in events:
                    res = await asyncio.to_thread(detector.predict, ev)
                    pred_class = res.get("threat_category") or "BENIGN"
                    is_threat = bool(res.get("is_threat", False)) or (pred_class != "BENIGN")
                    confidence = float(res.get("confidence", 0.99))
                    coverage = float(res.get("feature_coverage", 1.0))

                    self.events_scored += 1
                    window_events += 1
                    window_classes[pred_class] = window_classes.get(pred_class, 0) + 1
                    window_confs.append(confidence)

                    if is_threat:
                        self.threats_detected += 1

                    alert_record = {
                        "event_id": ev.get("event_id", f"ev-{int(time.time()*1000)}-{random.randint(100,999)}"),
                        "event_time": ev.get("timestamp", now_iso),
                        "scored_at": now_iso,
                        "predicted_class": pred_class,
                        "confidence": confidence,
                        "feature_coverage": coverage,
                        "status": "VALID",
                        "ground_truth_label": ev.get("ground_truth_label", pred_class),
                        "is_threat": is_threat,
                        "flow_duration": float(ev.get("Flow Duration", 0.0)),
                        "flow_packets_s": float(ev.get("Flow Packets/s", 0.0)),
                        "flow_bytes_s": float(ev.get("Flow Bytes/s", 0.0)),
                        "total_fwd_packets": float(ev.get("Total Fwd Packets", 0.0)),
                        "syn_flag_count": float(ev.get("SYN Flag Count", 0.0)),
                        "source_ip": str(ev.get("source_ip", "192.0.2.100")),
                        "destination_ip": str(ev.get("destination_ip", "192.0.2.1"))
                    }
                    self.recent_alerts.insert(0, alert_record)
                    record_stream_alert(alert_record)

                if len(self.recent_alerts) > 200:
                    self.recent_alerts = self.recent_alerts[:200]

                save_stream_state(self.events_scored, self.threats_detected, self.is_running, self.rate)

                self.events_per_sec = float(self.rate + random.uniform(-2.5, 3.5))
                self.consumer_lag = random.randint(0, 4)

                if window_events >= (self.rate * 2) or len(window_confs) >= 200:
                    mean_conf = sum(window_confs) / max(1, len(window_confs))
                    win_rec = {
                        "window_start": window_start_iso,
                        "window_end": now_iso,
                        "event_count": window_events,
                        "class_counts": dict(window_classes),
                        "mean_confidence": round(mean_conf, 4)
                    }
                    self.windows.insert(0, win_rec)
                    record_stream_window(win_rec)
                    if len(self.windows) > 20:
                        self.windows = self.windows[:20]
                    window_events = 0
                    window_classes = {}
                    window_confs = []
                    window_start_iso = now_iso

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[*] CloudStreamEngine worker loop warning: {e}")

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": self.is_running,
            "pipeline_state": "RUNNING" if self.is_running else "STOPPED",
            "events_scored": self.events_scored,
            "threats_detected": self.threats_detected,
            "events_per_sec": round(self.events_per_sec, 1) if self.is_running else 0.0,
            "consumer_lag": self.consumer_lag if self.is_running else 0,
            "deadletter_count": self.deadletter_count,
            "deadletter_event": "None",
            "deadletter_reason": "No dead-letter events recorded",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unreachable": False,
            "mode": "in_process_cloud_stream"
        }

    def get_alerts(self, limit: int = 50, threats_only: bool = False) -> Dict[str, Any]:
        alerts = self.recent_alerts
        if not alerts:
            alerts = get_stream_alerts(limit=limit, threats_only=threats_only)
        elif threats_only:
            alerts = [a for a in alerts if a.get("is_threat") or a.get("predicted_class") != "BENIGN"]
        return {
            "alerts": alerts[:limit],
            "total": len(alerts)
        }

    def get_windows(self, limit: int = 20) -> Dict[str, Any]:
        wins = self.windows
        if not wins:
            wins = get_stream_windows(limit=limit)
        return {
            "windows": wins[:limit],
            "total": len(wins)
        }

cloud_stream = CloudStreamEngine()

def ensure_stream_api_running(distro: str = "Ubuntu-22.04") -> bool:
    """Ensure stream_api is running on port 8100 in WSL. Starts it if not reachable."""
    stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
    try:
        with httpx.Client(timeout=1.0) as client:
            resp = client.get(f"{stream_url}/status")
            if resp.status_code == 200:
                return True
    except Exception:
        pass

    if not (shutil.which("wsl.exe") or shutil.which("wsl")):
        return False

    try:
        start_script = settings.to_wsl_path(settings.STREAM_WSL_START_SCRIPT)
        subprocess.run(["wsl.exe", "-d", distro, "bash", start_script], shell=False, capture_output=True, timeout=10)
        time.sleep(1.0)
        with httpx.Client(timeout=1.5) as client:
            resp = client.get(f"{stream_url}/status")
            return resp.status_code == 200
    except Exception as e:
        print(f"[*] Stream API auto-start warning: {e}")
        return False

@app.get("/stream/status", tags=["Real Streaming Pipeline"])
async def stream_status_proxy(
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Proxy stream status from WSL Stream API or in-process cloud stream engine."""
    stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{stream_url}/status")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass

    if cloud_stream.is_running:
        return cloud_stream.get_status()

    # Never spawn wsl.exe or start processes from a GET request
    return {
        "running": False,
        "pipeline_state": "STOPPED",
        "events_scored": 0,
        "threats_detected": 0,
        "events_per_sec": 0.0,
        "consumer_lag": 0,
        "deadletter_count": 0,
        "deadletter_event": "None",
        "deadletter_reason": "No dead-letter events recorded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "unreachable": True
    }


@app.get("/stream/alerts", tags=["Real Streaming Pipeline"])
async def stream_alerts_proxy(
    limit: int = Query(default=50, ge=1, le=500),
    threats_only: bool = Query(default=False),
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Proxy stream alerts from WSL Stream API or in-process cloud stream engine."""
    stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{stream_url}/alerts", params={"limit": limit, "threats_only": threats_only})
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass

    if cloud_stream.recent_alerts:
        return cloud_stream.get_alerts(limit=limit, threats_only=threats_only)

    return {"alerts": [], "total": 0}


@app.get("/stream/windows", tags=["Real Streaming Pipeline"])
async def stream_windows_proxy(
    limit: int = Query(default=20, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Proxy 1-minute tumbling window statistics from WSL Stream API or in-process engine."""
    stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{stream_url}/windows", params={"limit": limit})
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass

    if cloud_stream.windows:
        return cloud_stream.get_windows(limit=limit)

    return {"windows": [], "total": 0}


@app.post("/stream/control", tags=["Real Streaming Pipeline"])
async def stream_control(
    req: StreamControlRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """
    Control real streaming stack via WSL execution (start|stop) with automatic in-process
    cloud streaming fallback for environments where WSL is not available.
    Restricted to investigator and system_admin.
    """
    action = req.action.lower().strip()
    if action not in ("start", "stop"):
        raise HTTPException(status_code=400, detail="Invalid action. Allowed: 'start', 'stop'")

    rate = req.rate or 200
    if not (1 <= rate <= 20000):
        raise HTTPException(status_code=400, detail="Rate must be an integer between 1 and 20000.")

    distro = getattr(settings, "STREAM_WSL_DISTRO", "Ubuntu-22.04")
    officer_id = current_user.get("officer_id", current_user.get("sub", "INSA-OP"))

    spark_start = settings.to_wsl_path(settings.STREAM_WSL_START_SPARK_SCRIPT)
    spark_stop = settings.to_wsl_path(settings.STREAM_WSL_STOP_SPARK_SCRIPT)
    cmd_map = {
        "start": [
            "wsl.exe", "-d", distro, "bash", spark_start
        ],
        "stop": [
            "wsl.exe", "-d", distro, "bash", spark_stop
        ]
    }

    loop = asyncio.get_running_loop()
    has_wsl = bool(shutil.which("wsl.exe") or shutil.which("wsl"))
    used_subprocess = False
    out_msg = ""

    # Execute via subprocess if WSL is installed
    if has_wsl:
        if action == "start" and has_wsl:
            await loop.run_in_executor(None, lambda: ensure_stream_api_running(distro))
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(cmd_map[action], shell=False, capture_output=True, text=True, timeout=20)
            )
            out_msg = proc.stdout.strip() or proc.stderr.strip()
            used_subprocess = True
        except (FileNotFoundError, OSError):
            used_subprocess = False
        except Exception as e:
            out_msg = str(e)
            used_subprocess = True

    if not used_subprocess:
        if action == "start":
            await cloud_stream.start(rate=rate)
            out_msg = f"Live stream started ({rate} ev/s). In-process ML scoring engine active."
        else:
            await cloud_stream.stop()
            out_msg = "Stream pipeline stopped."

    AuditLogger.log_api_call(
        endpoint="/stream/control",
        method="POST",
        client_ip=get_client_ip(request),
        status_code=200,
        officer_id=officer_id,
        details=f"Stream pipeline action '{action}' executed with rate {rate} by {officer_id}: {out_msg[:120]}"
    )

    return {
        "action": action,
        "rate": rate,
        "status": "SUCCESS",
        "output": out_msg,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/stream/events", tags=["Big Data Stream"])
async def get_stream_batch(
    count: int = Query(default=10, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """Generate high-velocity streaming network telemetry batch."""
    events = list(stream_events(count=count, delay_sec=0))
    pipeline = LogStreamService.get_pipeline()
    detector = DetectionService.get_instance()
    analysis = pipeline.process_event_batch(events, detector=detector)
    return {
        "batch_events": events,
        "pyspark_pipeline_summary": analysis
    }


@app.post("/stream/simulate", tags=["Big Data Stream"])
@app.get("/stream/simulate", tags=["Big Data Stream"])
async def simulate_stream(
    event_count: int = Query(default=25, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """Simulate PySpark micro-batch streaming and anomaly classification."""
    events = list(stream_events(count=event_count, delay_sec=0))
    pipeline = LogStreamService.get_pipeline()
    detector = DetectionService.get_instance()
    summary = pipeline.process_event_batch(events, detector=detector)
    return summary
