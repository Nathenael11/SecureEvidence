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
import subprocess
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
    get_verification_stats
)
from backend.security import (
    SecurityHeadersMiddleware,
    AuditLogger,
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
    description="INSA Cyber Threat AI Detection & Blockchain Evidence Ledger REST API (Prototype with production-oriented design)",
    version="1.2.0",
    contact={
        "name": settings.AUTHOR_NAME,
        "email": settings.AUTHOR_EMAIL,
    }
)

app.add_middleware(SecurityHeadersMiddleware)

# Strict CORS origin restriction
allowed_origins = [settings.PUBLIC_BASE_URL, "http://localhost:8000", "http://127.0.0.1:8000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
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
    
    v_res = evidence_client.verify_chain()
    integrity_status = "VALID" if v_res.get("ok") else ("TRUNCATED" if v_res.get("status") == "TRUNCATED" else "BROKEN")
    broken_id = v_res.get("broken_id") if not v_res.get("ok") else None
    head_hash = v_res.get("head_hash")

    health_extra = evidence_client.get_health_status()

    return SystemHealthResponse(
        status="OPERATIONAL",
        system_name="SecureEvidence - INSA Cyber Defense Engine",
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
        connected=health_extra["connected"]
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
    global LEDGER_INTEGRITY_ACKNOWLEDGED
    LEDGER_INTEGRITY_ACKNOWLEDGED = True
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
        receipt = evidence_client.anchor_ledger_head()
        return receipt
    except (RpcDownError, WrongChainIdError, InsufficientFundsError, BlockchainError) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Ledger head anchoring failed: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ledger head anchoring failed: {str(e)}"
        )

# Server-side detection results cache (bounded in-memory store keyed by incident_id)
SERVER_DETECTION_STORE: Dict[str, Dict[str, Any]] = {}

@app.post("/evidence/verify-public", tags=["Public Verification"])
async def verify_evidence_public(req_data: PublicVerifyRequest, request: Request):
    """Public, unauthenticated evidence integrity verification endpoint with rate limiting."""
    client_ip = request.client.host if request.client else "127.0.0.1"
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
        result = evidence_client.verify_by_hash(target_hash)

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

        # Perform genuine case ID lookup in ledger database for unverified raw text
        matched_case = False
        if req_data.raw_text and not is_authentic:
            extracted_case_id = None
            try:
                parsed_json = json.loads(req_data.raw_text)
                if isinstance(parsed_json, dict):
                    extracted_case_id = parsed_json.get("case_id") or parsed_json.get("incident_id")
            except Exception:
                m = re.search(r'["\']?(?:case_id|incident_id)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]+)', req_data.raw_text)
                if m:
                    extracted_case_id = m.group(1)

            if extracted_case_id:
                case_records = evidence_client.store.get_records_by_case(extracted_case_id)
                if case_records:
                    matched_case = True

        # Determine exact status among the 4 required states:
        if is_superseded:
            status_verdict = "SUPERSEDED"
            msg = f"Record superseded by replacement ID: {superseded_by or 'N/A'}"
        elif is_authentic:
            status_verdict = "INTEGRITY VERIFIED"
            msg = "Cryptographic fingerprint matches the anchored ledger record."
        elif matched_case:
            status_verdict = "HASH MISMATCH"
            msg = "Record found by ID but calculated evidence hash does not match anchored ledger digest."
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
        raise HTTPException(status_code=500, detail=str(e))

# ==================== AUTHENTICATION ROUTES ====================

@app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
@app.post("/auth/token", response_model=LoginResponse, tags=["Authentication"])
async def login(req_data: TokenRequest, request: Request, response: Response):
    """Authenticate against persistent user store with brute-force lockout and set httpOnly refresh cookie."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not login_limiter.check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for authentication requests."
        )

    success, user, message = authenticate_user(req_data.username, req_data.password)
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
                client_ip=request.client.host if request.client else "127.0.0.1",
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
        client_ip=request.client.host if request.client else "127.0.0.1",
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
        prediction = detector.predict(filtered_event)
        incident_id = f"INSA-CR-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"
        prediction["incident_id"] = incident_id

        # Persist detection result on the server by incident_id
        SERVER_DETECTION_STORE[incident_id] = {
            "prediction": dict(prediction),
            "filtered_event": filtered_event,
            "review": None,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        if len(SERVER_DETECTION_STORE) > 500:
            oldest_key = next(iter(SERVER_DETECTION_STORE))
            del SERVER_DETECTION_STORE[oldest_key]

        if prediction.get("status") == "INSUFFICIENT_DATA":
            AuditLogger.log_api_call(
                endpoint="/detect",
                method="POST",
                client_ip=request.client.host if request.client else "127.0.0.1",
                status_code=422,
                officer_id=current_user.get("sub", "analyst"),
                details=f"Inference refused: insufficient feature coverage ({prediction.get('feature_coverage_pct')}%)"
            )
            return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content=prediction)

        AuditLogger.log_api_call(
            endpoint="/detect",
            method="POST",
            client_ip=request.client.host if request.client else "127.0.0.1",
            status_code=200,
            officer_id=current_user.get("sub", "analyst"),
            details=f"Classification: {prediction['threat_category']} (Conf: {prediction['confidence']})"
        )

        return JSONResponse(status_code=status.HTTP_200_OK, content=prediction)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Suricata parsing error: {str(e)}")

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
    if req_data.incident_id and req_data.incident_id in SERVER_DETECTION_STORE:
        det_entry = SERVER_DETECTION_STORE[req_data.incident_id]
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

        # Update server cached prediction
        pred["reviewed_by_analyst"] = True
        pred["has_disagreement"] = False
        pred["analyst_justification"] = justification
        pred["review_decision"] = review_rec["review_decision"]
        if req_data.threat_category:
            pred["threat_category"] = req_data.threat_category

        AuditLogger.log_api_call(
            endpoint="/evidence/review",
            method="POST",
            client_ip=request.client.host if request.client else "127.0.0.1",
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

        case_id = req_data.case_id or check["record"].get("case_id", "INSA-CASE")
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
            client_ip=request.client.host if request.client else "127.0.0.1",
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
    officer_name = current_user.get("full_name", current_user.get("sub", "INSA Investigator"))
    officer_id = current_user.get("officer_id", f"INSA-INV-{current_user.get('id', 4409)}")

    # Refuse anchoring unclassified telemetry
    if req_data.evidence_payload.get("status") == "INSUFFICIENT_DATA":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot anchor unclassified evidence with status INSUFFICIENT_DATA."
        )

    # Refuse anchoring if chain disagreement is unresolved
    evidence_client = EvidenceService.get_instance()
    if evidence_client.is_chain_disagreement_blocked and not LEDGER_INTEGRITY_ACKNOWLEDGED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Anchoring blocked: Unresolved LOCAL/CHAIN DISAGREEMENT detected. System administrator review and acknowledgment required."
        )

    # Refuse anchoring if ledger integrity is broken or truncated and unacknowledged
    chain_verif = evidence_client.verify_chain()
    if not chain_verif.get("ok") and not LEDGER_INTEGRITY_ACKNOWLEDGED:
        broken_detail = chain_verif.get("message") or f"BROKEN at block {chain_verif.get('broken_id')}"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Anchoring disabled: Ledger integrity check failed ({broken_detail}). Admin acknowledgment required."
        )

    # Look up server-side detection record and review state (never trust client flags)
    incident_id = req_data.evidence_payload.get("incident_id")
    server_det = SERVER_DETECTION_STORE.get(incident_id) if incident_id else None

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

        # Apply verified server review values to evidence payload
        if server_review:
            req_data.evidence_payload["reviewed_by_analyst"] = True
            req_data.evidence_payload["has_disagreement"] = False
            req_data.evidence_payload["analyst_justification"] = server_review["analyst_justification"]
            req_data.evidence_payload["review_decision"] = server_review["review_decision"]
            req_data.evidence_payload["threat_category"] = server_review["adjudicated_category"]
            req_data.incident_type = server_review["adjudicated_category"]
    else:
        # Fallback check for records without cached incident_id
        is_disagreement = (
            req_data.evidence_payload.get("has_disagreement", False) or 
            req_data.incident_type == "MODEL/RULE DISAGREEMENT - analyst review required"
        )
        is_reviewed = bool(req_data.evidence_payload.get("reviewed_by_analyst", False))
        if is_disagreement and not is_reviewed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anchoring rejected: evidence has an unresolved MODEL/RULE DISAGREEMENT. Forensic analyst review must be recorded prior to anchoring."
            )

    # Server-side Case ID generation
    case_id = req_data.case_id
    if not case_id or case_id.strip() == "" or case_id.startswith("DEMO-CASE-"):
        case_id = f"INSA-CR-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"

    try:
        evidence_client = EvidenceService.get_instance()
        receipt = evidence_client.store_evidence(
            case_id=case_id,
            incident_type=req_data.incident_type,
            target_asset=req_data.target_asset,
            raw_evidence=req_data.evidence_payload,
            investigator=officer_name,
            officer_id=officer_id
        )

        AuditLogger.log_api_call(
            endpoint="/evidence/store",
            method="POST",
            client_ip=request.client.host if request.client else "127.0.0.1",
            status_code=200,
            officer_id=officer_id,
            details=f"Anchored evidence for {case_id} (hash: {receipt['evidence_hash'][:16]}...)"
        )

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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evidence anchoring failed: {str(e)}"
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

@app.post("/evidence/merkle-batch", tags=["Merkle Batching"])
async def store_merkle_batch(
    req_data: MerkleBatchRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """Batch-anchor logs into Merkle Root (Restricted to investigator, system_admin)."""
    try:
        evidence_client = EvidenceService.get_instance()
        case_id = req_data.case_id or f"INSA-BATCH-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"
        investigator = current_user.get("full_name", current_user.get("sub", "INSA Officer"))
        officer_id = current_user.get("officer_id", "INSA-SYS-01")

        batch_res = evidence_client.store_batch_merkle(
            case_id=case_id,
            events=req_data.events,
            investigator=investigator,
            officer_id=officer_id
        )
        return batch_res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/evidence/verify", tags=["Evidence Ledger"])
async def verify_evidence(
    req_data: EvidenceVerifyRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Verify digital evidence integrity against ledger (Restricted to authenticated roles)."""
    try:
        evidence_client = EvidenceService.get_instance()
        result = evidence_client.verify_evidence(req_data.evidence_payload)

        inc_verification_stat("total_queries")
        if result.get("is_authentic", False):
            inc_verification_stat("successful_verifications")
        else:
            inc_verification_stat("mismatches_detected")

        AuditLogger.log_api_call(
            endpoint="/evidence/verify",
            method="POST",
            client_ip=request.client.host if request.client else "127.0.0.1",
            status_code=200,
            details=f"Integrity check result: {result.get('is_authentic')} for hash {result.get('calculated_hash', '')[:16]}..."
        )

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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

def generate_court_certificate_html(record: Dict[str, Any], is_live: bool = False, verification_result: Optional[Dict[str, Any]] = None) -> str:
    """Generate self-contained official FDRE INSA Forensic Evidence Integrity Certificate."""
    emblem_b64 = ""
    emblem_path = os.path.join(frontend_dir, "images", "insa-emblem.png")
    if os.path.exists(emblem_path):
        try:
            import base64
            with open(emblem_path, "rb") as ef:
                emblem_b64 = "data:image/png;base64," + base64.b64encode(ef.read()).decode("ascii")
        except Exception:
            pass
    if not emblem_b64:
        emblem_b64 = "/static/images/insa-emblem.png"

    case_id = html.escape(str(record.get("case_id", "INSA-CR-UNKNOWN")))
    incident = html.escape(str(record.get("incident_type") or "Cyber Threat Telemetry").replace("_", " "))
    target = html.escape(str(record.get("target_asset", "National-Core-Gateway")))
    block_num = html.escape(str(record.get("block_number", 1)))
    investigator = html.escape(str(record.get("investigator", "INSA Certified Forensic Examiner")))
    timestamp = html.escape(str(record.get("timestamp") or record.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()))
    ev_hash = html.escape(str(record.get("evidence_hash", "")))
    raw_sig = record.get("officer_signature")
    sig = html.escape(str(raw_sig)) if raw_sig else "NOT SIGNED (demo)"
    ledger_mode = "LIVE PERMISSIONED BLOCKCHAIN" if is_live else "SQLITE HASH-CHAINED SOVEREIGN LEDGER"

    chain_id_val = record.get("chain_id") or (settings.CHAIN_ID if settings.CHAIN_MODE != "off" else None)
    contract_val = record.get("contract_address") or (settings.CONTRACT_ADDRESS if settings.CHAIN_MODE != "off" else None)
    tx_hash_val = record.get("tx_hash")
    has_real_tx = bool(tx_hash_val and str(tx_hash_val).startswith("0x"))
    chain_block_val = record.get("chain_block_number") if has_real_tx else None
    chain_mode_val = record.get("chain_mode") or settings.CHAIN_MODE
    is_sepolia = (str(chain_id_val) == "11155111" or chain_mode_val == "sepolia")
    explorer_base = (settings.EXPLORER_BASE_URL or "").rstrip("/") if is_sepolia else ""
    explorer_link = f"{explorer_base}/tx/{tx_hash_val}" if (explorer_base and has_real_tx) else ""
    if explorer_link:
        safe_link = html.escape(explorer_link)
        explorer_display = f'<a href="{safe_link}" target="_blank" style="color:#1F6FB2;word-break:break-all;">{safe_link}</a>'
    elif str(chain_id_val) == "31337" or chain_mode_val == "local":
        explorer_display = '<span style="color:#64748B;">Local node (Chain ID 31337 &mdash; private test RPC, not on public Etherscan)</span>'
    else:
        explorer_display = html.escape(str(tx_hash_val)) if tx_hash_val else "Local / N/A"

    is_authentic = verification_result.get("is_authentic", False) if verification_result else False
    is_superseded = record.get("superseded", False)
    if is_superseded:
        verdict_html = """
        <div class="verdict-banner" style="background:#FFF1F2;border:1px solid #FDA4AF;color:#BE123C;">
            <span>⚠</span>
            <span>RECORD SUPERSEDED: This evidence record has been revoked or superseded in the ledger history.</span>
        </div>"""
    elif is_authentic:
        verdict_html = """
        <div class="verdict-banner" style="background:#E3F3EA;border:1px solid #A8DEC0;color:#1E7B4F;">
            <span>✔</span>
            <span>INTEGRITY VERIFIED: Cryptographic fingerprint matches the anchored sovereign ledger record.</span>
        </div>"""
    else:
        verdict_html = """
        <div class="verdict-banner" style="background:#FFFBEB;border:1px solid #FCD34D;color:#B45309;">
            <span>⚠</span>
            <span>UNVERIFIED / PROTOTYPE RECORD: Cryptographic ledger verification not confirmed.</span>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Official Court Certificate — {case_id}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #0B2A4A;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            color: #16212E;
            padding: 30px 15px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .no-print {{
            width: 100%;
            max-width: 820px;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-bottom: 16px;
        }}
        .btn {{
            background: #1F6FB2;
            color: #FFFFFF;
            border: none;
            padding: 9px 18px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }}
        .btn:hover {{ background: #185A92; }}
        .cert-container {{
            background: #FFFFFF;
            width: 100%;
            max-width: 820px;
            border: 4px double #0B2A4A;
            padding: 40px 48px;
            border-radius: 4px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            position: relative;
        }}
        .cert-watermark {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            opacity: 0.04;
            width: 400px;
            height: auto;
            pointer-events: none;
        }}
        .cert-header {{
            text-align: center;
            border-bottom: 2px solid #0B2A4A;
            padding-bottom: 18px;
            margin-bottom: 22px;
        }}
        .cert-logo {{
            width: 72px;
            height: auto;
            margin-bottom: 10px;
        }}
        .agency-title {{
            font-size: 13px;
            font-weight: 700;
            color: #0B2A4A;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .country-title {{
            font-size: 11px;
            color: #5B6B7D;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 2px;
        }}
        .doc-title {{
            font-size: 20px;
            font-weight: 800;
            color: #0B2A4A;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 14px;
        }}
        .framework-sub {{
            font-size: 10px;
            color: #5B6B7D;
            margin-top: 4px;
        }}
        .status-pill {{
            display: inline-block;
            background: #E4EFF9;
            color: #1F6FB2;
            border: 1px solid rgba(31,111,178,0.3);
            font-size: 10px;
            font-weight: 700;
            padding: 4px 12px;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 10px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px 24px;
            background: #F8FAFD;
            border: 1px solid #D6DEE8;
            border-radius: 6px;
            padding: 16px 20px;
            margin: 20px 0;
            font-size: 12px;
        }}
        .meta-item {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}
        .meta-label {{
            font-size: 10px;
            font-weight: 700;
            color: #5B6B7D;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .meta-val {{
            font-size: 13px;
            font-weight: 600;
            color: #16212E;
        }}
        .meta-val.mono {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
            color: #0B2A4A;
        }}
        .crypto-box {{
            background: #FFFFFF;
            border: 1px solid #D6DEE8;
            border-left: 4px solid #1F6FB2;
            border-radius: 4px;
            padding: 12px 16px;
            margin-bottom: 12px;
        }}
        .crypto-label {{
            font-size: 10px;
            font-weight: 700;
            color: #1F6FB2;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .crypto-val {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
            font-size: 11px;
            word-break: break-all;
            color: #0B2A4A;
            background: #F3F6FA;
            padding: 6px 8px;
            border-radius: 4px;
            border: 1px solid #E8EDF4;
        }}
        .verdict-banner {{
            background: #E3F3EA;
            border: 1px solid #A8DEC0;
            color: #1E7B4F;
            border-radius: 6px;
            padding: 12px 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 12px;
            font-weight: 700;
            margin: 18px 0;
        }}
        .cert-legal {{
            font-size: 11px;
            color: #5B6B7D;
            line-height: 1.6;
            margin-bottom: 24px;
            text-align: justify;
        }}
        .signatures-row {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 40px;
            margin-top: 36px;
            padding-top: 20px;
        }}
        .sig-block {{
            text-align: center;
        }}
        .sig-line {{
            border-bottom: 1px solid #16212E;
            margin-bottom: 8px;
        }}
        .sig-title {{
            font-size: 11px;
            font-weight: 700;
            color: #16212E;
        }}
        .sig-sub {{
            font-size: 10px;
            color: #5B6B7D;
            margin-top: 2px;
        }}
        @media print {{
            body {{ background: #FFFFFF !important; padding: 0 !important; }}
            .no-print {{ display: none !important; }}
            .cert-container {{ border: 2px solid #0B2A4A !important; box-shadow: none !important; padding: 24px 30px !important; }}
        }}
    </style>
</head>
<body>
    <div class="no-print">
        <button class="btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
    </div>

    <div class="cert-container">
        <div style="background:#FEF2F2;border:1px solid #DC2626;color:#991B1B;padding:8px 12px;border-radius:4px;font-size:11px;font-weight:700;text-align:center;letter-spacing:0.5px;margin-bottom:16px;">
            DEMONSTRATION PROTOTYPE &mdash; NOT AN OFFICIAL INSA DOCUMENT
        </div>
        <img src="{emblem_b64}" class="cert-watermark" alt="">
        <div class="cert-header">
            <img src="{emblem_b64}" class="cert-logo" alt="INSA Seal">
            <div class="agency-title">Information Network Security Administration</div>
            <div class="country-title">Federal Democratic Republic of Ethiopia</div>
            <div class="doc-title">Forensic Evidence Integrity Certificate</div>
            <div class="framework-sub">Pursuant to Federal Electronic Signature & Evidence Legal Frameworks (Proclamation No. 958/2016 & No. 1072/2018)</div>
            <div class="status-pill">{ledger_mode}</div>
        </div>

        <div class="meta-grid">
            <div class="meta-item">
                <span class="meta-label">Case Identifier:</span>
                <span class="meta-val mono">{case_id}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Incident Classification:</span>
                <span class="meta-val">{incident}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Target Asset / Node:</span>
                <span class="meta-val mono">{target}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Ledger Block Number:</span>
                <span class="meta-val mono">#{block_num}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Lead Forensic Investigator:</span>
                <span class="meta-val">{investigator}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Internal timestamp (not RFC 3161):</span>
                <span class="meta-val mono">{timestamp}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Chain ID:</span>
                <span class="meta-val mono">{chain_id_val if chain_id_val else 'Local / N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Contract Address:</span>
                <span class="meta-val mono" style="font-size:11px;word-break:break-all;">{contract_val if contract_val else 'N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Transaction Hash:</span>
                <span class="meta-val mono" style="font-size:11px;word-break:break-all;">{tx_hash_val if tx_hash_val else 'N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Chain Block Number:</span>
                <span class="meta-val mono">#{chain_block_val if chain_block_val else 'N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Explorer Link:</span>
                <span class="meta-val" style="font-size:11px;">{explorer_display}</span>
            </div>
        </div>

        <div style="background:#FFF9E6;border:1px solid #FFE082;color:#8D6E10;border-radius:4px;padding:8px 12px;font-size:11px;margin:12px 0;text-align:center;font-weight:600;">
            public test network, hashes only; not a legal timestamp
        </div>

        <div class="crypto-box">
            <div class="crypto-label">SHA-256 Cryptographic Evidence Digest:</div>
            <div class="crypto-val">{ev_hash}</div>
        </div>

        <div class="crypto-box">
            <div class="crypto-label">Officer Digital Signature (SECP256R1 / ECDSA):</div>
            <div class="crypto-val">{sig}</div>
        </div>

        {verdict_html}

        <p class="cert-legal">
            This official document certifies that the aforementioned digital forensic payload was ingested, verified, and anchored into the INSA Sovereign Evidence Ledger. The SHA-256 cryptographic digest and digital signature provide non-repudiation and tamper detection. Judicial admissibility remains subject to the court pursuant to FDRE Evidence Law.
        </p>

        <div class="signatures-row">
            <div class="sig-block">
                <div class="sig-line"></div>
                <div class="sig-title">Certified Forensic Examiner</div>
                <div class="sig-sub">Digital Forensics Directorate, INSA</div>
            </div>
            <div class="sig-block">
                <div class="sig-line"></div>
                <div class="sig-title">Federal Registrar / Judiciary Auditor</div>
                <div class="sig-sub">Federal High Court Depository, Addis Ababa</div>
            </div>
        </div>
    </div>
</body>
</html>"""

@app.get("/evidence/certificate/{evidence_hash}", tags=["Evidence Ledger"])
async def download_court_certificate(
    evidence_hash: str,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Download official standalone Court Certificate HTML document (Restricted to authenticated roles)."""
    evidence_client = EvidenceService.get_instance()
    check = evidence_client.verify_by_hash(evidence_hash)
    if not check.get("record"):
        raise HTTPException(status_code=404, detail="Evidence hash not found on ledger.")

    record = check["record"]
    case_id = record.get("case_id", "INSA-CERT")
    safe_case_id = re.sub(r'[^a-zA-Z0-9_-]', '_', case_id)
    html_content = generate_court_certificate_html(record, is_live=evidence_client.is_live_chain, verification_result=check)

    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="Certificate_{safe_case_id}_{evidence_hash[:10]}.html"'}
    )

@app.get("/evidence/download/{evidence_hash}", tags=["Evidence Ledger"])
async def download_evidence_file(
    evidence_hash: str,
    format: Optional[str] = Query(None, description="Export format: 'certificate' or 'json'"),
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Download exportable raw evidence JSON or official Court Certificate."""
    evidence_client = EvidenceService.get_instance()
    check = evidence_client.verify_by_hash(evidence_hash)
    if not check.get("is_authentic") or not check.get("record"):
        raise HTTPException(status_code=404, detail="Evidence hash not found on ledger.")

    record = check["record"]
    if format == "certificate":
        case_id = record.get("case_id", "INSA-CERT")
        safe_case_id = re.sub(r'[^a-zA-Z0-9_-]', '_', case_id)
        html_content = generate_court_certificate_html(record, is_live=evidence_client.is_live_chain, verification_result=check)
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="Certificate_{safe_case_id}_{evidence_hash[:10]}.html"'}
        )

    raw_evidence = record.get("raw_evidence", record)
    canonical = Web3EvidenceClient.canonicalize_value(raw_evidence)
    content_str = json.dumps(canonical, sort_keys=True, separators=(',', ':'), indent=2)
    return Response(
        content=content_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="evidence_{evidence_hash[:16]}.json"'}
    )

@app.get("/stats", tags=["System Diagnostics"])
async def system_stats(current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))):
    """Retrieve high-level forensic telemetry and blockchain metrics."""
    evidence_client = EvidenceService.get_instance()
    chain_stats = evidence_client.get_chain_stats()

    total_events = 0
    total_threats = 0
    try:
        stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
        with httpx.Client(timeout=1.5) as client:
            resp = client.get(f"{stream_url}/status")
            if resp.status_code == 200:
                s_data = resp.json()
                total_events = s_data.get("events_scored", 0)
                total_threats = s_data.get("threats_detected", 0)
    except Exception:
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
    """Proxy stream status from WSL Stream API (3s timeout). Never fake data; return stopped with zeros if unreachable."""
    stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{stream_url}/status")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass

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
    """Proxy stream alerts from WSL Stream API."""
    stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{stream_url}/alerts", params={"limit": limit, "threats_only": threats_only})
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"alerts": [], "total": 0}


@app.get("/stream/windows", tags=["Real Streaming Pipeline"])
async def stream_windows_proxy(
    limit: int = Query(default=20, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(require_role({ROLE_ANALYST, ROLE_INVESTIGATOR, ROLE_COURT_AUDITOR, ROLE_SYSTEM_ADMIN}))
):
    """Proxy 1-minute tumbling window statistics from WSL Stream API."""
    stream_url = getattr(settings, "STREAM_API_URL", "http://127.0.0.1:8100")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{stream_url}/windows", params={"limit": limit})
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"windows": [], "total": 0}


@app.post("/stream/control", tags=["Real Streaming Pipeline"])
async def stream_control(
    req: StreamControlRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role({ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMIN}))
):
    """
    Control real streaming stack via WSL execution (start|stop).
    Restricted to investigator and system_admin.
    Calls wsl.exe with allow-listed fixed command set, shell=False, validates rate,
    and records every action in the hash-chained audit log.
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

    # When starting stream, also ensure stream_api monitoring service is running in WSL
    if action == "start":
        await loop.run_in_executor(None, lambda: ensure_stream_api_running(distro))

    try:
        proc = await loop.run_in_executor(
            None,
            lambda: subprocess.run(cmd_map[action], shell=False, capture_output=True, text=True, timeout=20)
        )
        out_msg = proc.stdout.strip() or proc.stderr.strip()
    except Exception as e:
        out_msg = str(e)

    AuditLogger.log_api_call(
        endpoint="/stream/control",
        method="POST",
        client_ip=request.client.host if request.client else "127.0.0.1",
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
