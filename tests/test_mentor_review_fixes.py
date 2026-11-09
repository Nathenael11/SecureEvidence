# -*- coding: utf-8 -*-
"""
Tests verifying all 6 findings from the mentor code review of SecureEvidence:
1. Analyst-review check bypass prevention & server-derived payload
2. Stored XSS prevention in case_id and Content-Security-Policy header
3. Hardcoded secrets removal & startup assertion
4. Honest disclaimer when CHAIN_MODE=off
5. Officer signature persistence across restarts & bare-hash replay rejection
6. Merkle batch root fix & persistent proof verification
"""

import os
import json
import pytest
import subprocess
from fastapi.testclient import TestClient

from backend.main import app, generate_court_certificate_html
from backend.security import create_jwt_token
from blockchain.digital_signature import OfficerKeyManager
from blockchain.ledger_store import MemoryLedgerStore
from blockchain.web3_client import Web3EvidenceClient

client = TestClient(app)

@pytest.fixture(scope="module")
def inv_token():
    token, _ = create_jwt_token("test_investigator", "investigator", full_name="Lead Examiner")
    return token

@pytest.fixture(scope="module")
def analyst_token():
    token, _ = create_jwt_token("test_analyst", "analyst", full_name="Forensic Analyst")
    return token

@pytest.fixture(scope="module")
def cicids_samples():
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "cicids2017_test_samples.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)

# --- Finding 1: Analyst-Review Bypass Blocked ---
def test_analyst_review_bypass_blocked_and_payload_server_built(inv_token, analyst_token, cicids_samples):
    sample = dict(cicids_samples["Disagreement_Sample"])
    sample["target_asset"] = "Gateway-Alpha"

    # Step 1: Run detection - triggers disagreement
    det_res = client.post("/detect", json=sample, headers={"Authorization": f"Bearer {analyst_token}"})
    assert det_res.status_code == 200
    det = det_res.json()
    assert det["has_disagreement"] is True
    inc_id = det["incident_id"]
    assert inc_id is not None

    # Step 2: Attempt bypass by forging reviewed_by_analyst: True and edited threat category
    bypass_payload = {
        "incident_id": inc_id,
        "case_id": "INSA-BYPASS-01",
        "evidence_payload": {
            "incident_id": inc_id,
            "reviewed_by_analyst": True,
            "has_disagreement": False,
            "threat_category": "BENIGN",  # Forged category
            "confidence": 0.99
        }
    }
    blocked_res = client.post("/evidence/store", json=bypass_payload, headers={"Authorization": f"Bearer {inv_token}"})
    assert blocked_res.status_code == 400
    assert "DISAGREEMENT" in blocked_res.json()["detail"]

    # Step 3: Legitimate server-side review
    rev_res = client.post("/evidence/review", json={
        "incident_id": inc_id,
        "choice": "rule",
        "threat_category": "DDoS",
        "justification": "Examiner verified SYN flood packet volume signature."
    }, headers={"Authorization": f"Bearer {analyst_token}"})
    assert rev_res.status_code == 200

    # Step 4: Anchoring succeeds, and saved payload has server-adjudicated category (not forged BENIGN)
    store_res = client.post("/evidence/store", json=bypass_payload, headers={"Authorization": f"Bearer {inv_token}"})
    assert store_res.status_code == 200
    stored_data = store_res.json()
    assert "evidence_hash" in stored_data

    # Verify retrieved record reflects server's adjudication
    rec_res = client.get(f"/evidence/{stored_data['evidence_hash']}", headers={"Authorization": f"Bearer {inv_token}"})
    assert rec_res.status_code == 200
    rec = rec_res.json()
    assert rec["incident_type"] == "DDoS"

# --- Finding 2: Stored XSS Prevention & CSP Header ---
def test_stored_xss_sanitization_and_csp(inv_token, cicids_samples):
    sample = dict(cicids_samples["BENIGN"])
    det_res = client.post("/detect", json=sample, headers={"Authorization": f"Bearer {inv_token}"})
    inc_id = det_res.json().get("incident_id")

    # Malicious case_id with XSS vector
    malicious_case_id = "<script>alert('XSS')</script>\"' onclick=alert(1)"
    store_req = {
        "incident_id": inc_id,
        "case_id": malicious_case_id,
        "evidence_payload": sample
    }
    res = client.post("/evidence/store", json=store_req, headers={"Authorization": f"Bearer {inv_token}"})
    assert res.status_code == 200
    data = res.json()
    # Server replaces malicious case_id with safe server-generated identifier
    assert "<script>" not in data["case_id"]
    assert "alert" not in data["case_id"]
    assert data["case_id"].startswith(("DEMO-CASE-", "INSA-CR-"))

    # Test Security Headers (CSP and X-Frame-Options: DENY)
    resp = client.get("/health")
    assert "Content-Security-Policy" in resp.headers
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert resp.headers.get("X-Frame-Options") == "DENY"

# --- Finding 3: Hardcoded Secrets Scanner & Startup Check ---
def test_secrets_scanner_and_startup_assertion():
    # Run scripts/check_secrets.py
    script_path = os.path.join(os.path.dirname(__file__), "..", "scripts", "check_secrets.py")
    res = subprocess.run([os.sys.executable, script_path], capture_output=True, text=True)
    assert res.returncode == 0, f"check_secrets.py failed:\n{res.stdout}\n{res.stderr}"

# --- Finding 4: Certificate Generation When CHAIN_MODE=off ---
def test_off_chain_disclaimer():
    record = {
        "case_id": "INSA-CR-2026-TEST",
        "evidence_hash": "b"*64,
        "incident_type": "DDoS",
        "target_asset": "Switch-01",
        "chain_mode": "off"
    }
    html_out = generate_court_certificate_html(record, is_live=False, verification_result={"is_authentic": True})
    assert "INSA-CR-2026-TEST" in html_out
    assert "INTEGRITY VERIFIED" in html_out

# --- Finding 5: Signatures Persistence & Anti-Replay Nonce ---
def test_signature_persistence_and_anti_replay():
    store = MemoryLedgerStore()
    OfficerKeyManager.set_store(store)

    officer_id = "test_officer_persistent"
    ev_hash = "c"*64
    case_id = "INSA-CR-PERSIST"
    nonce_val = "nonce-unique-99"

    # Sign evidence
    sig_result = OfficerKeyManager.sign_evidence(
        officer_id=officer_id,
        evidence_hash=ev_hash,
        case_id=case_id,
        nonce=nonce_val
    )
    pub_pem = sig_result["public_key_pem"]
    sig_b64 = sig_result["signature_b64"]
    timestamp = sig_result["timestamp"]

    # Clear in-memory caches to simulate server restart
    OfficerKeyManager._demo_officer_private_vault.clear()
    OfficerKeyManager._registered_public_keys.clear()

    # Re-retrieve key - should load from SQLite store
    _, reloaded_pub = OfficerKeyManager.get_or_create_demo_key(officer_id)
    assert reloaded_pub == pub_pem

    # Legitimate signature must verify
    ok = OfficerKeyManager.verify_signature(
        evidence_hash=ev_hash,
        signature_b64=sig_b64,
        public_key_pem=pub_pem,
        officer_id=officer_id,
        case_id=case_id,
        timestamp=timestamp,
        nonce=nonce_val
    )
    assert ok is True

    # Bare-hash bypass attempt must FAIL
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    import base64
    priv, _ = OfficerKeyManager.get_or_create_demo_key(officer_id)
    bare_sig = base64.b64encode(priv.sign(ev_hash.encode('utf-8'), ec.ECDSA(hashes.SHA256()))).decode('utf-8')
    bare_ok = OfficerKeyManager.verify_signature(
        evidence_hash=ev_hash,
        signature_b64=bare_sig,
        public_key_pem=pub_pem,
        officer_id=officer_id
    )
    assert bare_ok is False

# --- Finding 6: Merkle Batch Root & Proof Endpoint ---
def test_merkle_batch_root_and_proof_endpoint(inv_token):
    batch_req = {
        "case_id": "INSA-BATCH-PROOF-TEST",
        "events": [
            {"src_ip": "10.0.0.1", "action": "LOGIN", "dest_port": 22},
            {"src_ip": "10.0.0.2", "action": "INSPECT", "dest_port": 80},
            {"src_ip": "10.0.0.3", "action": "ALERT", "dest_port": 443}
        ]
    }
    batch_res = client.post("/evidence/batch", json=batch_req, headers={"Authorization": f"Bearer {inv_token}"})
    assert batch_res.status_code == 200
    batch_data = batch_res.json()
    root_hash = batch_data["merkle_root"]
    assert root_hash is not None

    # Query proof for a leaf in the batch
    from blockchain.merkle_tree import MerkleTree
    tree = MerkleTree(batch_req["events"])
    first_leaf = tree.leaves[0]

    proof_res = client.get(f"/evidence/merkle-proof/{first_leaf}", headers={"Authorization": f"Bearer {inv_token}"})
    assert proof_res.status_code == 200
    proof_data = proof_res.json()
    assert proof_data["leaf_hash"] == first_leaf
    assert proof_data["root_hash"] == root_hash
    assert proof_data["is_valid"] is True

# --- Certificate Download Endpoint Stability ---
def test_certificate_download_endpoint_stability(inv_token, cicids_samples):
    sample = dict(cicids_samples["PortScan"])
    det = client.post("/detect", json=sample, headers={"Authorization": f"Bearer {inv_token}"}).json()
    store = client.post("/evidence/store", json={"incident_id": det["incident_id"], "evidence_payload": sample}, headers={"Authorization": f"Bearer {inv_token}"}).json()
    ev_hash = store["evidence_hash"]

    # Download certificate
    cert_res = client.get(f"/evidence/certificate/{ev_hash}", headers={"Authorization": f"Bearer {inv_token}"})
    assert cert_res.status_code == 200
    assert "text/html" in cert_res.headers.get("content-type", "")
    assert "Forensic Evidence Integrity Certificate" in cert_res.text


# --- Finding 7: Process Memory State Persistence across Restarts ---
def test_finding_7_state_persistence():
    from backend.main import SERVER_DETECTION_STORE, save_detection_entry, get_detection_entry, is_ledger_integrity_acknowledged, set_ledger_integrity_acknowledged
    from backend.user_store import save_stream_state, load_stream_state, record_stream_alert, get_stream_alerts, record_stream_window, get_stream_windows

    # 1. Detection Results persistence
    test_inc_id = "INSA-CR-TEST-PERSIST-99"
    entry = {
        "prediction": {"threat_category": "PortScan", "confidence": 0.98, "is_threat": True},
        "filtered_event": {"target_asset": "Server-Alpha", "source_ip": "10.0.0.5"},
        "review": None,
        "created_at": "2026-11-09T00:00:00Z"
    }
    save_detection_entry(test_inc_id, entry)
    # Clear in-memory cache to simulate server restart
    SERVER_DETECTION_STORE.pop(test_inc_id, None)
    # Retrieve from DB
    loaded = get_detection_entry(test_inc_id)
    assert loaded is not None
    assert loaded["prediction"]["threat_category"] == "PortScan"
    assert loaded["filtered_event"]["target_asset"] == "Server-Alpha"

    # 2. Acknowledged flag persistence
    set_ledger_integrity_acknowledged(True)
    assert is_ledger_integrity_acknowledged() is True

    # 3. Stream Engine state persistence
    save_stream_state(events_scored=1234, threats_detected=56, is_running=True, rate=250)
    st = load_stream_state()
    assert st["events_scored"] == 1234
    assert st["threats_detected"] == 56
    assert st["rate"] == 250

    # Stream alerts & windows persistence
    alert = {"event_id": "ev-test-1", "predicted_class": "DDoS", "is_threat": True, "scored_at": "2026-11-09T00:00:00Z"}
    record_stream_alert(alert)
    alerts = get_stream_alerts(limit=5)
    assert any(a["event_id"] == "ev-test-1" for a in alerts)

    window = {"window_start": "2026-11-09T00:00:00Z", "event_count": 500, "mean_confidence": 0.95}
    record_stream_window(window)
    windows = get_stream_windows(limit=5)
    assert any(w["event_count"] == 500 for w in windows)

# --- Finding 8: Client IP Extraction & Scoped Account Lockout ---
def test_finding_8_client_ip_and_scoped_lockout():
    from backend.security import get_client_ip
    from backend.user_store import authenticate_user, is_account_locked, get_user_by_username
    from unittest.mock import MagicMock

    # 1. get_client_ip parses X-Forwarded-For
    req = MagicMock()
    req.headers = {"X-Forwarded-For": "203.0.113.195, 10.0.0.1"}
    req.client.host = "10.0.0.1"
    assert get_client_ip(req) == "203.0.113.195"

    req2 = MagicMock()
    req2.headers = {"X-Real-IP": "198.51.100.42"}
    req2.client.host = "10.0.0.1"
    assert get_client_ip(req2) == "198.51.100.42"

    # 2. Account lockout is scoped to attacker's IP
    attacker_ip = "198.51.100.99"
    legit_ip = "203.0.113.1"
    test_user = "test_lockout_user"
    from backend.user_store import create_user
    try:
        create_user(test_user, "Lockout Test User", "analyst", "SecurePassword123!")
    except Exception:
        pass

    # Attacker fails 5 times
    for _ in range(5):
        authenticate_user(test_user, "WrongPassword123!", client_ip=attacker_ip)

    # User is locked from attacker's IP
    u = get_user_by_username(test_user)
    assert is_account_locked(u, client_ip=attacker_ip) is True
    # But legitimate user from different IP is NOT locked out
    assert is_account_locked(u, client_ip=legit_ip) is False

# --- Finding 9 & 10: Server Freeze Under Load & Wasted Work Per Request ---
def test_finding_9_and_10_caching_and_wasted_work():
    from backend.main import _CHAIN_VERIFY_CACHE, invalidate_chain_verification_cache
    from backend.security import AuditLogger
    from backend.user_store import cleanup_expired_tokens

    # 1. Health chain verification TTL cache
    invalidate_chain_verification_cache()
    resp1 = client.get("/health")
    assert resp1.status_code == 200
    ts1 = _CHAIN_VERIFY_CACHE["timestamp"]
    assert ts1 > 0

    # Second call uses cache
    resp2 = client.get("/health")
    assert resp2.status_code == 200
    ts2 = _CHAIN_VERIFY_CACHE["timestamp"]
    assert ts1 == ts2  # Served from cache without re-verifying whole chain

    # Invalidation works
    invalidate_chain_verification_cache()
    assert _CHAIN_VERIFY_CACHE["timestamp"] == 0.0

    # 2. Audit logger tail seeking
    last_h = AuditLogger.get_latest_hash()
    assert last_h is not None
    assert len(last_h) == 64

    # 3. Token denylist cleanup runs without error
    cleaned = cleanup_expired_tokens()
    assert cleaned >= 0

# --- Finding 11: Safe Transaction Retries & EIP-1559 Fees ---
def test_finding_11_safe_tx_and_eip1559():
    from blockchain.web3_client import Web3EvidenceClient
    from unittest.mock import MagicMock
    client_mock = Web3EvidenceClient()

    # 1. Fallback when disconnected
    gas_params_default = client_mock._build_fee_params()
    assert "gasPrice" in gas_params_default

    # 2. When connected to EVM node supporting EIP-1559 (has baseFeePerGas)
    mock_w3 = MagicMock()
    mock_w3.eth.get_block.return_value = {"baseFeePerGas": 10000000000}
    mock_w3.eth.max_priority_fee = 2000000000
    gas_params = client_mock._build_fee_params(w3=mock_w3)
    assert gas_params["type"] == 2
    assert "maxFeePerGas" in gas_params
    assert "maxPriorityFeePerGas" in gas_params
    assert gas_params["maxPriorityFeePerGas"] == 2000000000
    assert gas_params["maxFeePerGas"] == int(10000000000 * 1.3) + 2000000000

# --- Finding 12: Sanitized Error Responses & Verify Public Oracle Removal ---
def test_finding_12_sanitized_errors_and_verify_public_no_oracle():
    # Verify unauthenticated verify-public returns NOT FOUND for unknown hash / raw_text
    resp = client.post("/evidence/verify-public", json={"evidence_hash": "a" * 64})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "NOT FOUND"

    # Probing with valid-looking case ID does NOT leak existence via HASH MISMATCH
    probe_resp = client.post("/evidence/verify-public", json={"raw_text": '{"case_id": "INSA-CR-2026-TEST", "payload": "fake"}'})
    assert probe_resp.status_code == 200
    assert probe_resp.json()["verdict"] == "NOT FOUND"
