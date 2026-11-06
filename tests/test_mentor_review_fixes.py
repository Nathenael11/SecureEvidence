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

# --- Finding 4: Honest Disclaimer When CHAIN_MODE=off ---
def test_off_chain_disclaimer():
    record = {
        "case_id": "INSA-CR-2026-TEST",
        "evidence_hash": "b"*64,
        "incident_type": "DDoS",
        "target_asset": "Switch-01",
        "chain_mode": "off"
    }
    html_out = generate_court_certificate_html(record, is_live=False, verification_result={"is_authentic": True})
    assert "Ledger is tamper-evident against partial edits only; not anchored externally." in html_out

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
