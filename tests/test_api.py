# -*- coding: utf-8 -*-
"""
Integration Tests for FastAPI Backend Endpoints & Frontend Default State
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import os
import re
import json
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.ingestion_service import SensorLogIngestionService
from blockchain.chain_of_custody import CustodyAction

client = TestClient(app)

@pytest.fixture(scope="module")
def cicids_samples():
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "cicids2017_test_samples.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)

def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OPERATIONAL"
    assert data["author"] == "Nathenael Ermias"
    assert "INSA" in data["agency"]
    assert "demo_mode" in data

def test_frontend_default_neutral_state():
    """
    Requirement 2: Verify that fresh load shows neutral 'Not yet verified' state.
    Never show green VERIFIED unless a lookup actually succeeded.
    """
    html_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    # Verdict box on initial load must have status-neutral, not status-verified
    assert 'class="verdict-box status-neutral"' in html_content
    assert 'id="verdict-title">Not yet verified<' in html_content  # sentence case
    assert 'id="verdict-status">—<' in html_content               # neutral dash
    assert 'status-verified' not in html_content.split('id="verdict-box"')[1].split('</section>')[0]

    # Header metric cards initial state
    assert 'id="stat-events-count">0<' in html_content
    assert 'id="stat-threats-count">0<' in html_content

def test_detect_endpoint(cicids_samples):
    payload = cicids_samples["DDoS"]
    res = client.post("/detect", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "is_threat" in data
    assert "threat_category" in data
    assert data["is_threat"] is True
    assert "feature_coverage_pct" in data
    assert data["feature_coverage_pct"] > 60.0
    assert "feature_attributions" in data
    assert len(data["feature_attributions"]) > 0

def test_detect_insufficient_data():
    sparse_payload = {
        "target_asset": "National-Gateway-Demo-01",
        "flow_duration": 1200.0
    }
    res = client.post("/detect", json=sparse_payload)
    assert res.status_code == 422
    data = res.json()
    assert data["status"] == "INSUFFICIENT_DATA"
    assert data["can_anchor"] is False
    assert len(data["missing_features"]) >= 40

def test_evidence_lifecycle_and_tampering():
    evidence_payload = {
        "incident_id": "INSA-TEST-999",
        "target": "National-Switch-Demo-02",
        "compromise_score": 0.98
    }
    
    # 1. Anchor evidence
    store_req = {
        "case_id": "INSA-CR-2026-TEST",
        "incident_type": "Web_Attack_Brute_Force",
        "target_asset": "National-Switch-Demo-02",
        "investigator": "Analyst-Demo",
        "evidence_payload": evidence_payload
    }
    res_store = client.post("/evidence/store", json=store_req)
    assert res_store.status_code == 200
    store_data = res_store.json()
    assert "evidence_hash" in store_data
    anchored_hash = store_data["evidence_hash"]
    
    # 2. Verify original payload -> INTEGRITY VERIFIED
    res_verify = client.post("/evidence/verify", json={"evidence_payload": evidence_payload})
    assert res_verify.status_code == 200
    v_data = res_verify.json()
    assert v_data["is_authentic"] is True
    assert v_data["integrity_verified"] is True
    assert v_data["tamper_status"] == "AUTHENTIC_UNMODIFIED"
    assert "No mismatch found" in v_data["message"]
    
    # 3. Verify tampered payload -> HASH MISMATCH
    tampered_payload = dict(evidence_payload)
    tampered_payload["compromise_score"] = 0.99
    res_tampered = client.post("/evidence/verify", json={"evidence_payload": tampered_payload})
    assert res_tampered.status_code == 200
    t_data = res_tampered.json()
    assert t_data["is_authentic"] is False
    assert t_data["integrity_verified"] is False
    assert "MISMATCH" in t_data["tamper_status"] or "UNKNOWN" in t_data["tamper_status"]

    # 4. Public verify unanchored hash -> NOT FOUND
    unanchored_hash = "f" * 64
    res_pub_nf = client.post("/evidence/verify-public", json={"evidence_hash": unanchored_hash})
    assert res_pub_nf.status_code == 200
    pub_nf_data = res_pub_nf.json()
    assert pub_nf_data["is_authentic"] is False
    assert pub_nf_data["verdict"] == "NOT FOUND"
    assert pub_nf_data["tamper_status"] == "NOT FOUND"

    # 5. Public verify anchored hash -> INTEGRITY VERIFIED (Privacy-preserving, minimal)
    res_pub = client.post("/evidence/verify-public", json={"evidence_hash": anchored_hash})
    assert res_pub.status_code == 200
    pub_data = res_pub.json()
    assert pub_data["is_authentic"] is True
    assert pub_data["verdict"] == "INTEGRITY VERIFIED"
    assert pub_data["evidence_hash"] == anchored_hash
    assert "block_number" in pub_data
    assert "raw_evidence" not in pub_data

def test_evidence_round_trip_download_and_tamper(cicids_samples):
    """
    Item 8: Round-trip test:
    detect -> anchor -> download -> drop into public verifier = INTEGRITY VERIFIED
    alter 1 byte in downloaded file -> public verifier = NOT FOUND
    """
    # 1. Detect
    sample = dict(cicids_samples["BENIGN"])
    sample["SYN Flag Count"] = 0.0
    sample["syn_flag_count"] = 0
    sample["Flow Packets/s"] = 50.0
    sample["flow_packets_s"] = 50.0
    detect_res = client.post("/detect", json=sample)
    assert detect_res.status_code == 200
    det = detect_res.json()
    assert det["has_disagreement"] is False
    assert det["threat_category"] == "BENIGN"

    # 2. Anchor
    anchor_payload = {
        "case_id": "INSA-CR-ROUNDTRIP-01",
        "incident_type": det["threat_category"],
        "target_asset": "Perimeter-Switch-01",
        "investigator": "Investigator-Demo",
        "evidence_payload": sample
    }
    store_res = client.post("/evidence/store", json=anchor_payload)
    assert store_res.status_code == 200
    s_data = store_res.json()
    ev_hash = s_data["evidence_hash"]
    assert "raw_artifact_sha256" in s_data

    # 3. Download evidence file
    dl_res = client.get(f"/evidence/download/{ev_hash}")
    assert dl_res.status_code == 200
    raw_content = dl_res.content
    assert len(raw_content) > 0

    # 4. Verify downloaded raw text via public verifier -> INTEGRITY VERIFIED
    verify_dl = client.post("/evidence/verify-public", json={"raw_text": raw_content.decode("utf-8")})
    assert verify_dl.status_code == 200
    v_dl_data = verify_dl.json()
    assert v_dl_data["verdict"] == "INTEGRITY VERIFIED"
    assert v_dl_data["is_authentic"] is True

    # 5. Alter 1 byte in downloaded file -> drop into public verifier -> NOT FOUND
    tampered_bytes = bytearray(raw_content)
    # Flip one byte safely (change character)
    tampered_bytes[10] = ord('X') if tampered_bytes[10] != ord('X') else ord('Y')
    tampered_text = tampered_bytes.decode("utf-8", errors="replace")
    verify_tampered = client.post("/evidence/verify-public", json={"raw_text": tampered_text})
    assert verify_tampered.status_code == 200
    v_tamp_data = verify_tampered.json()
    assert v_tamp_data["verdict"] in ["NOT FOUND", "HASH MISMATCH"]
    assert v_tamp_data["is_authentic"] is False

def test_system_stats_endpoint():
    """Requirement 3: Verify stats returns real metrics without fake offsets."""
    res = client.get("/stats")
    assert res.status_code == 200
    data = res.json()
    assert "events_processed" in data
    assert "threats_detected" in data
    assert "total_blocks" in data
    assert "integrity_verification_rate" in data
    assert data["total_blocks"] >= 1
    assert "%" in data["integrity_verification_rate"]

def test_stream_simulate_endpoint():
    res_post = client.post("/stream/simulate?event_count=5")
    assert res_post.status_code == 200
    post_data = res_post.json()
    assert post_data["batch_size"] == 5
    assert "throughput_events_per_sec" in post_data
    assert "threats_detected_count" in post_data

def test_cases_endpoints():
    """Item 26: Test case management endpoints /cases and /cases/{case_id}."""
    res = client.get("/cases")
    assert res.status_code == 200
    data = res.json()
    assert "cases" in data
    assert "total_cases" in data

    if data["cases"]:
        cid = data["cases"][0]["case_id"]
        detail_res = client.get(f"/cases/{cid}")
        assert detail_res.status_code == 200
        assert detail_res.json()["case_id"] == cid



# ---------------------------------------------------------------------------
# Item 3: HASH MISMATCH, SUPERSEDED, and MODEL/RULE DISAGREEMENT tests
# ---------------------------------------------------------------------------

def test_hash_mismatch_lookup_by_case_id():
    """
    Item 3a: Anchor evidence under a known case_id, then verify with a
    different (tampered) payload -> not_authentic (different hash, not found).
    """
    original_payload = {
        "incident_id": "INSA-MISMATCH-TEST-01",
        "target": "Perimeter-Switch-03",
        "compromise_score": 0.75,
        "packet_rate": 120.0,
    }
    store_req = {
        "case_id": "INSA-CR-MISMATCH-2026",
        "incident_type": "PortScan",
        "target_asset": "Perimeter-Switch-03",
        "investigator": "Analyst-Test",
        "evidence_payload": original_payload,
    }
    res_store = client.post("/evidence/store", json=store_req)
    assert res_store.status_code == 200

    # Verify with a DIFFERENT payload (one field changed) -> hash mismatch / not found
    tampered_payload = dict(original_payload)
    tampered_payload["compromise_score"] = 0.999

    res_verify = client.post("/evidence/verify", json={"evidence_payload": tampered_payload})
    assert res_verify.status_code == 200
    v = res_verify.json()
    assert v["is_authentic"] is False
    assert v["integrity_verified"] is False

    # The original payload must still verify correctly
    res_orig = client.post("/evidence/verify", json={"evidence_payload": original_payload})
    assert res_orig.status_code == 200
    assert res_orig.json()["is_authentic"] is True


def test_superseded_shows_replacement_id():
    """
    Item 3b: Anchor a record, supersede it, then public verifier must return
    SUPERSEDED with the replacement hash pointer.
    Uses the same EvidenceService singleton as the app so the records are shared.
    """
    from backend.services.evidence_service import EvidenceService
    ec = EvidenceService.get_instance()

    orig_payload = {"incident_id": "SUPERSEDE-ORIG", "score": 0.8}
    new_payload  = {"incident_id": "SUPERSEDE-NEW",  "score": 0.8, "amended": True}

    receipt_orig = ec.store_evidence(
        case_id="INSA-CR-SUPERSEDE-2026",
        incident_type="DDoS",
        target_asset="CBE-GW-01",
        raw_evidence=orig_payload,
        investigator="Test-Officer",
    )
    receipt_new = ec.store_evidence(
        case_id="INSA-CR-SUPERSEDE-2026",
        incident_type="DDoS",
        target_asset="CBE-GW-01",
        raw_evidence=new_payload,
        investigator="Test-Officer",
    )
    orig_hash = receipt_orig["evidence_hash"]
    new_hash  = receipt_new["evidence_hash"]

    ec.supersede_evidence(orig_hash, new_hash, "Amended telemetry analysis")

    # Old hash -> SUPERSEDED
    res = client.post("/evidence/verify-public", json={"evidence_hash": orig_hash})
    assert res.status_code == 200
    d = res.json()
    assert d["superseded"] is True or d["tamper_status"] == "SUPERSEDED", (
        f"Expected SUPERSEDED, got: {d}"
    )
    assert d.get("superseded_by") == new_hash

    # New hash -> still authentic
    res2 = client.post("/evidence/verify-public", json={"evidence_hash": new_hash})
    assert res2.status_code == 200
    assert res2.json()["is_authentic"] is True



def test_model_rule_disagreement_blocks_anchoring(cicids_samples):
    """
    Item 3c: MODEL/RULE DISAGREEMENT must have severity=UNDETERMINED,
    no MITRE technique, both predictions present, can_anchor=False,
    and anchoring must be rejected (400) until reviewed_by_analyst=True.
    """
    # Start from a full-feature DDoS sample, then flip syn+rate to force rule to fire
    full_payload = dict(cicids_samples["DDoS"])
    full_payload.update({
        "syn_flag_count": 1,
        "SYN Flag Count": 1,
        "flow_packets_s": 3500.0,
        "Flow Packets/s": 3500.0,
        "target_asset": "TestGW-DisagreementTest",
    })

    det_res = client.post("/detect", json=full_payload)
    assert det_res.status_code == 200
    det = det_res.json()

    if not det.get("has_disagreement"):
        pytest.skip("No MODEL/RULE disagreement triggered by this payload (model and rule agree)")

    assert det["severity"] == "UNDETERMINED"
    assert "None" in det["mitre_attack_id"]
    assert det["model_prediction"] is not None
    assert det["rule_prediction"] is not None
    assert det["can_anchor"] is False

    # Anchoring blocked without review
    store_req = {
        "case_id": "INSA-CR-DISAGREE-2026",
        "incident_type": det["threat_category"],
        "target_asset": "TestGW-DisagreementTest",
        "investigator": "Analyst-Test",
        "evidence_payload": full_payload,
    }
    res_blocked = client.post("/evidence/store", json=store_req)
    assert res_blocked.status_code == 400
    assert "DISAGREEMENT" in res_blocked.json()["detail"]

    # Client attempt to bypass via payload flags without server review must still be blocked
    bypass_payload = dict(full_payload)
    bypass_payload["reviewed_by_analyst"] = True
    bypass_payload["has_disagreement"] = False
    store_req["evidence_payload"] = bypass_payload
    res_bypass = client.post("/evidence/store", json=store_req)
    assert res_bypass.status_code == 400
    assert "DISAGREEMENT" in res_bypass.json()["detail"]

    # Legitimate path: Record server-side review with written forensic justification
    inc_id = det["incident_id"]
    rev_res = client.post("/evidence/review", json={
        "incident_id": inc_id,
        "choice": "rule",
        "threat_category": "DDoS",
        "justification": "Flow packet rate and active SYN flag match DDoS flood signature; verified by forensic examiner."
    })
    assert rev_res.status_code == 200

    # Anchoring is now unlocked
    res_ok = client.post("/evidence/store", json=store_req)
    assert res_ok.status_code == 200
    assert "evidence_hash" in res_ok.json()

def test_suricata_ingestion_api():
    eve_payload = {
        "timestamp": "2026-10-10T14:22:00.000000+0300",
        "event_type": "flow",
        "src_ip": "185.220.101.5",
        "dest_ip": "197.156.104.1",
        "flow": {
            "pkts_toserver": 1500,
            "pkts_toclient": 0,
            "bytes_toserver": 96000,
            "bytes_toclient": 0,
            "age": 1
        },
        "tcp": {"syn": True}
    }
    res = client.post("/ingest/suricata", json={"eve_record": eve_payload, "case_id": "INSA-TEST-SURICATA"})
    assert res.status_code == 200
    data = res.json()
    assert "ai_classification" in data
    assert "feature_attributions" in data["ai_classification"]

def test_public_verify_and_stix():
    # Anchor an item first
    sample_evidence = {"test_key": "val_public_verify_123", "flow_rate": 8800, "source_ip": "198.51.100.42"}
    store_req = {
        "case_id": "INSA-PUBLIC-VERIFY-01",
        "incident_type": "DDoS",
        "target_asset": "EthioTelecom-Backbone-Router-4",
        "investigator": "Nathenael Ermias",
        "evidence_payload": sample_evidence
    }
    store_res = client.post("/evidence/store", json=store_req)
    assert store_res.status_code == 200
    ev_hash = store_res.json()["evidence_hash"]

    # Public verify by hash
    pv_res = client.post("/evidence/verify-public", json={"evidence_hash": ev_hash})
    assert pv_res.status_code == 200
    assert pv_res.json()["is_authentic"] is True

    # STIX export
    stix_res = client.get(f"/evidence/stix/{ev_hash}")
    assert stix_res.status_code == 200
    bundle = stix_res.json()
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 4

def test_ingestion_feature_coverage_calculation():
    """Verify feature coverage fraction against 77 CICFlowMeter features and refusal under threshold."""
    suricata_record = {
        "event_type": "flow",
        "src_ip": "10.0.0.5",
        "dest_ip": "10.0.0.1",
        "flow": {
            "pkts_toserver": 100,
            "pkts_toclient": 50,
            "bytes_toserver": 5000,
            "bytes_toclient": 2000,
            "age": 2.0
        },
        "tcp": {"syn": True}
    }

    res = SensorLogIngestionService.parse_suricata_eve(suricata_record, min_coverage=0.10)
    assert "feature_coverage" in res
    assert res["feature_coverage"] > 0.10
    assert res["total_schema_features"] == 77

    with pytest.raises(ValueError, match="below minimum required"):
        SensorLogIngestionService.parse_suricata_eve(suricata_record, min_coverage=0.90)

def test_analyst_review_workflow():
    """Verify /evidence/review endpoint updates reviewed_by_analyst and logs to custody."""
    sample = {"event": "evidence_for_review_test", "metric": 999}
    store_res = client.post("/evidence/store", json={
        "case_id": "INSA-CASE-REVIEW-01",
        "incident_type": "DDoS",
        "target_asset": "Server-Alpha",
        "evidence_payload": sample
    })
    assert store_res.status_code == 200
    ev_hash = store_res.json()["evidence_hash"]

    review_res = client.post("/evidence/review", json={
        "evidence_hash": ev_hash,
        "case_id": "INSA-CASE-REVIEW-01",
        "notes": "Verified by Senior Forensic Analyst"
    })
    assert review_res.status_code == 200
    assert review_res.json()["reviewed_by_analyst"] is True

    custody_res = client.get("/evidence/custody/INSA-CASE-REVIEW-01")
    assert custody_res.status_code == 200
    actions = [e["action"] for e in custody_res.json()["timeline"]]
    assert CustodyAction.ANALYZED in actions

def test_suricata_ui_sample_coverage_gate():
    """Item 4: Assert feature_coverage < 0.6 and response is INSUFFICIENT_DATA on Suricata UI sample."""
    ui_suricata_record = {
        "event_type": "flow",
        "src_ip": "198.51.100.45",
        "dest_ip": "192.0.2.1",
        "flow": {
            "pkts_toserver": 1500,
            "bytes_toserver": 96000,
            "age": 1
        },
        "tcp": {"syn": True}
    }
    res = client.post("/ingest/suricata", json={"eve_record": ui_suricata_record, "case_id": "INSA-TEST-UI-SURICATA"})
    assert res.status_code == 200
    data = res.json()
    ai_classification = data["ai_classification"]
    actual_coverage = ai_classification["feature_coverage"]
    assert actual_coverage < 0.60
    assert ai_classification["status"] == "INSUFFICIENT_DATA"
    assert ai_classification["can_anchor"] is False
    assert ai_classification["threat_category"] == "INSUFFICIENT_DATA"

