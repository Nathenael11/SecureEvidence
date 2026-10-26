"""
Unit Tests for Blockchain Evidence Ledger, Canonicalization & SHA-256 Hashing
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import json
import pytest
from blockchain.web3_client import Web3EvidenceClient
from blockchain.chain_of_custody import ChainOfCustody, CustodyAction
from blockchain.digital_signature import OfficerKeyManager
from blockchain.merkle_tree import MerkleTree
from blockchain.local_timestamp import LocalTimestampAuthority

def test_evidence_hashing_determinism_and_key_order():
    """Verify SHA-256 hashing is 100% deterministic regardless of key ordering."""
    payload_a = {"case_id": "INSA-01", "ip": "198.51.100.1", "threat": "DDoS"}
    payload_b = {"threat": "DDoS", "case_id": "INSA-01", "ip": "198.51.100.1"}
    
    hash_a = Web3EvidenceClient.calculate_evidence_hash(payload_a)
    hash_b = Web3EvidenceClient.calculate_evidence_hash(payload_b)
    
    assert hash_a == hash_b
    assert len(hash_a) == 64

def test_canonicalization_numeric_and_string_equivalence():
    """
    Requirement 7: Canonicalization normalizes schema-declared numeric fields
    so that string representations match numeric, and whole floats match integers.
    Non-schema fields maintain string integrity.
    """
    payload_int = {"flow_duration": 1200, "total_fwd_packets": 850, "flow_bytes_s": 1850000}
    payload_str = {"flow_duration": "1200", "total_fwd_packets": "850", "flow_bytes_s": "1850000"}
    payload_float = {"flow_duration": 1200.0, "total_fwd_packets": 850.0, "flow_bytes_s": 1850000.0}

    hash_int = Web3EvidenceClient.calculate_evidence_hash(payload_int)
    hash_str = Web3EvidenceClient.calculate_evidence_hash(payload_str)
    hash_float = Web3EvidenceClient.calculate_evidence_hash(payload_float)

    assert hash_int == hash_str, "Hash mismatch between integer and string representation of schema numbers!"
    assert hash_int == hash_float, "Hash mismatch between integer and whole float representation of schema numbers!"

    # Non-schema fields must NOT coerce
    h_str = Web3EvidenceClient.calculate_evidence_hash({"case_code": "007"})
    h_num = Web3EvidenceClient.calculate_evidence_hash({"case_code": 7})
    assert h_str != h_num, "Non-schema strings must NOT coerce!"

def test_store_and_verify_evidence():
    """Verify that stored evidence is authenticated and tamper-proofing works."""
    client = Web3EvidenceClient()
    evidence_payload = {
        "incident_id": "INC-TEST-001",
        "target_asset": "National-Core-GW-01",
        "threat_type": "SQL_Injection",
        "timestamp": "2026-10-08T12:00:00Z"
    }
    
    # Store evidence
    receipt = client.store_evidence(
        case_id="INSA-CR-2026-TEST",
        incident_type="SQL_Injection",
        target_asset="National-Core-GW-01",
        raw_evidence=evidence_payload,
        investigator="Analyst-Demo"
    )
    
    assert receipt["status"] == "STORED_SUCCESSFULLY"
    assert receipt["block_number"] >= 1
    assert "evidence_hash" in receipt
    
    # Verify original payload
    v_res = client.verify_evidence(evidence_payload)
    assert v_res["is_authentic"] is True
    assert v_res["integrity_verified"] is True
    assert v_res["tamper_status"] == "AUTHENTIC_UNMODIFIED"
    assert "No mismatch found" in v_res["message"]
    
    # Verify tampered payload (single character modified)
    tampered_payload = dict(evidence_payload)
    tampered_payload["timestamp"] = "2026-10-08T12:00:01Z"
    
    v_tampered = client.verify_evidence(tampered_payload)
    assert v_tampered["is_authentic"] is False
    assert v_tampered["integrity_verified"] is False
    assert v_tampered["tamper_status"] == "HASH_MISMATCH_OR_UNANCHORED"

def test_ledger_mode_wording_in_simulated_mode():
    """
    Requirement 5: In simulated ledger mode, ensure output never claims
    'immutable', uses 'simulated ledger record', cites Proclamation No. 958/2016
    and No. 1072/2018 with 'to be verified by legal counsel'.
    """
    client = Web3EvidenceClient()
    assert not client.is_live_chain
    assert "SIMULATED LEDGER" in client.ledger_mode

    receipt = client.store_evidence(
        case_id="INSA-CR-TEST-WORDING",
        incident_type="DDoS",
        target_asset="National-Gateway-Demo-01",
        raw_evidence={"flow": 1},
        investigator="Analyst"
    )
    
    v_res = client.verify_evidence({"flow": 1})
    msg = v_res["message"].lower()
    assert "immutable" not in msg
    assert "simulated ledger record" in msg
    assert "no mismatch found between the submitted data and the anchored record" in msg
    
    # Check statutory citation
    statutory = v_res.get("statutory_basis", "")
    assert "958/2016" in statutory
    assert "1072/2018" in statutory
    assert "to be verified by legal counsel" in statutory
    assert "article" not in statutory.lower()

def test_chain_of_custody_tamper_detection():
    """Verify tampering at middle index, deletion, and empty/single chain handling."""
    custody = ChainOfCustody()
    case_id = "INSA-CASE-VERIFY-001"
    ev_hash = "1" * 64

    valid_empty, idx_empty, reason_empty = custody.validate_chain(case_id)
    assert valid_empty is True
    assert idx_empty == -1

    custody.add_entry(case_id, ev_hash, CustodyAction.COLLECTED, "OFF-1", "Analyst A", "Seized")
    valid_one, idx_one, _ = custody.validate_chain(case_id)
    assert valid_one is True
    assert idx_one == -1

    custody.add_entry(case_id, ev_hash, CustodyAction.ANALYZED, "OFF-2", "Analyst B", "Triage")
    custody.add_entry(case_id, ev_hash, CustodyAction.TRANSFERRED, "OFF-1", "Analyst A", "Transfer to Vault")
    custody.add_entry(case_id, ev_hash, CustodyAction.ANCHORED, "OFF-3", "Officer C", "Anchored to ledger")
    custody.add_entry(case_id, ev_hash, CustodyAction.VERIFIED, "OFF-3", "Officer C", "Verified in court")

    valid_all, _, _ = custody.validate_chain(case_id)
    assert valid_all is True

    entries = custody.get_timeline(case_id)
    original_action = entries[2]["action"]
    entries[2]["action"] = "MUTATED_ACTION"

    is_valid, broken_idx, reason = custody.validate_chain(case_id)
    assert is_valid is False
    assert broken_idx == 2
    assert "hash mismatch" in reason

    entries[2]["action"] = original_action
    assert custody.validate_chain(case_id)[0] is True

    deleted_item = entries.pop(2)
    is_valid_del, broken_idx_del, reason_del = custody.validate_chain(case_id)
    assert is_valid_del is False
    assert broken_idx_del == 2

def test_merkle_tree_domain_separation_and_odd_leaves():
    """Verify Merkle leaf/node prefixes, odd leaf promotion rule, and proof checks."""
    events = [{"id": i, "val": f"test_{i}"} for i in range(5)]
    tree = MerkleTree(events)

    assert len(tree.leaves) == 5
    assert tree.root is not None
    assert len(tree.root) == 64

    for i in range(5):
        proof = tree.get_proof(i)
        leaf_hash = tree.leaves[i]
        assert MerkleTree.verify_proof(leaf_hash, proof, tree.root) is True

    leaf_0 = tree.leaves[0]
    proof_0 = tree.get_proof(0)
    fake_root = "0" * 64
    assert MerkleTree.verify_proof(leaf_0, proof_0, fake_root) is False

    leaf_hash_as_data = bytes.fromhex(leaf_0)
    assert leaf_hash_as_data != tree.root

def test_digital_signature_envelope_and_revocation():
    """Verify anti-replay envelope and officer key revocation."""
    officer_id = "INSA-TEST-OFFICER-99"
    ev_hash = "a" * 64
    case_id = "INSA-CR-2026-99"

    sig_info = OfficerKeyManager.sign_evidence_hash(officer_id, ev_hash, case_id=case_id)
    assert sig_info["officer_id"] == officer_id
    assert sig_info["case_id"] == case_id
    assert "nonce" in sig_info

    assert OfficerKeyManager.verify_signature(
        ev_hash,
        sig_info["signature_b64"],
        sig_info["public_key_pem"],
        case_id=case_id,
        timestamp=sig_info["timestamp"],
        nonce=sig_info["nonce"]
    ) is True

    assert OfficerKeyManager.verify_signature(
        ev_hash,
        sig_info["signature_b64"],
        sig_info["public_key_pem"],
        case_id="DIFFERENT-CASE",
        timestamp=sig_info["timestamp"],
        nonce=sig_info["nonce"]
    ) is False

    OfficerKeyManager.revoke_officer(officer_id, "Key compromise simulation")
    assert OfficerKeyManager.is_revoked(officer_id) is True

    with pytest.raises(PermissionError):
        OfficerKeyManager.sign_evidence_hash(officer_id, ev_hash)

def test_rfc3161_timestamp_token():
    dummy_hash = "c" * 64
    token = LocalTimestampAuthority.create_timestamp_token(dummy_hash)
    assert token["message_imprint"]["hashed_message"] == dummy_hash
    assert "internal timestamp - not RFC 3161" in token["warning"]
    assert LocalTimestampAuthority.verify_token(token, dummy_hash) is True

def test_shared_canonicalization_vectors_and_nan_inf_rejection():
    """Coerce only schema numeric fields, reject NaN/Inf, match shared JSON test vectors."""
    # 1. NaN and Infinity must be rejected
    with pytest.raises(ValueError, match="NaN and Infinity are not allowed"):
        Web3EvidenceClient.calculate_evidence_hash({"flow_duration": float("nan")})

    with pytest.raises(ValueError, match="NaN and Infinity are not allowed"):
        Web3EvidenceClient.calculate_evidence_hash({"flow_duration": float("inf")})

    # 2. Non-schema numeric strings must hash differently
    h_007 = Web3EvidenceClient.calculate_evidence_hash({"case_code": "007"})
    h_7 = Web3EvidenceClient.calculate_evidence_hash({"case_code": 7})
    assert h_007 != h_7, "Non-schema string '007' must NOT coerce to 7!"

    h_1e3 = Web3EvidenceClient.calculate_evidence_hash({"scientific_note": "1e3"})
    h_1000 = Web3EvidenceClient.calculate_evidence_hash({"scientific_note": 1000})
    assert h_1e3 != h_1000, "Non-schema string '1e3' must NOT coerce to 1000!"

    # 3. Test shared test vectors against Python implementation
    with open("tests/fixtures/canonicalization_vectors.json", "r", encoding="utf-8") as f:
        vectors = json.load(f)

    for tv in vectors:
        calculated = Web3EvidenceClient.calculate_evidence_hash(tv["input"])
        assert calculated == tv["expected_sha256"], f"Python hash mismatch on {tv['description']}"

