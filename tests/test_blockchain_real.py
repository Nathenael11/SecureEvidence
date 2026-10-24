# -*- coding: utf-8 -*-
"""
Real End-to-End Blockchain Anchoring & Verification Test Suite.
Tests full lifecycle against live local Hardhat node (Chain ID 31337).
Enforces temp database isolation to guarantee data/ledger.db is never touched.
"""

import os
import time
import hashlib
import json
import pytest
from backend.config import settings
from blockchain.ledger_store import SqliteLedgerStore
from blockchain.web3_client import (
    Web3EvidenceClient,
    BlockchainError,
    RpcDownError,
    WrongChainIdError,
    InsufficientFundsError,
    ChainDisagreementError
)

LOCAL_RPC_URL = "http://127.0.0.1:8545"
LOCAL_CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
HARDHAT_ACCOUNT_0_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
HARDHAT_UNAUTHORIZED_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"


def get_file_hash(path: str) -> str:
    """Compute SHA-256 hash of a file if it exists."""
    if not os.path.exists(path):
        return "NOT_EXIST"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture
def temp_ledger(tmp_path, monkeypatch):
    """Provide an isolated temporary SqliteLedgerStore and verify data/ledger.db is untouched."""
    prod_db = os.path.join(settings.BASE_DIR, "data", "ledger.db") if hasattr(settings, "BASE_DIR") else "data/ledger.db"
    prod_hash_before = get_file_hash(prod_db)

    temp_db_path = str(tmp_path / "test_chain_real.db")
    monkeypatch.setenv("LEDGER_DB_PATH", temp_db_path)

    store = SqliteLedgerStore(temp_db_path)
    from blockchain.ledger_store import set_ledger_store
    set_ledger_store(store)

    yield store

    store.close()
    set_ledger_store(None)
    prod_hash_after = get_file_hash(prod_db)
    assert prod_hash_before == prod_hash_after, "SECURITY ALERT: data/ledger.db was modified during test execution!"


@pytest.fixture
def local_web3_client(temp_ledger):
    """Provide a Web3EvidenceClient configured for real local Hardhat node with temp ledger."""
    client = Web3EvidenceClient(
        rpc_url=LOCAL_RPC_URL,
        contract_address=LOCAL_CONTRACT,
        chain_mode="local",
        chain_id=31337,
        submitter_private_key=HARDHAT_ACCOUNT_0_KEY,
        confirmations=1,
        head_anchor_every=10,
        store=temp_ledger
    )
    return client


def test_blockchain_full_lifecycle(local_web3_client, temp_ledger):
    """
    C1: Full lifecycle test:
    1. Detect / Create unique telemetry
    2. Anchor to real blockchain
    3. Verify on-chain confirmation
    4. Tamper and detect mismatch
    5. Supersede and verify superseded state
    """
    client = local_web3_client
    assert client.is_connected is True
    assert client.chain_mode == "local"
    assert "LOCAL CHAIN ANCHOR" in client.ledger_mode

    # Unique telemetry payload
    nonce = f"lifecycle_{int(time.time()*1000)}"
    evidence_payload = {
        "flow_duration": 45000,
        "total_fwd_packets": 120,
        "total_backward_packets": 95,
        "threat_category": "DDoS",
        "target_asset": "National-Core-Gateway-01",
        "nonce": nonce,
        "timestamp": "2026-10-21T02:00:00Z"
    }

    # 2. Anchor
    case_id = f"INSA-CR-{nonce[:12].upper()}"
    receipt = client.store_evidence(
        case_id=case_id,
        incident_type="DDoS",
        target_asset="National-Core-Gateway-01",
        raw_evidence=evidence_payload,
        investigator="Senior Forensics Investigator"
    )

    assert receipt["status"] == "STORED_SUCCESSFULLY"
    assert receipt["tx_hash"].startswith("0x")
    assert len(receipt["tx_hash"]) == 66
    assert receipt["chain_block_number"] >= 1
    assert receipt["chain_mode"] == "local"
    assert receipt["chain_id"] == 31337

    # Verify receipt saved in separate chain_receipts table
    chain_rc = temp_ledger.get_chain_receipt(receipt["evidence_hash"])
    assert chain_rc is not None
    assert chain_rc["tx_hash"] == receipt["tx_hash"]
    assert chain_rc["chain_id"] == 31337

    # 3. Verify on-chain confirmation
    v_res = client.verify_evidence(evidence_payload)
    assert v_res["is_authentic"] is True
    assert v_res["integrity_verified"] is True
    assert v_res["on_chain_confirmed"] is True
    assert v_res["on_chain_status"] == "On-chain: confirmed"
    assert v_res["tx_hash"] == receipt["tx_hash"]
    assert v_res["tamper_status"] == "AUTHENTIC_UNMODIFIED"

    # 4. Tamper detection
    tampered_payload = dict(evidence_payload)
    tampered_payload["total_fwd_packets"] = 9999

    v_tampered = client.verify_evidence(tampered_payload)
    assert v_tampered["is_authentic"] is False
    assert v_tampered["integrity_verified"] is False
    assert v_tampered["on_chain_confirmed"] is False
    assert "HASH_MISMATCH" in v_tampered["tamper_status"]

    # 5. Supersede
    new_payload = dict(evidence_payload)
    new_payload["notes"] = "Amended forensics analysis"
    new_receipt = client.store_evidence(
        case_id=case_id,
        incident_type="DDoS",
        target_asset="National-Core-Gateway-01",
        raw_evidence=new_payload,
        investigator="Senior Forensics Investigator"
    )

    client.supersede_evidence(
        old_evidence_hash=receipt["evidence_hash"],
        new_evidence_hash=new_receipt["evidence_hash"],
        reason="Updated forensic assessment"
    )

    v_old = client.verify_evidence(evidence_payload)
    assert v_old["is_authentic"] is True
    assert v_old["superseded"] is True
    assert v_old["tamper_status"] == "SUPERSEDED"


def test_idempotent_retry(local_web3_client):
    """C1: Idempotent retry never double-anchors or submits duplicate transactions."""
    client = local_web3_client
    nonce = f"idem_{int(time.time()*1000)}"
    payload = {
        "flow_duration": 18000,
        "threat_category": "PortScan",
        "target_asset": "National-Gateway-Demo-01",
        "nonce": nonce
    }

    # First anchor
    r1 = client.store_evidence(
        case_id="INSA-CR-IDEM-01",
        incident_type="PortScan",
        target_asset="National-Gateway-Demo-01",
        raw_evidence=payload
    )
    assert r1["status"] == "STORED_SUCCESSFULLY"
    first_tx = r1["tx_hash"]

    # Re-anchor identical payload
    r2 = client.store_evidence(
        case_id="INSA-CR-IDEM-01",
        incident_type="PortScan",
        target_asset="National-Gateway-Demo-01",
        raw_evidence=payload
    )
    assert r2["status"] == "ALREADY_REGISTERED"
    assert r2["evidence_hash"] == r1["evidence_hash"]
    assert r2["tx_hash"] == first_tx


def test_rpc_down_leaves_sqlite_untouched(temp_ledger):
    """C1: Unreachable RPC returns RpcDownError and leaves SQLite ledger strictly unchanged."""
    client = Web3EvidenceClient(
        rpc_url="http://127.0.0.1:9999",
        contract_address=LOCAL_CONTRACT,
        chain_mode="local",
        chain_id=31337,
        submitter_private_key=HARDHAT_ACCOUNT_0_KEY,
        store=temp_ledger
    )

    stats_before = temp_ledger.get_stats()
    initial_count = stats_before["total_evidence_stored"]

    payload = {"incident": "TEST_RPC_DOWN", "val": 123}

    with pytest.raises(RpcDownError):
        client.store_evidence(
            case_id="INSA-CR-DOWN-01",
            incident_type="DDoS",
            target_asset="Gateway-01",
            raw_evidence=payload
        )

    stats_after = temp_ledger.get_stats()
    assert stats_after["total_evidence_stored"] == initial_count, "SQLite was modified despite RPC failure!"


def test_wrong_chain_id_rejected(temp_ledger):
    """C1: Configured chain ID mismatch raises WrongChainIdError."""
    client = Web3EvidenceClient(
        rpc_url=LOCAL_RPC_URL,
        contract_address=LOCAL_CONTRACT,
        chain_mode="local",
        chain_id=999999,
        submitter_private_key=HARDHAT_ACCOUNT_0_KEY,
        store=temp_ledger
    )

    payload = {"incident": "TEST_WRONG_CHAIN"}
    with pytest.raises(WrongChainIdError):
        client.store_evidence(
            case_id="INSA-CR-CHAIN-01",
            incident_type="DDoS",
            target_asset="Gateway-01",
            raw_evidence=payload
        )


def test_unauthorized_signer_rejected_on_chain(temp_ledger):
    """C1: Unauthorized signer without contract roles is rejected on-chain."""
    client = Web3EvidenceClient(
        rpc_url=LOCAL_RPC_URL,
        contract_address=LOCAL_CONTRACT,
        chain_mode="local",
        chain_id=31337,
        submitter_private_key=HARDHAT_UNAUTHORIZED_KEY,
        store=temp_ledger
    )

    payload = {"incident": f"UNAUTH_{int(time.time()*1000)}"}
    with pytest.raises(BlockchainError) as exc_info:
        client.store_evidence(
            case_id="INSA-CR-UNAUTH-01",
            incident_type="DDoS",
            target_asset="Gateway-01",
            raw_evidence=payload
        )

    assert "revert" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()


def test_head_anchoring(local_web3_client, temp_ledger):
    """C1: Periodic / on-demand ledger head anchoring updates on-chain head with monotonic count."""
    client = local_web3_client

    # Get latest on-chain head count to guarantee monotonicity
    current_head = client.contract.functions.getLatestHead().call()
    on_chain_count = current_head[1]

    # Store enough records so total_stored >= on_chain_count + 2
    needed = max(2, (on_chain_count + 2) - temp_ledger.get_stats()["total_evidence_stored"])
    for i in range(needed):
        nonce = f"head_{int(time.time()*1000)}_{i}"
        client.store_evidence(
            case_id=f"INSA-CR-HEAD-{i}",
            incident_type="Benign",
            target_asset="Asset-1",
            raw_evidence={"flow_duration": 1000 + i, "threat": "BENIGN", "nonce": nonce}
        )

    total_count = temp_ledger.get_stats()["total_evidence_stored"]
    res = client.anchor_ledger_head()
    assert res["status"] == "HEAD_ANCHORED"
    assert res["tx_hash"].startswith("0x")
    assert res["record_count"] == total_count
    assert res["record_count"] >= on_chain_count

    # Verify head recorded in SQLite chain_head_anchors table
    latest_anchor = temp_ledger.get_latest_head_anchor()
    assert latest_anchor is not None
    assert latest_anchor["tx_hash"] == res["tx_hash"]
    assert latest_anchor["record_count"] == total_count


def test_truncated_detection(local_web3_client, temp_ledger):
    """C1: Truncation detection when SQLite rows are deleted after on-chain head anchor."""
    client = local_web3_client

    current_head = client.contract.functions.getLatestHead().call()
    on_chain_count = current_head[1]

    # Store records to exceed current on-chain count
    needed = max(5, (on_chain_count + 5) - temp_ledger.get_stats()["total_evidence_stored"])
    for i in range(needed):
        nonce = f"trunc_{int(time.time()*1000)}_{i}"
        client.store_evidence(
            case_id=f"INSA-CR-TRUNC-{i}",
            incident_type="Benign",
            target_asset="Asset-Trunc",
            raw_evidence={"flow_duration": 2000 + i, "counter": i, "nonce": nonce}
        )

    head_res = client.anchor_ledger_head()
    anchored_count = head_res["record_count"]

    # Chain initially verifies
    v_init = client.verify_chain()
    assert v_init["ok"] is True

    # Truncate: drop delete trigger and remove last 3 records from SQLite
    conn = temp_ledger._get_connection()
    try:
        conn.execute("DROP TRIGGER IF EXISTS trg_ledger_prevent_delete")
        cur = conn.execute("SELECT id FROM ledger_records ORDER BY id DESC LIMIT 3")
        del_ids = [row[0] for row in cur.fetchall()]
        if del_ids:
            placeholders = ",".join("?" for _ in del_ids)
            conn.execute(f"DELETE FROM ledger_records WHERE id IN ({placeholders})", del_ids)
            conn.commit()
    finally:
        conn.close()

    # verify_chain must detect TRUNCATED state
    v_trunc = client.verify_chain()
    assert v_trunc["ok"] is False
    assert v_trunc["status"] == "TRUNCATED"
    assert "TRUNCATED state detected" in v_trunc["message"]


def test_local_chain_disagreement(local_web3_client, temp_ledger):
    """C1: LOCAL/CHAIN DISAGREEMENT detection blocks subsequent anchoring until admin review."""
    client = local_web3_client

    fake_payload = {"synthetic_evidence": f"rogue_{int(time.time()*1000)}", "flow_duration": 9999}
    fake_hash = client.calculate_evidence_hash(fake_payload)
    fake_canonical = json.dumps(client.canonicalize_value(fake_payload), sort_keys=True, separators=(',', ':'))

    # Inject into SQLite without on-chain anchoring
    temp_ledger.append_record(
        evidence_hash=fake_hash,
        case_id="INSA-CR-ROGUE-01",
        payload_canonical=fake_canonical,
        officer_id="ROGUE-OFFICER",
        timestamp_utc="2026-10-21T00:00:00Z"
    )

    # Verify presented evidence: local exists, but on-chain does not -> DISAGREEMENT
    v_res = client.verify_evidence(fake_payload)
    assert v_res["is_authentic"] is False
    assert v_res["tamper_status"] == "LOCAL_CHAIN_DISAGREEMENT"
    assert v_res["integrity_result"] == "LOCAL/CHAIN DISAGREEMENT"
    assert client.is_chain_disagreement_blocked is True

    # Subsequent anchoring must be blocked
    with pytest.raises(ChainDisagreementError):
        client.store_evidence(
            case_id="INSA-CR-BLOCKED-01",
            incident_type="DDoS",
            target_asset="Target",
            raw_evidence={"flow": 1}
        )


@pytest.mark.skipif(
    os.getenv("CHAIN_MODE", "off").lower() != "sepolia" or not os.getenv("SEPOLIA_RPC_URL"),
    reason="Sepolia testnet environment variables not configured"
)
def test_sepolia_integration():
    """Phase D Sepolia integration test (auto-skipped without Sepolia env vars)."""
    sepolia_rpc = os.getenv("SEPOLIA_RPC_URL") or os.getenv("CHAIN_RPC_URL")
    client = Web3EvidenceClient(
        rpc_url=sepolia_rpc,
        contract_address=settings.CONTRACT_ADDRESS,
        chain_mode="sepolia",
        chain_id=11155111,
        submitter_private_key=settings.SUBMITTER_PRIVATE_KEY,
        confirmations=2
    )
    assert client.chain_mode == "sepolia"
    assert client.chain_id == 11155111
