# -*- coding: utf-8 -*-
"""
SecureEvidence: Comprehensive Hash-Chained SQLite Ledger Tests
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: Blockchain & Digital Forensics (INSA)

Tests covering:
1. Persistence across store restart (close and reopen DB)
2. Chain verification after 50 appends and genesis link correctness
3. Tamper detection: direct SQL UPDATE, deleted middle row, swapped prev_hash
4. Database triggers: UPDATE and DELETE enforcement
5. Duplicate evidence_hash rejection
6. Concurrent multi-threaded appends producing linear chain without forks
7. Supersession workflow and replacement ID verification
8. MemoryLedgerStore isolation
"""

import json
import sqlite3
import hashlib
import threading
import pytest
from datetime import datetime, timezone

from blockchain.ledger_store import (
    SqliteLedgerStore,
    MemoryLedgerStore,
    compute_canonical_record_hash
)
from blockchain.web3_client import Web3EvidenceClient


def test_records_persist_across_store_restart(tmp_path):
    """Test 1: Records persist across a store restart (close and reopen the DB)."""
    db_file = str(tmp_path / "test_persist.db")
    
    # Session 1: Write records
    store1 = SqliteLedgerStore(db_file)
    for i in range(1, 6):
        payload = json.dumps({"sensor": "EthioTelecom-GW", "counter": i}, sort_keys=True)
        ev_hash = hashlib.sha256(f"evidence_sample_{i}".encode()).hexdigest()
        store1.append_record(
            evidence_hash=ev_hash,
            case_id=f"INSA-CR-2026-{i:03d}",
            payload_canonical=payload,
            officer_id="INSA-INV-4409",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            raw_artifact_sha256=hashlib.sha256(f"raw_{i}".encode()).hexdigest(),
            model_sha256=hashlib.sha256(b"xgb_model").hexdigest(),
            officer_signature=f"SIG_{i}"
        )
    head1 = store1.get_chain_head()
    store1.close()

    # Session 2: Reopen same DB file
    store2 = SqliteLedgerStore(db_file)
    head2 = store2.get_chain_head()
    assert head2["id"] == 5
    assert head2["record_hash"] == head1["record_hash"]

    # Verify all records exist and chain verifies
    all_recs = store2.get_all_records()
    assert len(all_recs) == 5

    v_res = store2.verify_chain()
    assert v_res["ok"] is True
    assert v_res["broken_id"] is None
    assert v_res["total_blocks"] == 6  # Genesis + 5
    store2.close()


def test_chain_verifies_after_50_appends_and_genesis_link(tmp_path):
    """Test 2: Chain verifies after 50 appends; the genesis link is correct."""
    db_file = str(tmp_path / "test_50_appends.db")
    store = SqliteLedgerStore(db_file)

    # Check Genesis Block
    genesis = store.get_record_by_id(0)
    assert genesis is not None
    assert genesis["prev_hash"] == "0" * 64
    assert genesis["id"] == 0

    # Append 50 distinct records
    for i in range(1, 51):
        payload = json.dumps({"stream_id": "CBE-SW-01", "sequence": i}, sort_keys=True)
        ev_hash = hashlib.sha256(f"batch_event_{i}".encode()).hexdigest()
        store.append_record(
            evidence_hash=ev_hash,
            case_id=f"INSA-BATCH-{i:04d}",
            payload_canonical=payload,
            officer_id="INSA-SYS-01",
            timestamp_utc=datetime.now(timezone.utc).isoformat()
        )

    # Block 1's prev_hash must link to Genesis record_hash
    block_1 = store.get_record_by_id(1)
    assert block_1["prev_hash"] == genesis["record_hash"]

    # Verify entire chain
    v = store.verify_chain()
    assert v["ok"] is True
    assert v["broken_id"] is None
    assert v["total_blocks"] == 51  # 1 genesis + 50 appends
    assert "Chain verified: 51 blocks" in v["message"]
    store.close()


def test_tamper_detection_direct_update_deleted_row_and_swapped_prev_hash(tmp_path):
    """
    Test 3: Tamper tests:
    - direct SQL UPDATE of payload_canonical (using a connection with triggers dropped)
    - a deleted middle row
    - a swapped prev_hash
    verify_chain returns the first broken id each time.
    """
    db_file = str(tmp_path / "test_tamper.db")
    store = SqliteLedgerStore(db_file)

    for i in range(1, 11):
        payload = json.dumps({"host": "NBE-GW", "pkt": i}, sort_keys=True)
        ev_hash = hashlib.sha256(f"tamper_ev_{i}".encode()).hexdigest()
        store.append_record(
            evidence_hash=ev_hash,
            case_id=f"INSA-CR-{i}",
            payload_canonical=payload,
            officer_id="INSA-INV-4409",
            timestamp_utc=datetime.now(timezone.utc).isoformat()
        )
    assert store.verify_chain()["ok"] is True

    # 3a. Direct SQL UPDATE of payload_canonical
    conn = sqlite3.connect(db_file)
    conn.execute("DROP TRIGGER IF EXISTS trg_ledger_prevent_update")
    conn.execute("UPDATE ledger_records SET payload_canonical = '{\"host\":\"HACKED\"}' WHERE id = 5")
    conn.commit()
    conn.close()

    res_tamper_payload = store.verify_chain()
    assert res_tamper_payload["ok"] is False
    assert res_tamper_payload["broken_id"] == 5
    assert "tampering detected at block 5" in res_tamper_payload["message"].lower()

    # Restore id=5 back to original for next tests
    orig_payload = json.dumps({"host": "NBE-GW", "pkt": 5}, sort_keys=True)
    conn = sqlite3.connect(db_file)
    conn.execute("UPDATE ledger_records SET payload_canonical = ? WHERE id = 5", (orig_payload,))
    conn.commit()
    conn.close()
    assert store.verify_chain()["ok"] is True

    # 3b. Deleted middle row
    conn = sqlite3.connect(db_file)
    conn.execute("DROP TRIGGER IF EXISTS trg_ledger_prevent_delete")
    conn.execute("DELETE FROM ledger_records WHERE id = 7")
    conn.commit()
    conn.close()

    res_deleted_row = store.verify_chain()
    assert res_deleted_row["ok"] is False
    assert res_deleted_row["broken_id"] == 8  # Sequence gap or link mismatch at block 8
    store.close()

    # 3c. Swapped prev_hash on fresh DB
    db_swap = str(tmp_path / "test_swap.db")
    store_swap = SqliteLedgerStore(db_swap)
    for i in range(1, 10):
        ev_hash = hashlib.sha256(f"swap_ev_{i}".encode()).hexdigest()
        store_swap.append_record(
            evidence_hash=ev_hash,
            case_id=f"INSA-CR-{i}",
            payload_canonical=json.dumps({"i": i}),
            officer_id="INSA-INV-4409",
            timestamp_utc=datetime.now(timezone.utc).isoformat()
        )
    
    conn_swap = sqlite3.connect(db_swap)
    conn_swap.execute("DROP TRIGGER IF EXISTS trg_ledger_prevent_update")
    conn_swap.execute("UPDATE ledger_records SET prev_hash = ? WHERE id = 4", ("f" * 64,))
    conn_swap.commit()
    conn_swap.close()

    res_swapped = store_swap.verify_chain()
    assert res_swapped["ok"] is False
    assert res_swapped["broken_id"] == 4
    store_swap.close()


def test_triggers_enforce_append_only_prevent_update_and_delete(tmp_path):
    """Test 4: Triggers: UPDATE and DELETE through normal connection raise an error."""
    db_file = str(tmp_path / "test_triggers.db")
    store = SqliteLedgerStore(db_file)

    ev_hash = hashlib.sha256(b"trigger_test").hexdigest()
    store.append_record(
        evidence_hash=ev_hash,
        case_id="INSA-CR-TRG-01",
        payload_canonical=json.dumps({"val": 1}),
        officer_id="INSA-INV-4409",
        timestamp_utc=datetime.now(timezone.utc).isoformat()
    )

    conn = sqlite3.connect(db_file, isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON;")

    # 4a. Attempt unauthorized UPDATE on ledger_records
    with pytest.raises(sqlite3.DatabaseError) as exc_update:
        conn.execute("UPDATE ledger_records SET payload_canonical = 'tampered' WHERE id = 1")
    assert "append-only" in str(exc_update.value).lower()

    # 4b. Attempt DELETE on ledger_records
    with pytest.raises(sqlite3.DatabaseError) as exc_del:
        conn.execute("DELETE FROM ledger_records WHERE id = 1")
    assert "append-only" in str(exc_del.value).lower()

    # 4c. Custody triggers
    store.add_custody_entry(
        case_id="INSA-CR-TRG-01",
        evidence_hash=ev_hash,
        action="COLLECTED",
        officer_id="INSA-01",
        officer_name="Officer",
        reason="Initial seizure"
    )
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE custody_entries SET reason = 'tampered' WHERE id = 1")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM custody_entries WHERE id = 1")

    # 4d. Audit log triggers
    store.add_audit_log_entry("/test", "GET", "127.0.0.1", 200, "INSA-01", "admin", "details")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE audit_log_entries SET details = 'tampered' WHERE id = 1")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM audit_log_entries WHERE id = 1")

    conn.close()
    store.close()


def test_duplicate_evidence_hash_rejected_cleanly(tmp_path):
    """Test 5: Duplicate evidence_hash is rejected cleanly."""
    db_file = str(tmp_path / "test_dup.db")
    store = SqliteLedgerStore(db_file)

    duplicate_hash = hashlib.sha256(b"same_payload").hexdigest()
    store.append_record(
        evidence_hash=duplicate_hash,
        case_id="INSA-CR-DUP-01",
        payload_canonical=json.dumps({"data": 123}),
        officer_id="INSA-INV-4409",
        timestamp_utc=datetime.now(timezone.utc).isoformat()
    )

    # Attempting to store the same evidence_hash must raise ValueError
    with pytest.raises(ValueError, match="already exists"):
        store.append_record(
            evidence_hash=duplicate_hash,
            case_id="INSA-CR-DUP-02",
            payload_canonical=json.dumps({"data": 456}),
            officer_id="INSA-INV-4409",
            timestamp_utc=datetime.now(timezone.utc).isoformat()
        )
    store.close()


def test_concurrent_appends_produce_valid_linear_chain_no_forks(tmp_path):
    """Test 6: Concurrent appends (threads) produce a valid linear chain with no forks."""
    db_file = str(tmp_path / "test_concurrency.db")
    store = SqliteLedgerStore(db_file)

    errors = []

    def worker(worker_id: int):
        try:
            for seq in range(5):
                ev_hash = hashlib.sha256(f"worker_{worker_id}_seq_{seq}".encode()).hexdigest()
                store.append_record(
                    evidence_hash=ev_hash,
                    case_id=f"INSA-WORKER-{worker_id}",
                    payload_canonical=json.dumps({"w": worker_id, "s": seq}),
                    officer_id=f"INSA-WORKER-{worker_id}",
                    timestamp_utc=datetime.now(timezone.utc).isoformat()
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrent workers encountered errors: {errors}"

    # Verify no forks and valid linear chain across all 50 appends
    v = store.verify_chain()
    assert v["ok"] is True
    assert v["total_blocks"] == 51  # 1 genesis + 50 appends

    # Verify consecutive block numbers 0..50
    records = store.get_all_records()
    assert len(records) == 50
    block_numbers = sorted([r["id"] for r in records])
    assert block_numbers == list(range(1, 51))
    store.close()


def test_supersession_shows_superseded_with_replacement_id_and_verifies(tmp_path):
    """Test 7: Supersession: the old record shows SUPERSEDED with the replacement id; the new one verifies."""
    db_file = str(tmp_path / "test_supersede.db")
    store = SqliteLedgerStore(db_file)
    client = Web3EvidenceClient(store=store)

    orig_payload = {"incident_id": "INSA-INC-01", "score": 0.82}
    new_payload = {"incident_id": "INSA-INC-01", "score": 0.95, "amended": True}

    receipt_orig = client.store_evidence(
        case_id="INSA-CR-SUPERSEDE-TEST",
        incident_type="DDoS",
        target_asset="EthioTelecom-Gateway-01",
        raw_evidence=orig_payload,
        investigator="Investigator Alpha"
    )
    receipt_new = client.store_evidence(
        case_id="INSA-CR-SUPERSEDE-TEST",
        incident_type="DDoS",
        target_asset="EthioTelecom-Gateway-01",
        raw_evidence=new_payload,
        investigator="Investigator Alpha"
    )

    orig_hash = receipt_orig["evidence_hash"]
    new_hash = receipt_new["evidence_hash"]

    # Trigger-permitted supersession
    sup_res = client.supersede_evidence(orig_hash, new_hash, "Court requested amended telemetry")
    assert sup_res["status"] == "SUPERSEDED"
    assert sup_res["superseded_by_id"] == 2

    # Verify old record: shows SUPERSEDED with replacement id and replacement hash
    v_old = client.verify_by_hash(orig_hash)
    assert v_old["tamper_status"] == "SUPERSEDED"
    assert v_old["record"]["superseded"] is True
    assert v_old["record"]["superseded_by"] == new_hash
    assert v_old["record"]["superseded_by_id"] == 2

    # Verify new record: active and authentic
    v_new = client.verify_by_hash(new_hash)
    assert v_new["is_authentic"] is True
    assert v_new["integrity_verified"] is True
    assert v_new["tamper_status"] == "AUTHENTIC_UNMODIFIED"

    # Whole hash chain continues to verify successfully
    chain_check = store.verify_chain()
    assert chain_check["ok"] is True
    assert chain_check["broken_id"] is None
    store.close()


def test_memory_ledger_store_isolation():
    """Verify MemoryLedgerStore provides isolated in-memory hash-chained ledger."""
    mem_store = MemoryLedgerStore()
    assert mem_store.backend == "memory"

    for i in range(1, 6):
        mem_store.append_record(
            evidence_hash=hashlib.sha256(f"mem_{i}".encode()).hexdigest(),
            case_id="INSA-MEM-01",
            payload_canonical=json.dumps({"mem": i}),
            officer_id="INSA-01",
            timestamp_utc=datetime.now(timezone.utc).isoformat()
        )

    v = mem_store.verify_chain()
    assert v["ok"] is True
    assert v["total_blocks"] == 6
    mem_store.close()


def test_delete_record_prohibited_preventing_silent_renumbering(tmp_path):
    """
    Verify that calling delete_record on the ledger store raises PermissionError,
    preventing silent renumbering and enforcing immutable append-only semantics.
    """
    db_file = str(tmp_path / "test_no_delete.db")
    store = SqliteLedgerStore(db_file)

    ev_hash = hashlib.sha256(b"no_delete_allowed").hexdigest()
    store.append_record(
        evidence_hash=ev_hash,
        case_id="INSA-CR-IMMUTABLE-01",
        payload_canonical=json.dumps({"sensor": "EthioTelecom", "status": "active"}),
        officer_id="INSA-INV-4409",
        timestamp_utc=datetime.now(timezone.utc).isoformat()
    )

    with pytest.raises(PermissionError) as exc_info:
        store.delete_record(ev_hash)

    assert "append-only" in str(exc_info.value).lower()
    assert "prohibited" in str(exc_info.value).lower()

    # Chain remains intact and verified
    assert store.verify_chain()["ok"] is True
    store.close()
