# -*- coding: utf-8 -*-
"""
SecureEvidence: Hash-Chained SQLite & Memory Ledger Store
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: Blockchain & Digital Forensics (INSA)

Implements a tamper-evident, append-only, hash-chained ledger backed by SQLite (WAL mode)
or in-memory fallback. Every block is SHA-256 hash-chained to its predecessor.
Database triggers strictly prohibit UPDATE and DELETE operations, except for a
governed active -> superseded status transition.
"""

import os
import json
import sqlite3
import hashlib
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


class LedgerStore(ABC):
    """Abstract interface for SecureEvidence ledger stores."""

    @property
    @abstractmethod
    def backend(self) -> str:
        """Return backend name: 'sqlite' or 'memory'."""
        pass

    @abstractmethod
    def append_record(
        self,
        evidence_hash: str,
        case_id: str,
        payload_canonical: str,
        officer_id: str,
        timestamp_utc: str,
        raw_artifact_sha256: Optional[str] = None,
        model_sha256: Optional[str] = None,
        officer_signature: Optional[str] = None,
        timestamp_kind: str = "internal"
    ) -> Dict[str, Any]:
        """Append a new evidence block to the hash chain."""
        pass

    @abstractmethod
    def get_record_by_hash(self, evidence_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve a block by its evidence_hash."""
        pass

    @abstractmethod
    def get_record_by_id(self, block_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a block by its id (block number)."""
        pass

    @abstractmethod
    def get_records_by_case(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve all blocks linked to a case_id."""
        pass

    @abstractmethod
    def get_record_by_raw_artifact(self, raw_artifact_sha256: str) -> Optional[Dict[str, Any]]:
        """Retrieve a block by its raw artifact digest."""
        pass

    @abstractmethod
    def get_all_records(self) -> List[Dict[str, Any]]:
        """Retrieve all blocks in reverse chronological order."""
        pass

    @abstractmethod
    def supersede_record(
        self,
        old_evidence_hash: str,
        new_evidence_hash: str,
        reason: str = "Amended evidence"
    ) -> Dict[str, Any]:
        """Mark an active block as superseded by a replacement block."""
        pass

    @abstractmethod
    def delete_record(self, evidence_hash: str) -> bool:
        """Permanently delete an evidence record by hash from the database and re-sequence chain."""
        pass

    @abstractmethod
    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify cryptographic integrity of the entire hash chain.
        Returns:
            {"ok": bool, "broken_id": Optional[int], "message": str, "total_blocks": int, "head_hash": str}
        """
        pass

    @abstractmethod
    def get_chain_head(self) -> Dict[str, Any]:
        """Return the latest block on the chain."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Return operational stats for the store."""
        pass

    @abstractmethod
    def add_custody_entry(
        self,
        case_id: str,
        evidence_hash: str,
        action: str,
        officer_id: str,
        officer_name: str,
        reason: str,
        signature: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        agency: str = "Information Network Security Administration (INSA)"
    ) -> Dict[str, Any]:
        """Append a hash-linked custodial event for a case."""
        pass

    @abstractmethod
    def get_custody_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve chronological chain-of-custody timeline for a case."""
        pass

    @abstractmethod
    def verify_custody_chain(self, case_id: str) -> Tuple[bool, int, str]:
        """Verify hash-chain integrity of custodial records for a case."""
        pass

    @abstractmethod
    def add_audit_log_entry(
        self,
        endpoint: str,
        method: str,
        client_ip: str,
        status_code: int,
        officer_id: str,
        role: str,
        details: str
    ) -> Dict[str, Any]:
        """Append a hash-linked audit log entry."""
        pass

    @abstractmethod
    def get_recent_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent audit log entries in reverse order."""
        pass

    @abstractmethod
    def verify_audit_log_chain(self) -> Tuple[bool, int, str]:
        """Verify hash chain integrity of the audit trail."""
        pass

    @abstractmethod
    def close(self):
        """Cleanly close any open connections."""
        pass


def compute_canonical_record_hash(record_dict: Dict[str, Any]) -> str:
    """
    Computes SHA-256 over canonical sorted-key compact UTF-8 JSON of all fields
    except record_hash itself, including prev_hash.
    """
    doc = {
        "case_id": record_dict.get("case_id"),
        "evidence_hash": record_dict.get("evidence_hash"),
        "id": int(record_dict["id"]),
        "model_sha256": record_dict.get("model_sha256") or "",
        "officer_id": record_dict.get("officer_id"),
        "officer_signature": record_dict.get("officer_signature") or "",
        "payload_canonical": record_dict.get("payload_canonical"),
        "prev_hash": record_dict.get("prev_hash"),
        "raw_artifact_sha256": record_dict.get("raw_artifact_sha256") or "",
        "status": "active",  # Canonical seal represents creation state
        "superseded_by": None,
        "timestamp_kind": record_dict.get("timestamp_kind") or "internal",
        "timestamp_utc": record_dict.get("timestamp_utc")
    }
    canonical_bytes = json.dumps(doc, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(canonical_bytes).hexdigest()


class SqliteLedgerStore(LedgerStore):
    """
    Persistent SQLite-backed hash-chained ledger.
    WAL mode, foreign keys, busy timeout, and trigger-enforced append-only semantics.
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str):
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()

    @property
    def backend(self) -> str:
        return "sqlite"

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_database(self):
        """Run schema migrations and initialize Genesis block."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    # 1. Version table
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS schema_version (
                            version INTEGER PRIMARY KEY,
                            applied_at TEXT NOT NULL,
                            description TEXT NOT NULL
                        );
                    """)

                    cur = conn.execute("SELECT MAX(version) FROM schema_version")
                    row = cur.fetchone()
                    current_ver = row[0] if (row and row[0] is not None) else 0

                    if current_ver < 1:
                        # Migration 1: Initial schema
                        conn.execute("""
                            CREATE TABLE IF NOT EXISTS ledger_records (
                                id INTEGER PRIMARY KEY,
                                evidence_hash TEXT UNIQUE NOT NULL,
                                raw_artifact_sha256 TEXT,
                                case_id TEXT,
                                payload_canonical TEXT NOT NULL,
                                model_sha256 TEXT,
                                officer_id TEXT NOT NULL,
                                officer_signature TEXT,
                                timestamp_utc TEXT NOT NULL,
                                timestamp_kind TEXT NOT NULL DEFAULT 'internal',
                                prev_hash TEXT NOT NULL,
                                record_hash TEXT NOT NULL,
                                status TEXT NOT NULL DEFAULT 'active',
                                superseded_by INTEGER NULL,
                                FOREIGN KEY(superseded_by) REFERENCES ledger_records(id)
                            );
                        """)

                        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_evidence_hash ON ledger_records(evidence_hash);")
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_case_id ON ledger_records(case_id);")
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_raw_artifact ON ledger_records(raw_artifact_sha256);")

                        # Custody table
                        conn.execute("""
                            CREATE TABLE IF NOT EXISTS custody_entries (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                case_id TEXT NOT NULL,
                                evidence_hash TEXT NOT NULL,
                                action TEXT NOT NULL,
                                officer_id TEXT NOT NULL,
                                officer_name TEXT NOT NULL,
                                agency TEXT NOT NULL DEFAULT 'Information Network Security Administration (INSA)',
                                timestamp_utc TEXT NOT NULL,
                                reason TEXT NOT NULL,
                                signature TEXT,
                                metadata_json TEXT,
                                prev_hash TEXT NOT NULL,
                                entry_hash TEXT NOT NULL
                            );
                        """)
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_custody_case_id ON custody_entries(case_id);")
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_custody_evidence_hash ON custody_entries(evidence_hash);")

                        # Audit log table
                        conn.execute("""
                            CREATE TABLE IF NOT EXISTS audit_log_entries (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                timestamp_utc TEXT NOT NULL,
                                endpoint TEXT NOT NULL,
                                method TEXT NOT NULL,
                                client_ip TEXT NOT NULL,
                                status_code INTEGER NOT NULL,
                                officer_id TEXT NOT NULL,
                                role TEXT NOT NULL,
                                details TEXT NOT NULL,
                                prev_hash TEXT NOT NULL,
                                entry_hash TEXT NOT NULL
                            );
                        """)
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log_entries(timestamp_utc);")
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_officer ON audit_log_entries(officer_id);")

                        # Append-only triggers
                        conn.execute("""
                            CREATE TRIGGER IF NOT EXISTS trg_ledger_prevent_update
                            BEFORE UPDATE ON ledger_records
                            FOR EACH ROW
                            WHEN NOT (
                                OLD.status = 'active'
                                AND NEW.status = 'superseded'
                                AND NEW.superseded_by IS NOT NULL
                                AND OLD.id = NEW.id
                                AND OLD.evidence_hash = NEW.evidence_hash
                                AND (OLD.raw_artifact_sha256 IS NEW.raw_artifact_sha256)
                                AND (OLD.case_id IS NEW.case_id)
                                AND OLD.payload_canonical = NEW.payload_canonical
                                AND (OLD.model_sha256 IS NEW.model_sha256)
                                AND OLD.officer_id = NEW.officer_id
                                AND (OLD.officer_signature IS NEW.officer_signature)
                                AND OLD.timestamp_utc = NEW.timestamp_utc
                                AND OLD.timestamp_kind = NEW.timestamp_kind
                                AND OLD.prev_hash = NEW.prev_hash
                                AND OLD.record_hash = NEW.record_hash
                            )
                            BEGIN
                                SELECT RAISE(ABORT, 'ledger_records is append-only: unauthorized UPDATE rejected');
                            END;
                        """)

                        conn.execute("""
                            CREATE TRIGGER IF NOT EXISTS trg_ledger_prevent_delete
                            BEFORE DELETE ON ledger_records
                            FOR EACH ROW
                            BEGIN
                                SELECT RAISE(ABORT, 'ledger_records is append-only: DELETE rejected');
                            END;
                        """)

                        conn.execute("""
                            CREATE TRIGGER IF NOT EXISTS trg_custody_prevent_update
                            BEFORE UPDATE ON custody_entries
                            FOR EACH ROW
                            BEGIN
                                SELECT RAISE(ABORT, 'custody_entries is append-only: UPDATE rejected');
                            END;
                        """)

                        conn.execute("""
                            CREATE TRIGGER IF NOT EXISTS trg_custody_prevent_delete
                            BEFORE DELETE ON custody_entries
                            FOR EACH ROW
                            BEGIN
                                SELECT RAISE(ABORT, 'custody_entries is append-only: DELETE rejected');
                            END;
                        """)

                        conn.execute("""
                            CREATE TRIGGER IF NOT EXISTS trg_audit_prevent_update
                            BEFORE UPDATE ON audit_log_entries
                            FOR EACH ROW
                            BEGIN
                                SELECT RAISE(ABORT, 'audit_log_entries is append-only: UPDATE rejected');
                            END;
                        """)

                        conn.execute("""
                            CREATE TRIGGER IF NOT EXISTS trg_audit_prevent_delete
                            BEFORE DELETE ON audit_log_entries
                            FOR EACH ROW
                            BEGIN
                                SELECT RAISE(ABORT, 'audit_log_entries is append-only: DELETE rejected');
                            END;
                        """)

                        # Record migration
                        conn.execute(
                            "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
                            (1, datetime.now(timezone.utc).isoformat(), "Initial versioned hash-chained ledger schema")
                        )

                    if current_ver < 2:
                        conn.execute("""
                            CREATE TABLE IF NOT EXISTS chain_receipts (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                evidence_hash TEXT UNIQUE NOT NULL,
                                tx_hash TEXT NOT NULL,
                                block_number INTEGER NOT NULL,
                                block_hash TEXT NOT NULL,
                                chain_id INTEGER NOT NULL,
                                contract_address TEXT NOT NULL,
                                anchored_at TEXT NOT NULL,
                                status TEXT NOT NULL DEFAULT 'confirmed'
                            );
                        """)
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_chain_receipts_hash ON chain_receipts(evidence_hash);")
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_chain_receipts_tx ON chain_receipts(tx_hash);")

                        conn.execute("""
                            CREATE TABLE IF NOT EXISTS chain_head_anchors (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                head_hash TEXT NOT NULL,
                                record_count INTEGER NOT NULL,
                                tx_hash TEXT NOT NULL,
                                block_number INTEGER NOT NULL,
                                chain_id INTEGER NOT NULL,
                                contract_address TEXT NOT NULL,
                                anchored_at TEXT NOT NULL
                            );
                        """)
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_head_anchors_hash ON chain_head_anchors(head_hash);")

                        conn.execute(
                            "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
                            (2, datetime.now(timezone.utc).isoformat(), "Separate chain_receipts and chain_head_anchors tables")
                        )

                    # Genesis Block check
                    cur = conn.execute("SELECT COUNT(*) FROM ledger_records")
                    if cur.fetchone()[0] == 0:
                        self._create_genesis_block(conn)
            finally:
                conn.close()

    def _create_genesis_block(self, conn: sqlite3.Connection):
        """Create block 0 (Genesis block) with 64 zeros as prev_hash."""
        genesis_payload = json.dumps(
            {"genesis": True, "metadata": "Genesis Block of SecureEvidence Digital Forensics Chain"},
            sort_keys=True, separators=(',', ':')
        )
        genesis_doc = {
            "case_id": "INSA-GENESIS-BLOCK",
            "evidence_hash": "0" * 64,
            "id": 0,
            "model_sha256": "0" * 64,
            "officer_id": "INSA-ROOT-0000",
            "officer_signature": "GENESIS_ROOT_SIGNATURE",
            "payload_canonical": genesis_payload,
            "prev_hash": "0" * 64,
            "raw_artifact_sha256": "0" * 64,
            "status": "active",
            "superseded_by": None,
            "timestamp_kind": "internal",
            "timestamp_utc": "2026-01-01T00:00:00Z"
        }
        record_hash = compute_canonical_record_hash(genesis_doc)
        conn.execute("""
            INSERT INTO ledger_records (
                id, evidence_hash, raw_artifact_sha256, case_id, payload_canonical,
                model_sha256, officer_id, officer_signature, timestamp_utc,
                timestamp_kind, prev_hash, record_hash, status, superseded_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL)
        """, (
            0,
            genesis_doc["evidence_hash"],
            genesis_doc["raw_artifact_sha256"],
            genesis_doc["case_id"],
            genesis_doc["payload_canonical"],
            genesis_doc["model_sha256"],
            genesis_doc["officer_id"],
            genesis_doc["officer_signature"],
            genesis_doc["timestamp_utc"],
            genesis_doc["timestamp_kind"],
            genesis_doc["prev_hash"],
            record_hash
        ))

    def append_record(
        self,
        evidence_hash: str,
        case_id: str,
        payload_canonical: str,
        officer_id: str,
        timestamp_utc: str,
        raw_artifact_sha256: Optional[str] = None,
        model_sha256: Optional[str] = None,
        officer_signature: Optional[str] = None,
        timestamp_kind: str = "internal"
    ) -> Dict[str, Any]:
        """
        Atomically append an evidence record using BEGIN IMMEDIATE to prevent chain forks.
        """
        clean_hash = evidence_hash.strip().lower()
        if clean_hash.startswith("0x"):
            clean_hash = clean_hash[2:]

        with self._lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN IMMEDIATE")

                # Check uniqueness
                cur = conn.execute("SELECT id FROM ledger_records WHERE evidence_hash = ?", (clean_hash,))
                if cur.fetchone() is not None:
                    conn.execute("ROLLBACK")
                    raise ValueError(f"Evidence hash {clean_hash} already exists in ledger.")

                # Read current head
                cur = conn.execute("SELECT id, record_hash FROM ledger_records ORDER BY id DESC LIMIT 1")
                head = cur.fetchone()
                if not head:
                    raise RuntimeError("Ledger is corrupted: missing Genesis block.")

                new_id = head["id"] + 1
                prev_hash = head["record_hash"]

                record_data = {
                    "id": new_id,
                    "evidence_hash": clean_hash,
                    "case_id": case_id,
                    "payload_canonical": payload_canonical,
                    "officer_id": officer_id,
                    "officer_signature": officer_signature or "",
                    "timestamp_utc": timestamp_utc,
                    "timestamp_kind": timestamp_kind,
                    "raw_artifact_sha256": raw_artifact_sha256 or "",
                    "model_sha256": model_sha256 or "",
                    "prev_hash": prev_hash,
                    "status": "active",
                    "superseded_by": None
                }

                record_hash = compute_canonical_record_hash(record_data)
                record_data["record_hash"] = record_hash

                conn.execute("""
                    INSERT INTO ledger_records (
                        id, evidence_hash, raw_artifact_sha256, case_id, payload_canonical,
                        model_sha256, officer_id, officer_signature, timestamp_utc,
                        timestamp_kind, prev_hash, record_hash, status, superseded_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL)
                """, (
                    new_id,
                    clean_hash,
                    record_data["raw_artifact_sha256"],
                    case_id,
                    payload_canonical,
                    record_data["model_sha256"],
                    officer_id,
                    record_data["officer_signature"],
                    timestamp_utc,
                    timestamp_kind,
                    prev_hash,
                    record_hash
                ))

                conn.execute("COMMIT")
                return self._row_to_dict(record_data)
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            finally:
                conn.close()

    def save_chain_receipt(
        self,
        evidence_hash: str,
        tx_hash: str,
        block_number: int,
        block_hash: str,
        chain_id: int,
        contract_address: str,
        status: str = "confirmed"
    ) -> Dict[str, Any]:
        clean_hash = evidence_hash.strip().lower()
        if clean_hash.startswith("0x"):
            clean_hash = clean_hash[2:]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO chain_receipts
                        (evidence_hash, tx_hash, block_number, block_hash, chain_id, contract_address, anchored_at, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (clean_hash, tx_hash, block_number, block_hash, chain_id, contract_address, now, status))
                return {
                    "evidence_hash": clean_hash,
                    "tx_hash": tx_hash,
                    "block_number": block_number,
                    "block_hash": block_hash,
                    "chain_id": chain_id,
                    "contract_address": contract_address,
                    "anchored_at": now,
                    "status": status
                }
            finally:
                conn.close()

    def get_chain_receipt(self, evidence_hash: str) -> Optional[Dict[str, Any]]:
        clean_hash = evidence_hash.strip().lower()
        if clean_hash.startswith("0x"):
            clean_hash = clean_hash[2:]
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM chain_receipts WHERE evidence_hash = ?", (clean_hash,))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def save_head_anchor(
        self,
        head_hash: str,
        record_count: int,
        tx_hash: str,
        block_number: int,
        chain_id: int,
        contract_address: str
    ) -> Dict[str, Any]:
        clean_hash = head_hash.strip().lower()
        if clean_hash.startswith("0x"):
            clean_hash = clean_hash[2:]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        INSERT INTO chain_head_anchors
                        (head_hash, record_count, tx_hash, block_number, chain_id, contract_address, anchored_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (clean_hash, record_count, tx_hash, block_number, chain_id, contract_address, now))
                return {
                    "head_hash": clean_hash,
                    "record_count": record_count,
                    "tx_hash": tx_hash,
                    "block_number": block_number,
                    "chain_id": chain_id,
                    "contract_address": contract_address,
                    "anchored_at": now
                }
            finally:
                conn.close()

    def get_latest_head_anchor(self) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM chain_head_anchors ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def _row_to_dict(self, row: Any) -> Dict[str, Any]:
        """Convert a sqlite3.Row or dict into a standard block dict."""
        if isinstance(row, dict):
            d = dict(row)
        else:
            d = dict(row)

        # Parse canonical payload if possible
        raw_evidence = None
        if "payload_canonical" in d and d["payload_canonical"]:
            try:
                raw_evidence = json.loads(d["payload_canonical"])
            except Exception:
                raw_evidence = d["payload_canonical"]

        d["block_number"] = d["id"]
        d["block_hash"] = d["record_hash"]
        d["previous_hash"] = d["prev_hash"]
        d["timestamp"] = d["timestamp_utc"]
        d["raw_evidence"] = raw_evidence
        d["superseded"] = (d.get("status") == "superseded")
        if d.get("superseded_by") is not None:
            d["superseded_by_id"] = d["superseded_by"]

        # Extract threat_category, target_asset, investigator if stored in payload
        if isinstance(raw_evidence, dict):
            if "threat_category" in raw_evidence:
                d["incident_type"] = raw_evidence["threat_category"]
            elif "incident_type" in raw_evidence:
                d["incident_type"] = raw_evidence["incident_type"]
            if "target_asset" in raw_evidence:
                d["target_asset"] = raw_evidence["target_asset"]
            if "investigator" in raw_evidence:
                d["investigator"] = raw_evidence["investigator"]
        return d

    def get_record_by_hash(self, evidence_hash: str) -> Optional[Dict[str, Any]]:
        clean_hash = evidence_hash.strip().lower()
        if clean_hash.startswith("0x"):
            clean_hash = clean_hash[2:]

        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM ledger_records WHERE evidence_hash = ?", (clean_hash,))
            row = cur.fetchone()
            if not row:
                return None
            res = self._row_to_dict(row)
            # If superseded, resolve the replacement record's hash
            if res.get("superseded_by") is not None:
                rep_cur = conn.execute("SELECT evidence_hash FROM ledger_records WHERE id = ?", (res["superseded_by"],))
                rep_row = rep_cur.fetchone()
                if rep_row:
                    res["replacement_evidence_hash"] = rep_row["evidence_hash"]
                    res["superseded_by_hash"] = rep_row["evidence_hash"]
            if res:
                rc = self.get_chain_receipt(clean_hash)
                if rc:
                    res["chain_receipt"] = rc
                    res["tx_hash"] = rc["tx_hash"]
                    res["chain_block_number"] = rc["block_number"]
                    res["chain_id"] = rc["chain_id"]
                    res["chain_contract_address"] = rc["contract_address"]
            return res
        finally:
            conn.close()

    def get_record_by_id(self, block_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM ledger_records WHERE id = ?", (block_id,))
            row = cur.fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def get_records_by_case(self, case_id: str) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM ledger_records WHERE case_id = ? ORDER BY id ASC", (case_id,))
            rows = cur.fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def get_record_by_raw_artifact(self, raw_artifact_sha256: str) -> Optional[Dict[str, Any]]:
        clean = raw_artifact_sha256.strip().lower()
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM ledger_records WHERE raw_artifact_sha256 = ?", (clean,))
            row = cur.fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def get_all_records(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM ledger_records WHERE id > 0 ORDER BY id DESC")
            rows = cur.fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def supersede_record(
        self,
        old_evidence_hash: str,
        new_evidence_hash: str,
        reason: str = "Amended evidence"
    ) -> Dict[str, Any]:
        clean_old = old_evidence_hash.strip().lower()
        if clean_old.startswith("0x"):
            clean_old = clean_old[2:]
        clean_new = new_evidence_hash.strip().lower()
        if clean_new.startswith("0x"):
            clean_new = clean_new[2:]

        with self._lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN IMMEDIATE")

                # Verify old record
                cur = conn.execute("SELECT id, status FROM ledger_records WHERE evidence_hash = ?", (clean_old,))
                old_row = cur.fetchone()
                if not old_row:
                    conn.execute("ROLLBACK")
                    raise KeyError(f"Original evidence hash {clean_old} not found in ledger.")

                if old_row["status"] == "superseded":
                    conn.execute("ROLLBACK")
                    raise ValueError(f"Evidence hash {clean_old} has already been superseded.")

                # Verify new record exists
                cur = conn.execute("SELECT id FROM ledger_records WHERE evidence_hash = ?", (clean_new,))
                new_row = cur.fetchone()
                if not new_row:
                    conn.execute("ROLLBACK")
                    raise KeyError(f"Replacement evidence hash {clean_new} not found on ledger.")

                replacement_id = new_row["id"]
                conn.execute(
                    "UPDATE ledger_records SET status = 'superseded', superseded_by = ? WHERE id = ? AND status = 'active'",
                    (replacement_id, old_row["id"])
                )

                conn.execute("COMMIT")
                return {
                    "status": "SUPERSEDED",
                    "old_evidence_hash": clean_old,
                    "superseded_by": clean_new,
                    "superseded_by_id": replacement_id,
                    "reason": reason
                }
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            finally:
                conn.close()

    def delete_record(self, evidence_hash: str) -> bool:
        """
        Forensic evidence ledgers are strictly append-only.
        Permanent deletion and silent chain renumbering are prohibited by design
        (FDRE Proclamations No. 958/2016 and 1072/2018).
        Use supersede_record() to supersede an amended or invalid entry.
        """
        raise PermissionError(
            "Forensic evidence ledger is strictly append-only. Permanent record deletion "
            "and chain renumbering are prohibited. Use supersede_record() instead."
        )

    def verify_chain(self) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM ledger_records ORDER BY id ASC")
            records = cur.fetchall()
            if not records:
                return {
                    "ok": True,
                    "broken_id": None,
                    "message": "Empty ledger chain",
                    "total_blocks": 0,
                    "head_hash": "0" * 64
                }

            expected_prev = "0" * 64
            expected_id = 0

            for idx, r in enumerate(records):
                block_id = r["id"]

                # Sequence check
                if block_id != expected_id:
                    return {
                        "ok": False,
                        "broken_id": block_id,
                        "message": f"Missing block or ID gap before block {block_id}",
                        "total_blocks": len(records),
                        "head_hash": records[-1]["record_hash"]
                    }

                # Link check
                if r["prev_hash"] != expected_prev:
                    return {
                        "ok": False,
                        "broken_id": block_id,
                        "message": f"Broken chain link at block {block_id}: prev_hash mismatch",
                        "total_blocks": len(records),
                        "head_hash": records[-1]["record_hash"]
                    }

                # Content hash check
                recomputed_hash = compute_canonical_record_hash(dict(r))
                if recomputed_hash != r["record_hash"]:
                    return {
                        "ok": False,
                        "broken_id": block_id,
                        "message": f"Content tampering detected at block {block_id}",
                        "total_blocks": len(records),
                        "head_hash": records[-1]["record_hash"]
                    }

                expected_prev = r["record_hash"]
                expected_id = block_id + 1

            total_blocks = len(records)
            head_hash = records[-1]["record_hash"]
            return {
                "ok": True,
                "broken_id": None,
                "message": f"Chain verified: {total_blocks} blocks",
                "total_blocks": total_blocks,
                "head_hash": head_hash
            }
        finally:
            conn.close()

    def get_chain_head(self) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM ledger_records ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            return self._row_to_dict(row) if row else {}
        finally:
            conn.close()

    def get_stats(self) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            cur_tot = conn.execute("SELECT COUNT(*) FROM ledger_records WHERE id > 0")
            total_evidence = cur_tot.fetchone()[0]

            cur_cases = conn.execute("SELECT COUNT(DISTINCT case_id) FROM ledger_records WHERE id > 0")
            total_cases = cur_cases.fetchone()[0]

            cur_head = conn.execute("SELECT id, record_hash FROM ledger_records ORDER BY id DESC LIMIT 1")
            head = cur_head.fetchone()

            return {
                "total_blocks": (head["id"] + 1) if head else 0,
                "total_evidence_stored": total_evidence,
                "total_cases_tracked": total_cases,
                "latest_block_hash": head["record_hash"] if head else ("0" * 64),
                "ledger_backend": self.backend
            }
        finally:
            conn.close()

    # --- Custody Entries ---

    def add_custody_entry(
        self,
        case_id: str,
        evidence_hash: str,
        action: str,
        officer_id: str,
        officer_name: str,
        reason: str,
        signature: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        agency: str = "Information Network Security Administration (INSA)"
    ) -> Dict[str, Any]:
        clean_hash = evidence_hash.strip().lower()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        meta_json = json.dumps(metadata or {}, sort_keys=True, separators=(',', ':'))

        with self._lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN IMMEDIATE")

                # Get latest entry for this case
                cur = conn.execute("SELECT entry_hash FROM custody_entries WHERE case_id = ? ORDER BY id DESC LIMIT 1", (case_id,))
                prev_row = cur.fetchone()
                prev_hash = prev_row["entry_hash"] if prev_row else ("0" * 64)

                doc = {
                    "action": action,
                    "agency": agency,
                    "case_id": case_id,
                    "evidence_hash": clean_hash,
                    "metadata": metadata or {},
                    "officer_id": officer_id,
                    "officer_name": officer_name,
                    "previous_entry_hash": prev_hash,
                    "reason": reason,
                    "signature": signature or "SIGNATURE_PENDING",
                    "timestamp": timestamp
                }
                canonical = json.dumps(doc, sort_keys=True, separators=(',', ':'))
                entry_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

                cur = conn.execute("""
                    INSERT INTO custody_entries (
                        case_id, evidence_hash, action, officer_id, officer_name,
                        agency, timestamp_utc, reason, signature, metadata_json,
                        prev_hash, entry_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    case_id, clean_hash, action, officer_id, officer_name,
                    agency, timestamp, reason, signature or "SIGNATURE_PENDING", meta_json,
                    prev_hash, entry_hash
                ))
                new_id = cur.lastrowid
                conn.execute("COMMIT")

                doc["id"] = new_id
                doc["entry_number"] = new_id
                doc["entry_hash"] = entry_hash
                return doc
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            finally:
                conn.close()

    def get_custody_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM custody_entries WHERE case_id = ? ORDER BY id ASC", (case_id,))
            rows = cur.fetchall()
            results = []
            for r in rows:
                meta = {}
                if r["metadata_json"]:
                    try:
                        meta = json.loads(r["metadata_json"])
                    except Exception:
                        pass
                results.append({
                    "id": r["id"],
                    "entry_number": r["id"],
                    "case_id": r["case_id"],
                    "evidence_hash": r["evidence_hash"],
                    "action": r["action"],
                    "officer_id": r["officer_id"],
                    "officer_name": r["officer_name"],
                    "agency": r["agency"],
                    "timestamp": r["timestamp_utc"],
                    "reason": r["reason"],
                    "signature": r["signature"],
                    "metadata": meta,
                    "previous_entry_hash": r["prev_hash"],
                    "entry_hash": r["entry_hash"]
                })
            return results
        finally:
            conn.close()

    def verify_custody_chain(self, case_id: str) -> Tuple[bool, int, str]:
        timeline = self.get_custody_timeline(case_id)
        if not timeline:
            return True, -1, "Empty chain"

        expected_prev = "0" * 64
        for idx, entry in enumerate(timeline):
            if entry["previous_entry_hash"] != expected_prev:
                return False, idx, f"Broken chain link at index {idx}: previous_entry_hash mismatch"

            doc = {
                "action": entry["action"],
                "agency": entry["agency"],
                "case_id": entry["case_id"],
                "evidence_hash": entry["evidence_hash"],
                "metadata": entry["metadata"],
                "officer_id": entry["officer_id"],
                "officer_name": entry["officer_name"],
                "previous_entry_hash": entry["previous_entry_hash"],
                "reason": entry["reason"],
                "signature": entry["signature"],
                "timestamp": entry["timestamp"]
            }
            canonical = json.dumps(doc, sort_keys=True, separators=(',', ':'))
            recalculated = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
            if recalculated != entry["entry_hash"]:
                return False, idx, f"Content tampering at index {idx}: hash mismatch"

            expected_prev = entry["entry_hash"]

        return True, -1, "Chain valid"

    # --- Audit Log Entries ---

    def add_audit_log_entry(
        self,
        endpoint: str,
        method: str,
        client_ip: str,
        status_code: int,
        officer_id: str,
        role: str,
        details: str
    ) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self._lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN IMMEDIATE")

                cur = conn.execute("SELECT entry_hash FROM audit_log_entries ORDER BY id DESC LIMIT 1")
                prev_row = cur.fetchone()
                prev_hash = prev_row["entry_hash"] if prev_row else ("0" * 64)

                entry = {
                    "client_ip": client_ip,
                    "details": details or "API operation",
                    "endpoint": endpoint,
                    "method": method,
                    "officer_id": officer_id,
                    "previous_hash": prev_hash,
                    "role": role,
                    "status_code": status_code,
                    "timestamp": timestamp
                }
                canonical = json.dumps(entry, sort_keys=True, separators=(',', ':'))
                entry_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

                conn.execute("""
                    INSERT INTO audit_log_entries (
                        timestamp_utc, endpoint, method, client_ip, status_code,
                        officer_id, role, details, prev_hash, entry_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, endpoint, method, client_ip, status_code,
                    officer_id, role, details or "API operation", prev_hash, entry_hash
                ))

                conn.execute("COMMIT")
                entry["log_hash"] = entry_hash
                entry["entry_hash"] = entry_hash
                return entry
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            finally:
                conn.close()

    def get_recent_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM audit_log_entries ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            return [{
                "timestamp": r["timestamp_utc"],
                "endpoint": r["endpoint"],
                "method": r["method"],
                "client_ip": r["client_ip"],
                "status_code": r["status_code"],
                "officer_id": r["officer_id"],
                "role": r["role"],
                "details": r["details"],
                "previous_hash": r["prev_hash"],
                "log_hash": r["entry_hash"],
                "entry_hash": r["entry_hash"]
            } for r in rows]
        finally:
            conn.close()

    def verify_audit_log_chain(self) -> Tuple[bool, int, str]:
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT * FROM audit_log_entries ORDER BY id ASC")
            entries = cur.fetchall()
            if not entries:
                return True, -1, "Audit log is empty"

            expected_prev = "0" * 64
            for idx, r in enumerate(entries):
                if r["prev_hash"] != expected_prev:
                    return False, idx, f"Line {idx} hash break: previous_hash mismatch"

                doc = {
                    "client_ip": r["client_ip"],
                    "details": r["details"],
                    "endpoint": r["endpoint"],
                    "method": r["method"],
                    "officer_id": r["officer_id"],
                    "previous_hash": r["prev_hash"],
                    "role": r["role"],
                    "status_code": r["status_code"],
                    "timestamp": r["timestamp_utc"]
                }
                canonical = json.dumps(doc, sort_keys=True, separators=(',', ':'))
                recalculated = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
                if recalculated != r["entry_hash"]:
                    return False, idx, f"Line {idx} content tampering detected"

                expected_prev = r["entry_hash"]

            return True, -1, "Audit log integrity verified"
        finally:
            conn.close()

    def close(self):
        # sqlite3 connections in WAL mode are managed per query
        pass


class MemoryLedgerStore(SqliteLedgerStore):
    """
    In-memory ledger store using shared SQLite memory connection.
    Used for isolated unit tests without disk residue.
    """

    def __init__(self):
        import time
        self._uri = f"file:mem_{id(self)}_{time.time_ns()}?mode=memory&cache=shared"
        self._keepalive = sqlite3.connect(self._uri, uri=True, check_same_thread=False)
        self._keepalive.row_factory = sqlite3.Row
        self._keepalive.execute("PRAGMA foreign_keys=ON;")
        super().__init__(db_path=self._uri)

    @property
    def backend(self) -> str:
        return "memory"

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._uri, uri=True, check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def close(self):
        try:
            self._keepalive.close()
        except Exception:
            pass


_store_instance: Optional[LedgerStore] = None
_store_lock = threading.Lock()


def get_ledger_store(backend: Optional[str] = None, db_path: Optional[str] = None) -> LedgerStore:
    """Singleton getter / factory for the active LedgerStore."""
    global _store_instance
    with _store_lock:
        if _store_instance is None:
            active_backend = backend or os.getenv("LEDGER_BACKEND", "sqlite").lower()
            if active_backend == "memory":
                _store_instance = MemoryLedgerStore()
            else:
                default_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "ledger.db"
                )
                active_path = db_path or os.getenv("LEDGER_DB_PATH", default_path)
                _store_instance = SqliteLedgerStore(active_path)
        return _store_instance


def set_ledger_store(store: Optional[LedgerStore]):
    """Explicitly override the active LedgerStore (used in tests)."""
    global _store_instance
    with _store_lock:
        _store_instance = store
