# -*- coding: utf-8 -*-
"""
SecureEvidence: Forensic Chain-of-Custody Cryptographic Ledger
Author: Nathenael Ermias
Design: Prototype with production-oriented design (INSA)

Implements a hash-linked chain-of-custody log for forensic evidence.
References Ethiopian Computer Crime Proclamation (No. 958/2016) and Electronic Signature
Proclamation (No. 1072/2018) - to be verified by legal counsel against the official text.
Every custodial transfer, analysis, and audit action is cryptographically
linked to its predecessor to detect tampering or repudiation.
Backed by persistent LedgerStore or in-memory verification.
"""

import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Tuple

class CustodyAction:
    COLLECTED = "COLLECTED"
    TRANSFERRED = "TRANSFERRED"
    ANALYZED = "ANALYZED"
    ANCHORED = "ANCHORED"
    VERIFIED = "VERIFIED"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"

class ChainOfCustody:
    """Manages hash-linked chain-of-custody records for forensic cases."""

    def __init__(self, store=None):
        self.store = store
        self.records_by_case: Dict[str, List[Dict[str, Any]]] = {}

    def add_entry(
        self,
        case_id: str,
        evidence_hash: str,
        action: str,
        officer_id: str,
        officer_name: str,
        reason: str,
        signature: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Append a new hash-linked custodial record to the case timeline."""
        # When persistent store is attached, it is the authoritative single source of truth
        if self.store is not None:
            return self.store.add_custody_entry(
                case_id=case_id,
                evidence_hash=evidence_hash,
                action=action,
                officer_id=officer_id,
                officer_name=officer_name,
                reason=reason,
                signature=signature,
                metadata=metadata
            )

        # In-memory fallback (only when no store is configured)
        if case_id not in self.records_by_case:
            self.records_by_case[case_id] = []

        history = self.records_by_case[case_id]
        prev_hash = history[-1]["entry_hash"] if history else "0" * 64
        entry_number = len(history) + 1

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        entry_data = {
            "entry_number": entry_number,
            "case_id": case_id,
            "evidence_hash": evidence_hash,
            "action": action,
            "officer_id": officer_id,
            "officer_name": officer_name,
            "agency": "Information Network Security Administration (INSA)",
            "timestamp": timestamp,
            "reason": reason,
            "previous_entry_hash": prev_hash,
            "signature": signature or "SIGNATURE_PENDING",
            "metadata": metadata or {}
        }

        # Calculate canonical SHA-256 for the entry
        canonical = json.dumps(
            {k: entry_data[k] for k in entry_data if k != "entry_hash"},
            sort_keys=True,
            separators=(',', ':')
        )
        entry_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        entry_data["entry_hash"] = entry_hash

        history.append(entry_data)
        return entry_data

    def get_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve full custodial timeline for a case."""
        if self.store is not None:
            return self.store.get_custody_timeline(case_id)
        return self.records_by_case.get(case_id, [])

    def verify_chain_integrity(self, case_id: str) -> Dict[str, Any]:
        """
        Verify that no entry in the chain has been altered and all hash links are intact.
        Returns validation result and any compromised block indices.
        """
        if self.store is not None:
            ok, broken_idx, msg = self.store.verify_custody_chain(case_id)
            timeline = self.store.get_custody_timeline(case_id)
            return {
                "is_valid": ok,
                "total_entries": len(timeline),
                "status": "VALID_CUSTODY_CHAIN" if ok else f"COMPROMISED_AT_ENTRY_{broken_idx}",
                "error": msg if not ok else None
            }

        history = self.get_timeline(case_id)
        if not history:
            return {"is_valid": True, "total_entries": 0, "status": "EMPTY_CHAIN"}

        expected_prev = "0" * 64
        for idx, entry in enumerate(history):
            if entry["previous_entry_hash"] != expected_prev:
                return {
                    "is_valid": False,
                    "compromised_index": idx,
                    "reason": f"Hash break at entry {entry.get('entry_number', idx + 1)}: previous_hash mismatch."
                }

            # Recalculate hash
            body = {k: entry[k] for k in entry if k not in ("entry_hash", "id")}
            canonical = json.dumps(
                body,
                sort_keys=True,
                separators=(',', ':')
            )
            recalculated = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
            if recalculated != entry["entry_hash"]:
                return {
                    "is_valid": False,
                    "compromised_index": idx,
                    "reason": f"Content tampering detected in entry {entry.get('entry_number', idx + 1)}."
                }

            expected_prev = entry["entry_hash"]

        return {
            "is_valid": True,
            "total_entries": len(history),
            "head_hash": history[-1]["entry_hash"],
            "status": "CHAIN_INTEGRITY_VERIFIED"
        }

    def validate_chain(self, case_id: str) -> Tuple[bool, int, str]:
        """
        Validate the full chain for a case.
        Returns:
            (is_valid: bool, broken_index: int, reason: str)
            broken_index is -1 if the chain is valid or empty.
            broken_index is the 0-based index of the first compromised/broken entry.
        """
        history = self.get_timeline(case_id)
        if not history:
            return True, -1, "Empty chain"

        expected_prev = "0" * 64
        for idx, entry in enumerate(history):
            if entry.get("previous_entry_hash") != expected_prev:
                return False, idx, f"Broken chain link at index {idx}: previous_entry_hash mismatch"

            body = {k: entry[k] for k in entry if k not in ("entry_hash", "id")}
            canonical = json.dumps(
                body,
                sort_keys=True,
                separators=(',', ':')
            )
            recalculated = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
            if recalculated != entry.get("entry_hash"):
                return False, idx, f"Content tampering at index {idx}: hash mismatch"

            expected_prev = entry.get("entry_hash")

        return True, -1, "Chain valid"
