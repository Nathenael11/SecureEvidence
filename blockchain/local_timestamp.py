# -*- coding: utf-8 -*-
"""
SecureEvidence: Local Cryptographic Timestamp Authority
Author: Nathenael Ermias nathenaelermias13@gmail.com
Design: Prototype with production-oriented design (INSA)

Implements:
Local cryptographic timestamp token generation with internal hash binding,
labeled honestly as a local cryptographic timestamp rather than a third-party RFC 3161 TSA server.
"""

from datetime import datetime, timezone
import uuid
import hashlib
import json
import base64
from typing import Dict, Any, Optional

class LocalTimestampAuthority:
    """Manages honest local cryptographic timestamp tokens with hash-binding verification."""

    @classmethod
    def create_local_timestamp(cls, evidence_hash: str) -> Dict[str, Any]:
        """
        Generate a local cryptographic timestamp token.
        Labeled honestly as an internal local cryptographic timestamp.
        """
        utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        serial = uuid.uuid4().hex[:16].upper()

        token_body = {
            "is_rfc3161": False,
            "tsa_type": "LOCAL_CRYPTOGRAPHIC_TIMESTAMP",
            "warning": "internal timestamp - not RFC 3161",
            "message_imprint": {
                "hash_algorithm": "SHA-256",
                "hashed_message": evidence_hash
            },
            "serial_number": f"INSA-LOCAL-TS-{serial}",
            "gen_time": utc_now,
            "statutory_note": "internal timestamp - not RFC 3161"
        }

        canonical = json.dumps(token_body, sort_keys=True, separators=(',', ':'))
        token_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        token_body["token_hash"] = token_hash

        return token_body

    @classmethod
    def create_timestamp_token(cls, evidence_hash: str, prefer_online: bool = False, tsa_url: Optional[str] = None) -> Dict[str, Any]:
        """Produce a local cryptographic timestamp token."""
        return cls.create_local_timestamp(evidence_hash)

    @classmethod
    def verify_token(cls, token: Dict[str, Any], evidence_hash: str) -> bool:
        """Verify binding of timestamp token to evidence_hash."""
        if token.get("message_imprint", {}).get("hashed_message") != evidence_hash:
            return False

        expected_hash = token.get("token_hash")
        body_to_hash = {k: token[k] for k in token if k != "token_hash"}
        canonical = json.dumps(body_to_hash, sort_keys=True, separators=(',', ':'))
        recalculated = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

        return recalculated == expected_hash

# Backward-compatibility alias
TrustedTimestampAuthority = LocalTimestampAuthority
