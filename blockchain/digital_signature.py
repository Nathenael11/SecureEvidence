# -*- coding: utf-8 -*-
"""
SecureEvidence: Forensic Officer Digital Signature Engine
Author: Nathenael Ermias
Design: Prototype with production-oriented design (INSA)

Implements ECDSA digital signature (P-256 / SECP256R1) signing and verification.
Does not claim legal recognition.
Key custody:
  - In production, server must NOT hold officer private keys; officers sign client-side.
  - In demo mode, server-side key generation is explicitly labeled:
    "DEMO KEY CUSTODY - not for production"
Anti-replay:
  - Signs canonical digest binding evidence_hash + case_id + timestamp + nonce.
"""

import base64
import hashlib
import json
from typing import Tuple, Dict, Any, Optional, Set
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

class OfficerKeyManager:
    """Manages officer ECDSA (P-256) public key registrations, signing, and verification."""

    # Key vaults (Demo mode only)
    _demo_officer_private_vault: Dict[str, ec.EllipticCurvePrivateKey] = {}
    _registered_public_keys: Dict[str, str] = {}
    _revoked_officers: Set[str] = set()


    @classmethod
    def register_officer_public_key(cls, officer_id: str, public_key_pem: str):
        """Register an officer's public key (production mode: officer keeps private key)."""
        cls._registered_public_keys[officer_id] = public_key_pem

    @classmethod
    def revoke_officer(cls, officer_id: str, reason: str = "Administrative revocation"):
        """Revoke an officer's signing privileges."""
        cls._revoked_officers.add(officer_id)


    @classmethod
    def is_revoked(cls, officer_id: str) -> bool:
        return officer_id in cls._revoked_officers

    @classmethod
    def get_or_create_demo_key(cls, officer_id: str) -> Tuple[ec.EllipticCurvePrivateKey, str]:
        """
        Server-side key generation for prototype demo only.
        NOT FOR PRODUCTION.
        """
        if officer_id in cls._demo_officer_private_vault:
            return cls._demo_officer_private_vault[officer_id], cls._registered_public_keys[officer_id]

        priv_key = ec.generate_private_key(ec.SECP256R1())
        pub_key = priv_key.public_key()
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        cls._demo_officer_private_vault[officer_id] = priv_key
        cls._registered_public_keys[officer_id] = pub_pem
        return priv_key, pub_pem

    @classmethod
    def compute_signature_payload(
        cls,
        evidence_hash: str,
        case_id: str,
        timestamp: str,
        nonce: str
    ) -> bytes:
        """
        Compute canonical anti-replay signature payload:
        SHA-256(canonical_json({"case_id": case_id, "evidence_hash": evidence_hash, "nonce": nonce, "timestamp": timestamp}))
        """
        envelope = {
            "case_id": case_id,
            "evidence_hash": evidence_hash,
            "nonce": nonce,
            "timestamp": timestamp
        }
        canonical = json.dumps(envelope, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).digest()

    @classmethod
    def sign_evidence(
        cls,
        officer_id: str,
        evidence_hash: str,
        case_id: str = "INSA-CR-DEMO",
        timestamp: str = "2026-10-10T00:00:00Z",
        nonce: str = "0",
        external_private_key: Optional[ec.EllipticCurvePrivateKey] = None
    ) -> Dict[str, Any]:
        """
        Sign evidence with ECDSA (P-256).
        Supports external client-side private key, or falls back to demo key custody with explicit warning.
        """
        if cls.is_revoked(officer_id):
            raise PermissionError(f"Officer {officer_id} key is revoked")

        if external_private_key:
            priv_key = external_private_key
            pub_pem = priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            key_custody_mode = "CLIENT_EXTERNAL_KEY"
        else:
            priv_key, pub_pem = cls.get_or_create_demo_key(officer_id)
            key_custody_mode = "DEMO KEY CUSTODY - not for production"

        payload_digest = cls.compute_signature_payload(evidence_hash, case_id, timestamp, nonce)
        signature_der = priv_key.sign(payload_digest, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(signature_der).decode('utf-8')

        return {
            "officer_id": officer_id,
            "evidence_hash": evidence_hash,
            "case_id": case_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature_algorithm": "ECDSA-SHA256-P256",
            "signature_b64": sig_b64,
            "public_key_pem": pub_pem,
            "key_custody_mode": key_custody_mode,
            "legal_note": "ECDSA digital signature (P-256) - technical authenticity token, legal weight subject to judicial evaluation"
        }

    @classmethod
    def verify_signature(
        cls,
        evidence_hash: str,
        signature_b64: str,
        public_key_pem: str,
        officer_id: Optional[str] = None,
        case_id: str = "INSA-CR-DEMO",
        timestamp: str = "2026-10-10T00:00:00Z",
        nonce: str = "0"
    ) -> bool:
        """
        Verify officer ECDSA signature over anti-replay payload.
        Rejects revoked officers and unregistered keys if officer_id is supplied.
        """
        if officer_id and cls.is_revoked(officer_id):
            return False

        if officer_id and officer_id in cls._registered_public_keys:
            if cls._registered_public_keys[officer_id].strip() != public_key_pem.strip():
                return False

        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            sig_der = base64.b64decode(signature_b64)
            payload_digest = cls.compute_signature_payload(evidence_hash, case_id, timestamp, nonce)
            pub_key.verify(sig_der, payload_digest, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, Exception):
            # Backward compatibility check for plain evidence_hash signature
            try:
                pub_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                sig_der = base64.b64decode(signature_b64)
                pub_key.verify(sig_der, evidence_hash.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                return False

    # Backwards compatibility alias
    @classmethod
    def sign_evidence_hash(cls, officer_id: str, evidence_hash: str, **kwargs) -> Dict[str, Any]:
        return cls.sign_evidence(officer_id, evidence_hash, **kwargs)

