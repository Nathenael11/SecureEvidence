# -*- coding: utf-8 -*-
"""
SecureEvidence: STIX 2.1 Cyber Threat Intelligence Exporter
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: AI Engineering & Cyber Intelligence (INSA)

Generates standardized STIX 2.1 JSON bundles from anchored forensic evidence records.
Prototype export format with honest validation against phantom indicators.
"""

import uuid
import time
import re
import ipaddress
from typing import Dict, Any, List

class STIX2ExportService:
    """Exports anchored forensic evidence into OASIS STIX 2.1 standard format."""

    @staticmethod
    def _is_valid_ipv4(ip_str: Any) -> bool:
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(str(ip_str).strip())
            return ip.version == 4
        except ValueError:
            return False

    @classmethod
    def create_stix_bundle(cls, evidence_record: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a SecureEvidence anchored record into an OASIS STIX 2.1 bundle."""
        bundle_id = f"bundle--{uuid.uuid4()}"
        now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        evidence_hash = evidence_record.get("evidence_hash", "UNKNOWN")
        case_id = evidence_record.get("case_id", "INSA-INCIDENT")
        incident_type = (evidence_record.get("incident_type") or "Network Telemetry").strip()
        target_asset = evidence_record.get("target_asset", "National-Gateway-Demo-01")
        raw_meta = evidence_record.get("raw_evidence", {})

        src_ip = raw_meta.get("source_ip") or evidence_record.get("source_ip")
        mitre_id = raw_meta.get("mitre_attack_id") or evidence_record.get("mitre_attack_id")
        is_threat = (incident_type.upper() != "BENIGN") and (raw_meta.get("is_threat", True))

        # Identity Object: INSA (Prototype Demonstration Export)
        identity_id = f"identity--{uuid.uuid4()}"
        insa_identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_utc,
            "modified": now_utc,
            "name": "Information Network Security Administration (INSA) - Prototype Export",
            "identity_class": "government",
            "sectors": ["government-national", "defense"],
            "description": "SecureEvidence digital forensics prototype demonstration export"
        }

        objects: List[Dict[str, Any]] = [insa_identity]
        object_refs: List[str] = []

        # Validate MITRE ATT&CK ID format (e.g. T1498 or T1498.001)
        valid_mitre = bool(mitre_id and re.match(r"^T\d{4}(\.\d{3})?$", str(mitre_id).strip()))
        attack_pattern_id = None
        indicator_id = None

        # Only generate malicious indicators and attack patterns if record is an actual threat
        if is_threat:
            attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
            ext_refs = []
            if valid_mitre:
                clean_mitre = str(mitre_id).strip()
                ext_refs.append({
                    "source_name": "mitre-attack",
                    "external_id": clean_mitre,
                    "url": f"https://attack.mitre.org/techniques/{clean_mitre.replace('.', '/')}"
                })

            attack_pattern = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id,
                "created": now_utc,
                "modified": now_utc,
                "name": f"Cyber Incident: {incident_type}",
                "description": f"Classified by SecureEvidence AI Engine against {target_asset}",
                "external_references": ext_refs
            }
            objects.append(attack_pattern)
            object_refs.append(attack_pattern_id)

            # Indicator Object: Only if a valid, parseable IPv4 address exists
            if cls._is_valid_ipv4(src_ip):
                indicator_id = f"indicator--{uuid.uuid4()}"
                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now_utc,
                    "modified": now_utc,
                    "name": f"Malicious Traffic from {src_ip}",
                    "pattern_type": "stix",
                    "pattern": f"[ipv4-addr:value = '{src_ip}']",
                    "valid_from": now_utc,
                    "indicator_types": ["malicious-activity", "anomalous-activity"]
                }
                objects.append(indicator)
                object_refs.append(indicator_id)

                # Relationship between indicator and attack pattern
                relationship_id = f"relationship--{uuid.uuid4()}"
                relationship = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": relationship_id,
                    "created": now_utc,
                    "modified": now_utc,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": attack_pattern_id
                }
                objects.append(relationship)

        # Cryptographic Forensics Note
        note_id = f"note--{uuid.uuid4()}"
        forensics_note = {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": now_utc,
            "modified": now_utc,
            "abstract": "Digital Forensics Integrity Proof",
            "content": (
                f"Case: {case_id} | Block #{evidence_record.get('block_number', 0)} | "
                f"Evidence SHA-256: {evidence_hash} | "
                f"Ledger Mode: {evidence_record.get('ledger_mode', 'SIMULATED')} | "
                f"Classification: {incident_type} (Threat: {is_threat}) | "
                f"Statutory Basis: FDRE Computer Crime Proclamation No. 958/2016 (to be verified by legal counsel)"
            ),
            "object_refs": object_refs if object_refs else [identity_id]
        }
        objects.append(forensics_note)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
