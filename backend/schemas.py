# -*- coding: utf-8 -*-
"""
SecureEvidence: Pydantic Data Models & Validation Schemas
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: AI Engineering, Big Data & Blockchain (INSA)
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict

class NetworkEventInput(BaseModel):
    """Network flow input submitted for AI threat analysis (CICIDS2017 Schema)."""
    model_config = ConfigDict(extra="allow")

    target_asset: Optional[str] = Field(default="National-Gateway-Demo-01", description="Impacted network infrastructure")
    source_ip: Optional[str] = Field(default="198.51.100.45", description="Originating IPv4 address (RFC 5737 demo)")
    destination_ip: Optional[str] = Field(default="192.0.2.1", description="Target destination IPv4 address (RFC 5737 demo)")
    
    # CICIDS2017 Flow Metrics - defaults are None to prevent inflating feature coverage
    flow_duration: Optional[float] = Field(default=None, description="Flow duration in microseconds")
    total_fwd_packets: Optional[float] = Field(default=None, ge=0.0, description="Total packets in forward direction")
    total_backward_packets: Optional[float] = Field(default=None, ge=0.0, description="Total packets in backward direction")
    total_length_fwd_packets: Optional[float] = Field(default=None, ge=0.0, description="Total payload bytes in forward direction")
    total_length_bwd_packets: Optional[float] = Field(default=None, ge=0.0, description="Total payload bytes in backward direction")
    fwd_packet_length_max: Optional[float] = Field(default=None, ge=0.0, description="Maximum size of packet in forward direction")
    fwd_packet_length_mean: Optional[float] = Field(default=None, ge=0.0, description="Mean size of packet in forward direction")
    bwd_packet_length_mean: Optional[float] = Field(default=None, ge=0.0, description="Mean size of packet in backward direction")
    flow_bytes_s: Optional[float] = Field(default=None, ge=0.0, description="Flow byte throughput per second")
    flow_packets_s: Optional[float] = Field(default=None, ge=0.0, description="Flow packet rate per second")
    flow_iat_mean: Optional[float] = Field(default=None, ge=0.0, description="Mean time between two packets sent in the flow")
    flow_iat_std: Optional[float] = Field(default=None, ge=0.0, description="Standard deviation time between two packets")
    fwd_iat_total: Optional[float] = Field(default=None, ge=0.0, description="Total time between two packets sent in forward direction")
    bwd_iat_total: Optional[float] = Field(default=None, ge=0.0, description="Total time between two packets sent in backward direction")
    fwd_packets_s: Optional[float] = Field(default=None, ge=0.0, description="Number of forward packets per second")
    bwd_packets_s: Optional[float] = Field(default=None, ge=0.0, description="Number of backward packets per second")
    packet_length_mean: Optional[float] = Field(default=None, ge=0.0, description="Mean size of packet in flow")
    packet_length_std: Optional[float] = Field(default=None, ge=0.0, description="Standard deviation size of packet in flow")
    fin_flag_count: Optional[float] = Field(default=None, ge=0.0)
    syn_flag_count: Optional[float] = Field(default=None, ge=0.0)
    rst_flag_count: Optional[float] = Field(default=None, ge=0.0)
    psh_flag_count: Optional[float] = Field(default=None, ge=0.0)
    ack_flag_count: Optional[float] = Field(default=None, ge=0.0)
    urg_flag_count: Optional[float] = Field(default=None, ge=0.0)
    down_up_ratio: Optional[float] = Field(default=None, ge=0.0)
    average_packet_size: Optional[float] = Field(default=None, ge=0.0)
    init_win_bytes_forward: Optional[float] = Field(default=None, ge=-1.0)
    init_win_bytes_backward: Optional[float] = Field(default=None, ge=-1.0)

class DetectionResponse(BaseModel):
    """Schema returned after AI inference with Explainable AI (XAI) provenance."""
    is_threat: bool
    threat_score: float
    confidence: float
    threat_category: str
    mitre_attack_id: str
    technique_name: str
    severity: str
    recommended_action: str
    class_probabilities: Dict[str, float]
    feature_attributions: List[Dict[str, Any]] = Field(default_factory=list, description="Top feature drivers for XAI")
    has_disagreement: bool = Field(default=False, description="Flag indicating disagreement between AI model and heuristic rules")
    disagreement_message: Optional[str] = Field(default=None, description="Detailed explanation if model and rules diverge")
    model_prediction: Optional[Dict[str, Any]] = Field(default=None, description="Pure AI model category and confidence")
    rule_prediction: Optional[Dict[str, Any]] = Field(default=None, description="Heuristic rule evaluation")
    feature_coverage_pct: float = Field(default=100.0, description="Percentage of input features with non-zero values")
    feature_coverage: Optional[float] = Field(default=1.0, description="Feature coverage ratio")
    feature_coverage_warning: bool = Field(default=False, description="True if feature coverage is under 80%")
    is_out_of_distribution: Optional[bool] = Field(default=False, description="Out of distribution flag")
    can_anchor: Optional[bool] = Field(default=True, description="Whether this result can be anchored")
    status: Optional[str] = Field(default="CLASSIFIED", description="Inference status")
    missing_features: Optional[List[str]] = Field(default_factory=list, description="List of unobserved schema features")
    missing_count: Optional[int] = Field(default=0, description="Number of missing features")
    provided_count: Optional[int] = Field(default=0, description="Number of provided features")
    total_features: Optional[int] = Field(default=77, description="Total expected features")
    threshold: Optional[float] = Field(default=0.60, description="Required feature coverage threshold")
    message: Optional[str] = Field(default=None, description="Status or refusal message")
    model_version: str = "XGBoost-CICIDS2017-v1.2"
    model_sha256: str = "PENDING"
    dataset_benchmark: str = "CICIDS2017 (Canadian Institute for Cybersecurity)"
    reviewed_by_analyst: bool = False
    target_asset: str
    source_ip: str
    destination_ip: str
    analyst_attribution: str

class EvidenceStoreRequest(BaseModel):
    """Schema for anchoring forensic evidence on the blockchain."""
    case_id: Optional[str] = Field(default=None, description="INSA case identifier (e.g., INSA-CR-2026-0891)")
    incident_type: str = Field(..., description="Threat classification category")
    target_asset: str = Field(..., description="Impacted infrastructure asset")
    investigator: Optional[str] = Field(default=None, description="Forensic Investigator")
    officer_id: Optional[str] = Field(default=None, description="Certified Investigator ID")
    evidence_payload: Dict[str, Any] = Field(..., description="Raw forensic telemetry & detection output")
    raw_artifact_hash: Optional[str] = Field(None, description="SHA-256 of raw seized artifact (PCAP/disk)")

class EvidenceVerifyRequest(BaseModel):
    """Schema for verifying digital evidence authenticity."""
    evidence_payload: Dict[str, Any] = Field(..., description="The forensic record to verify against the blockchain")

class PublicVerifyRequest(BaseModel):
    """Schema for public integrity verification by court clerk or auditor."""
    evidence_hash: Optional[str] = Field(None, description="SHA-256 fingerprint to verify directly")
    raw_text: Optional[str] = Field(None, description="Raw text or JSON content to calculate hash and verify")

class MerkleBatchRequest(BaseModel):
    """Schema for batching multiple telemetry events into a single Merkle root."""
    case_id: Optional[str] = Field(default=None, description="INSA incident case ID")
    events: List[Dict[str, Any]] = Field(..., description="List of network events to batch")
    investigator: Optional[str] = Field(default=None, description="Investigator Name")
    officer_id: Optional[str] = Field(default=None, description="Officer ID")

class SuricataIngestRequest(BaseModel):
    """Schema for ingesting Suricata EVE JSON records."""
    eve_record: Dict[str, Any] = Field(..., description="Raw Suricata EVE JSON event")
    case_id: str = Field(default="INSA-SURICATA-001", description="Target case ID")

class TokenRequest(BaseModel):
    """Schema for requesting a JWT authentication token."""
    username: str = Field(..., description="Username or Officer identifier")
    password: str = Field(..., description="Account secret or password")

class LoginResponse(BaseModel):
    """Schema returned after successful user authentication."""
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: Dict[str, Any]

class ReviewEvidenceRequest(BaseModel):
    """Schema for forensic analyst review of evidence before or after anchoring."""
    evidence_hash: Optional[str] = Field(default=None, description="Forensic SHA-256 evidence hash (if anchored)")
    incident_id: Optional[str] = Field(default=None, description="Detection incident identifier (pre-anchoring)")
    case_id: Optional[str] = Field(default=None, description="Case identifier")
    choice: Optional[str] = Field(default=None, description="Endorsed decision: 'rule' or 'model'")
    threat_category: Optional[str] = Field(default=None, description="Adjudicated threat category")
    justification: Optional[str] = Field(default=None, description="Mandatory written forensic justification")
    notes: Optional[str] = Field(default="Forensic analyst manual verification completed.", description="Review notes")

class SystemHealthResponse(BaseModel):
    """Health check diagnostics response."""
    status: str
    system_name: str
    version: str
    author: str
    email: str
    agency: str
    ai_model_status: str
    blockchain_status: str
    ledger_mode: str
    is_live_chain: bool
    legal_framework: str
    total_evidence_on_chain: int
    demo_mode: bool = False
    ledger_backend: str = "sqlite"
    chain_head_hash: Optional[str] = None
    ledger_integrity: str = "VALID"
    broken_block_id: Optional[int] = None
    chain_mode: str = "off"
    chain_id: Optional[int] = None
    block_number: Optional[int] = None
    contract_address: Optional[str] = None
    connected: bool = False

class StreamControlRequest(BaseModel):
    action: str = Field(..., description="Action to perform: 'start' or 'stop'")
    rate: Optional[int] = Field(default=200, ge=1, le=20000, description="Replay rate in events/second (1..20000)")

