# -*- coding: utf-8 -*-
"""
SecureEvidence: CICIDS2017 Threat Inference Engine with Explainable AI (XAI)
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: AI Engineering & Digital Forensics (INSA)

Production inference engine loading XGBoost model to perform real-time
flow classification across 12 CICIDS2017 classes, directional feature attribution
(TreeSHAP-style explainability), cryptographic model provenance, and MITRE ATT&CK mapping.
"""

import os
import re
import math
import json
import joblib
import hashlib
import numpy as np
from typing import Dict, Any, List, Tuple
import xgboost as xgb
from xgboost import XGBClassifier
from .flow_preprocessor import FlowPreprocessor, normalize_key

# 12 Target classes matching LabelEncoder and model_metadata.json
CICIDS_ATTACK_CLASSES: Dict[int, str] = {
    0: "BENIGN",
    1: "Bot",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    7: "FTP-Patator",
    8: "Other_Attack",
    9: "PortScan",
    10: "SSH-Patator",
    11: "Web_Attack"
}

# MITRE ATT&CK mapping for all 12 CICIDS2017 threat classes
CICIDS_MITRE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "BENIGN": {
        "mitre_id": "N/A",
        "technique": "Benign Baseline Flow",
        "severity": "LOW",
        "action": "Allow Traffic & Record Baseline Telemetry"
    },
    "Bot": {
        "mitre_id": "T1071.001",
        "technique": "Command and Control: Application Layer Protocol / Botnet C2",
        "severity": "CRITICAL",
        "action": "Isolate Infected Endpoint, Block C2 Destination Subnet & Capture Memory Forensics"
    },
    "DDoS": {
        "mitre_id": "T1498.001",
        "technique": "Network Denial of Service: Direct Network Flood",
        "severity": "CRITICAL",
        "action": "Trigger Perimeter BGP Blackholing & Ingress Rate-Limiting"
    },
    "DoS GoldenEye": {
        "mitre_id": "T1498",
        "technique": "Network Denial of Service: HTTP Keep-Alive Connection Exhaustion",
        "severity": "HIGH",
        "action": "Deploy Anti-DDoS WAF Mitigation & Terminate Persistent Idle HTTP Connections"
    },
    "DoS Hulk": {
        "mitre_id": "T1498",
        "technique": "Network Denial of Service: High-Volume Obfuscated HTTP Request Flood",
        "severity": "HIGH",
        "action": "Enable Dynamic Rate-Limiting & Challenge Responses on Application Gateway"
    },
    "DoS Slowhttptest": {
        "mitre_id": "T1499.001",
        "technique": "Endpoint Denial of Service: Slow Request Attack",
        "severity": "HIGH",
        "action": "Enforce Strict Connection Timeouts and Minimum Header Data Rates"
    },
    "DoS slowloris": {
        "mitre_id": "T1499.001",
        "technique": "Endpoint Denial of Service: Slowloris Connection Exhaustion",
        "severity": "HIGH",
        "action": "Limit Concurrent Connections Per Client IP on Reverse Proxy"
    },
    "FTP-Patator": {
        "mitre_id": "T1110.001",
        "technique": "Brute Force: Password Guessing on FTP Port 21",
        "severity": "HIGH",
        "action": "Enforce IP Ban on Probing Source, Reset Credentials & Audit Access Logs"
    },
    "Other_Attack": {
        "mitre_id": "T1059",
        "technique": "Execution: Command and Scripting Interpreter / Unclassified Exploitation",
        "severity": "HIGH",
        "action": "Quarantine Active Session, Dump Packet Payloads & Secure Cryptographic Hash"
    },
    "PortScan": {
        "mitre_id": "T1046",
        "technique": "Network Service Discovery: Port Scanning",
        "severity": "MEDIUM",
        "action": "Blacklist Probing Subnet on Perimeter Firewalls & Revoke Ingress"
    },
    "SSH-Patator": {
        "mitre_id": "T1110.001",
        "technique": "Brute Force: Password Guessing on SSH Port 22",
        "severity": "HIGH",
        "action": "Enforce Multi-Factor Authentication Lockout, Block Remote IP & Rotate SSH Keys"
    },
    "Web_Attack": {
        "mitre_id": "T1190",
        "technique": "Exploit Public-Facing Application: Web Vulnerability / SQLi / XSS",
        "severity": "CRITICAL",
        "action": "Block Session via WAF, Capture SQL/HTTP Payload & Anchor Forensic Hash to Blockchain"
    }
}

CATEGORY_ALIASES = {
    "Botnet_Infiltration": "Bot",
    "Web_Attack_Brute_Force": "Web_Attack",
    "Web_Attack_SQL_Injection": "Web_Attack",
    "Web_Attack_XSS": "Web_Attack",
    "Brute_Force": "SSH-Patator"
}

class ThreatDetector:
    """Production AI Threat Detector with Explainable AI for INSA Forensics Operations."""
    
    def __init__(self, models_dir: str = None):
        if models_dir is None:
            models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
            
        self.models_dir = models_dir
        self.model_path = os.path.join(models_dir, "threat_detector_xgb.json")
        self.scaler_path = os.path.join(models_dir, "feature_scaler.joblib")
        self.encoder_path = os.path.join(models_dir, "label_encoder.joblib")
        self.meta_path = os.path.join(models_dir, "model_metadata.json")
        
        self.model = None
        self.scaler = None
        self.encoder = None
        self.metadata = {}
        self.feature_columns = []
        self.attack_classes = {}
        self.model_hash = "UNKNOWN"
        self.coverage_threshold = float(os.getenv("FEATURE_COVERAGE_THRESHOLD", "0.60"))
        
        self._load_or_initialize()
        
    def _load_or_initialize(self):
        """Load trained model or auto-train if missing, and compute model SHA-256."""
        if not os.path.exists(self.model_path) or not os.path.exists(self.scaler_path):
            print("[*] Trained model artifacts not found. Training on CICIDS2017 dataset...")
            try:
                from .train import train_and_evaluate
            except ImportError:
                from train import train_and_evaluate
            train_and_evaluate(self.models_dir)
            
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                self.model_hash = hashlib.sha256(f.read()).hexdigest()

        if os.path.exists(self.meta_path):
            with open(self.meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
                
        self.feature_columns = self.metadata.get("feature_columns", [])
            
        raw_classes = self.metadata.get("attack_classes", None)
        if isinstance(raw_classes, list):
            self.attack_classes = {i: str(v) for i, v in enumerate(raw_classes)}
        elif isinstance(raw_classes, dict):
            self.attack_classes = {int(k): str(v) for k, v in raw_classes.items()}
            
        if os.path.exists(self.encoder_path):
            try:
                self.encoder = joblib.load(self.encoder_path)
                if hasattr(self.encoder, "classes_") and not self.attack_classes:
                    self.attack_classes = {i: str(cls_name) for i, cls_name in enumerate(self.encoder.classes_)}
            except Exception as e:
                print(f"[!] Note: Label encoder fallback: {e}")

        if not self.attack_classes:
            self.attack_classes = dict(CICIDS_ATTACK_CLASSES)
        
        self.preprocessor = FlowPreprocessor(models_dir=self.models_dir)
        self.scaler = self.preprocessor.scaler
        self.model = XGBClassifier()
        self.model.load_model(self.model_path)
        print(f"[OK] ThreatDetector loaded with 12 classes. Model SHA-256: {self.model_hash[:16]}...")
        
    def extract_features(self, event: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, float]]:
        """Convert input flow dictionary to formatted CICIDS2017 feature vector and raw mapped values."""
        return self.preprocessor.extract_features(event)

    def explain_prediction(self, raw_features: Dict[str, float], scaled_features: np.ndarray, predicted_class_id: int) -> List[Dict[str, Any]]:
        """
        Compute top driving feature attributions using XGBoost native TreeSHAP (pred_contribs=True).
        Generates contextual courtroom explanations comparing raw telemetry against training distributions.
        """
        attribution_method = "TreeSHAP"
        try:
            booster = self.model.get_booster()
            dmat = xgb.DMatrix(scaled_features)
            # shape: (1, num_classes, num_features + 1) or (1, num_features + 1)
            shap_matrix = booster.predict(dmat, pred_contribs=True)
            if len(shap_matrix.shape) == 3:
                class_idx = max(0, min(predicted_class_id, shap_matrix.shape[1] - 1))
                shap_values = shap_matrix[0, class_idx, :len(self.feature_columns)]
            elif len(shap_matrix.shape) == 2:
                shap_values = shap_matrix[0, :len(self.feature_columns)]
            else:
                shap_values = np.zeros(len(self.feature_columns))
        except Exception:
            # Fallback to feature importance * scaled value
            attribution_method = "approximate importance"
            importances = getattr(self.model, "feature_importances_", np.zeros(len(self.feature_columns)))
            shap_values = importances * scaled_features[0]

        means = getattr(self.scaler, "mean_", np.zeros(len(self.feature_columns)))
        scales = getattr(self.scaler, "scale_", np.ones(len(self.feature_columns)))

        attributions = []
        for idx, col in enumerate(self.feature_columns):
            shap_val = float(shap_values[idx])
            raw_val = raw_features.get(col, 0.0)
            scaled_val = float(scaled_features[0][idx])
            mean_val = float(means[idx]) if idx < len(means) else 0.0

            # Calculate empirical percentile using training distribution in model_metadata.json
            emp_pcts = self.metadata.get("empirical_percentiles", {}).get(col, {})
            if emp_pcts:
                if raw_val <= emp_pcts.get("p10", 0.0):
                    pctile = 10.0
                elif raw_val <= emp_pcts.get("p25", 0.0):
                    pctile = 25.0
                elif raw_val <= emp_pcts.get("p50", 0.0):
                    pctile = 50.0
                elif raw_val <= emp_pcts.get("p75", 0.0):
                    pctile = 75.0
                elif raw_val <= emp_pcts.get("p90", 0.0):
                    pctile = 90.0
                elif raw_val <= emp_pcts.get("p99", 0.0):
                    pctile = 99.0
                else:
                    pctile = 99.9
            else:
                pctile = round(0.5 * (1.0 + math.erf(scaled_val / math.sqrt(2.0))) * 100.0, 1)

            # Generate human-readable telemetry explanation
            col_lower = col.lower()
            readable_name = col.replace("_", " ")
            if "flag" in col_lower:
                if raw_val > 0:
                    reason = f"{readable_name} flag active in packet headers."
                else:
                    reason = f"{readable_name} flag inactive."
            elif "duration" in col_lower:
                reason = f"Flow duration of {raw_val:,.1f} µs ({pctile:.0f}th percentile of baseline traffic)."
            elif "packet" in col_lower or "byte" in col_lower:
                reason = f"Recorded {readable_name} ({raw_val:,.1f}) matches {pctile:.0f}th percentile of baseline traffic."
            else:
                reason = f"Observed {readable_name} at {raw_val:,.2f} ({pctile:.0f}th percentile of baseline traffic)."

            attributions.append({
                "feature": col,
                "raw_value": round(raw_val, 4),
                "shap_value": round(shap_val, 4),
                "impact_score": round(shap_val, 4),
                "scaled_z_score": round(scaled_val, 3),
                "percentile": pctile,
                "attribution_method": attribution_method,
                "explanation": reason
            })

        # Rank by absolute SHAP impact
        attributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        return attributions[:5]

    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Perform threat classification with single source of truth, coverage gate, and model/rule consistency verification."""
        # 1. Feature Coverage & Telemetry Gate Check
        feature_coverage_ratio, provided_features, missing_features = self.preprocessor.evaluate_coverage(event)
        feature_coverage_pct = round(feature_coverage_ratio * 100.0, 1)

        # Enforce coverage gate: refuse inference if coverage < threshold
        if feature_coverage_ratio < self.coverage_threshold:
            return {
                "status": "INSUFFICIENT_DATA",
                "is_threat": False,
                "threat_score": 0.0,
                "confidence": 0.0,
                "threat_category": "INSUFFICIENT_DATA",
                "severity": "N/A",
                "mitre_attack_id": "None (Inference Refused)",
                "technique_name": "Telemetry Incomplete",
                "recommended_action": f"Provide at least {int(self.coverage_threshold*100)}% of network flow features (current: {feature_coverage_pct}%).",
                "feature_coverage_pct": feature_coverage_pct,
                "feature_coverage": round(feature_coverage_ratio, 4),
                "threshold": self.coverage_threshold,
                "missing_features": missing_features,
                "missing_count": len(missing_features),
                "provided_count": len(provided_features),
                "total_features": len(self.feature_columns),
                "is_out_of_distribution": True,
                "can_anchor": False,
                "has_disagreement": False,
                "disagreement_message": None,
                "model_prediction": None,
                "rule_prediction": None,
                "class_probabilities": {},
                "feature_attributions": [],
                "model_version": self.metadata.get("model_version", f"XGBoost-CICIDS2017-v{self.metadata.get('schema_version', '1.2')}"),
                "model_sha256": self.model_hash,
                "dataset_benchmark": "CICIDS2017 (Canadian Institute for Cybersecurity)",
                "reviewed_by_analyst": False,
                "target_asset": event.get("target_asset", "National-Gateway-Demo-01"),
                "source_ip": event.get("source_ip", "198.51.100.45"),
                "destination_ip": event.get("destination_ip", "192.0.2.1"),
                "analyst_attribution": "SecureEvidence Forensics Prototype",
                "message": f"Inference refused: feature coverage ({feature_coverage_pct}%) is below required threshold ({self.coverage_threshold*100:.0f}%). Telemetry requires at least {int(self.coverage_threshold*len(self.feature_columns))} of {len(self.feature_columns)} flow features."
            }

        scaled_features, raw_features = self.extract_features(event)
        
        # 2. Pure model output (the single source of truth for probabilities)
        probas = self.model.predict_proba(scaled_features)[0]
        model_class_id = int(np.argmax(probas))
        model_category = self.attack_classes.get(model_class_id, "Unknown")
        model_confidence = float(probas[model_class_id])
        
        class_probabilities = {
            self.attack_classes.get(i, f"Class_{i}"): round(float(prob), 4)
            for i, prob in enumerate(probas)
        }

        # OOD / Low-confidence determination
        is_out_of_distribution = (model_confidence < 0.65 or feature_coverage_ratio < 0.85)

        # 3. Independent heuristic signature rules (based strictly on telemetry, not model outputs)
        syn_count = float(event.get("syn_flag_count", event.get("SYN Flag Count", 0)))
        rst_count = float(event.get("rst_flag_count", event.get("RST Flag Count", 0)))
        pkt_rate = float(event.get("flow_packets_s", event.get("Flow Packets/s", event.get("packet_rate", 0))))
        fwd_pkts = float(event.get("total_fwd_packets", event.get("Total Fwd Packets", 0)))
        failed_logins = float(event.get("failed_logins", 0))
        entropy = float(event.get("byte_entropy", 0))

        rule_category = None
        rule_name = None
        rule_reason = None

        if (syn_count > 0 and (pkt_rate > 300 or fwd_pkts > 100)) or pkt_rate > 2000:
            rule_category = "DDoS"
            rule_name = "SYN_FLOOD_THRESHOLD_RULE"
            rule_reason = f"Active SYN flag and packet rate ({pkt_rate:.1f} pkt/s) exceeds threshold"
        elif rst_count > 0 and syn_count > 0:
            rule_category = "PortScan"
            rule_name = "RST_SYN_SCAN_RULE"
            rule_reason = "Concurrent active RST and SYN flags"
        elif failed_logins >= 3:
            rule_category = "SSH-Patator"
            rule_name = "FAILED_LOGIN_BURST_RULE"
            rule_reason = f"Consecutive failed logins count ({int(failed_logins)}) >= 3"
        elif entropy > 7.0:
            rule_category = "Bot"
            rule_name = "PAYLOAD_ENTROPY_RULE"
            rule_reason = f"High byte entropy ({entropy:.2f}) indicates encrypted C2 beaconing"

        # 4. Conflict resolution & Disagreement detection (Item 12: severity UNDETERMINED, no MITRE assertion)
        has_disagreement = False
        disagreement_message = None

        if rule_category is not None and rule_category != model_category:
            has_disagreement = True
            disagreement_message = (
                f"MODEL/RULE DISAGREEMENT - analyst review required: "
                f"Model predicts '{model_category}' ({model_confidence * 100:.1f}%), "
                f"Heuristic rule predicts '{rule_category}' ({rule_reason})."
            )
            threat_category = "MODEL/RULE DISAGREEMENT - analyst review required"
            is_threat = True
            confidence = round(model_confidence, 4)
            action = f"Flag flow for urgent manual analyst review before anchoring. Model: {model_category} ({model_confidence*100:.1f}%) vs Rule: {rule_category}."
            severity = "UNDETERMINED"
            technique_name = "None (Disagreement Requires Analyst Adjudication)"
            mitre_id = "None - Model/Rule Disagreement"
        else:
            threat_category = model_category
            is_threat = (model_class_id != 0)
            confidence = round(model_confidence, 4)
            canonical_name = CATEGORY_ALIASES.get(model_category, model_category)
            mitre_info = CICIDS_MITRE_MAPPINGS.get(canonical_name, {
                "mitre_id": "T1000",
                "technique": f"Network Telemetry ({model_category})",
                "severity": "HIGH" if is_threat else "LOW",
                "action": "Quarantine Flow & Investigate"
            })
            action = mitre_info["action"]
            severity = mitre_info["severity"]
            technique_name = mitre_info["technique"]
            mitre_id = mitre_info["mitre_id"]

        threat_score = round(float(1.0 - class_probabilities.get("BENIGN", 0.0)), 4)
        top_explanations = self.explain_prediction(raw_features, scaled_features, model_class_id)
        
        can_anchor = (not has_disagreement) or bool(event.get("reviewed_by_analyst", False))

        return {
            "status": "CLASSIFIED",
            "is_threat": is_threat,
            "threat_score": threat_score,
            "confidence": confidence,
            "threat_category": threat_category,
            "has_disagreement": has_disagreement,
            "disagreement_message": disagreement_message,
            "model_prediction": {
                "category": model_category,
                "confidence": round(model_confidence, 4),
                "is_threat": (model_class_id != 0)
            },
            "rule_prediction": {
                "category": rule_category,
                "rule_name": rule_name,
                "reason": rule_reason
            } if rule_category else None,
            "mitre_attack_id": mitre_id,
            "technique_name": technique_name,
            "severity": severity,
            "recommended_action": action,
            "class_probabilities": class_probabilities,
            "feature_attributions": top_explanations,
            "feature_coverage_pct": feature_coverage_pct,
            "feature_coverage": round(feature_coverage_ratio, 4),
            "feature_coverage_warning": (feature_coverage_pct < 80.0),
            "is_out_of_distribution": is_out_of_distribution,
            "can_anchor": can_anchor,
            "model_version": self.metadata.get("model_version", f"XGBoost-CICIDS2017-v{self.metadata.get('schema_version', '1.2')}"),
            "model_sha256": self.model_hash,
            "dataset_benchmark": "CICIDS2017 (Canadian Institute for Cybersecurity)",
            "reviewed_by_analyst": bool(event.get("reviewed_by_analyst", False)),
            "target_asset": event.get("target_asset", "National-Gateway-Demo-01"),
            "source_ip": event.get("source_ip", "198.51.100.45"),
            "destination_ip": event.get("destination_ip", "192.0.2.1"),
            "analyst_attribution": "SecureEvidence Forensics Prototype"
        }
