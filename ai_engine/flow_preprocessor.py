# -*- coding: utf-8 -*-
"""
SecureEvidence: Shared Flow Preprocessor and Feature Schema for CICIDS2017
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: AI Engineering & Digital Forensics (INSA)

Used by both the REST API Detector and Spark Structured Streaming Processor
to guarantee identical feature order, normalization, scaling, and coverage gating.
"""

import os
import re
import json
import joblib
import numpy as np
from typing import Dict, Any, List, Tuple, Optional


def normalize_key(key: str) -> str:
    """Strip non-alphanumeric characters and lowercase for flexible dictionary matching."""
    return re.sub(r'[^a-zA-Z0-9]', '', str(key)).lower()


# Explicit alias map for alternate naming conventions in CICIDS2017 / Suricata / Zeek
CICIDS_KEY_ALIASES: Dict[str, List[str]] = {
    "Total Length of Fwd Packets": ["total_length_of_fwd_packets", "total_length_fwd_packets", "fwd_bytes", "totlen_fwd_pkts"],
    "Total Length of Bwd Packets": ["total_length_of_bwd_packets", "total_length_bwd_packets", "bwd_bytes", "totlen_bwd_pkts"],
    "Flow Packets/s": ["flow_packets_s", "packet_rate", "flow_pkts_s"],
    "Flow Bytes/s": ["flow_bytes_s", "byte_rate", "flow_byts_s"],
    "SYN Flag Count": ["syn_flag_count", "syn_count", "syn_flags"],
    "RST Flag Count": ["rst_flag_count", "rst_count", "rst_flags"],
    "PSH Flag Count": ["psh_flag_count", "psh_count", "psh_flags"],
    "ACK Flag Count": ["ack_flag_count", "ack_count", "ack_flags"],
    "FIN Flag Count": ["fin_flag_count", "fin_count", "fin_flags"],
    "URG Flag Count": ["urg_flag_count", "urg_count", "urg_flags"],
    "Total Fwd Packets": ["total_fwd_packets", "tot_fwd_pkts", "fwd_packets"],
    "Total Backward Packets": ["total_backward_packets", "tot_bwd_pkts", "bwd_packets"],
    "Flow Duration": ["flow_duration", "duration"]
}


class FlowPreprocessor:
    """
    Shared preprocessing logic for network flow events.
    Enforces identical feature ordering, standard scaling, and coverage gating (<0.60).
    """

    def __init__(self, models_dir: Optional[str] = None):
        if models_dir is None:
            models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

        self.models_dir = models_dir
        self.meta_path = os.path.join(models_dir, "model_metadata.json")
        self.scaler_path = os.path.join(models_dir, "feature_scaler.joblib")
        self.coverage_threshold = float(os.getenv("FEATURE_COVERAGE_THRESHOLD", "0.60"))

        self.feature_columns: List[str] = []
        self.metadata: Dict[str, Any] = {}
        self.scaler = None

        self._load_artifacts()

    def _load_artifacts(self):
        if os.path.exists(self.meta_path):
            with open(self.meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
            self.feature_columns = self.metadata.get("feature_columns", [])

        if os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)

    def _extract_single_row(self, event: Dict[str, Any]) -> Tuple[List[float], Dict[str, float]]:
        """
        Helper extracting ordered feature values and raw feature dictionary for a single flow event.
        Checks exact column name, explicit alias list, snake_case, and stripped key.
        """
        event_lookup = {}
        for k, v in event.items():
            if isinstance(k, str):
                event_lookup[normalize_key(k)] = v
                event_lookup[k] = v

        values = []
        raw_feature_map = {}

        for col in self.feature_columns:
            val = None
            if col in event:
                val = event[col]
            else:
                # Check explicit aliases
                aliases = CICIDS_KEY_ALIASES.get(col, [])
                for alias in aliases:
                    if alias in event:
                        val = event[alias]
                        break
                    norm_alias = normalize_key(alias)
                    if norm_alias in event_lookup:
                        val = event_lookup[norm_alias]
                        break

                # Fallback to normalized and snake_case keys
                if val is None:
                    norm_col = normalize_key(col)
                    if norm_col in event_lookup:
                        val = event_lookup[norm_col]
                    elif col.replace(" ", "_").lower() in event:
                        val = event[col.replace(" ", "_").lower()]
                    elif col.replace(" ", "").lower() in event_lookup:
                        val = event_lookup[col.replace(" ", "").lower()]

            if val is None:
                val = 0.0
            try:
                val = float(val)
                if np.isnan(val) or np.isinf(val):
                    val = 0.0
            except (ValueError, TypeError):
                val = 0.0

            values.append(val)
            raw_feature_map[col] = val

        return values, raw_feature_map

    def evaluate_coverage(self, event: Dict[str, Any]) -> Tuple[float, List[str], List[str]]:
        """
        Evaluate feature coverage for an incoming flow event.
        Returns: (coverage_ratio, provided_features, missing_features)
        """
        event_lookup = {}
        for k, v in event.items():
            if isinstance(k, str):
                event_lookup[normalize_key(k)] = v
                event_lookup[k] = v

        provided_features = []
        missing_features = []
        for col in self.feature_columns:
            found = False
            if col in event:
                found = True
            else:
                for alias in CICIDS_KEY_ALIASES.get(col, []):
                    if alias in event or normalize_key(alias) in event_lookup:
                        found = True
                        break
                if not found:
                    norm_col = normalize_key(col)
                    if (norm_col in event_lookup or
                        col.replace(" ", "_").lower() in event or
                        col.replace(" ", "").lower() in event_lookup):
                        found = True

            if found:
                provided_features.append(col)
            else:
                missing_features.append(col)

        coverage_ratio = len(provided_features) / max(1, len(self.feature_columns))
        return coverage_ratio, provided_features, missing_features

    def extract_features(self, event: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, float]]:
        """
        Convert input flow dictionary to scaled CICIDS2017 feature vector (1, N) and raw mapped values.
        """
        values, raw_feature_map = self._extract_single_row(event)
        arr = np.array([values], dtype=np.float32)
        if self.scaler is not None:
            scaled_arr = self.scaler.transform(arr)
        else:
            scaled_arr = arr
        return scaled_arr, raw_feature_map

    def extract_batch(self, events: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[float]]:
        """
        Batch feature extraction and scaling.
        Returns: (scaled_matrix, coverage_ratios)
        """
        matrix_rows = []
        coverages = []
        for event in events:
            cov, _, _ = self.evaluate_coverage(event)
            coverages.append(cov)
            values, _ = self._extract_single_row(event)
            matrix_rows.append(values)

        arr = np.array(matrix_rows, dtype=np.float32)
        if self.scaler is not None and len(arr) > 0:
            scaled_arr = self.scaler.transform(arr)
        else:
            scaled_arr = arr
        return scaled_arr, coverages
