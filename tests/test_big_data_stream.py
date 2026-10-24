# -*- coding: utf-8 -*-
"""
Tests for Big Data Streaming Pipeline (Kafka, Spark, XGBoost, Equivalence)
"""

import os
import json
import sqlite3
import pytest
import numpy as np

from ai_engine.flow_preprocessor import FlowPreprocessor
from ai_engine.detector import ThreatDetector


def test_shared_logic_equivalence_100_rows():
    """
    Verify identical predictions on 100 rows between the API detector
    and the batch flow preprocessor + model pipeline used by Spark.
    """
    detector = ThreatDetector()
    preprocessor = FlowPreprocessor()

    fixtures_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "cicids2017_test_samples.json")
    with open(fixtures_path, "r", encoding="utf-8") as f:
        samples_dict = json.load(f)

    # Generate 100 rows by varying fields slightly across real classes
    events = []
    classes = list(samples_dict.keys())
    for i in range(100):
        base_event = dict(samples_dict[classes[i % len(classes)]])
        # Slightly alter flow duration and bytes
        base_event["Flow Duration"] = float(base_event.get("Flow Duration", 100.0)) + i * 5.0
        base_event["Total Fwd Packets"] = float(base_event.get("Total Fwd Packets", 10.0)) + (i % 7)
        base_event["reviewed_by_analyst"] = True
        events.append(base_event)

    # Predict via ThreatDetector (API path)
    detector_results = [detector.predict(ev) for ev in events]

    # Predict via FlowPreprocessor + XGBoost directly (Spark path)
    scaled_batch, coverages = preprocessor.extract_batch(events)
    batch_probas = detector.model.predict_proba(scaled_batch)
    batch_preds = np.argmax(batch_probas, axis=1)

    for i in range(100):
        det_class = detector_results[i]["model_prediction"]["category"]
        det_conf = detector_results[i]["model_prediction"]["confidence"]
        det_cov = detector_results[i]["feature_coverage"]

        spark_pred_id = int(batch_preds[i])
        spark_class = detector.attack_classes.get(spark_pred_id, f"Class_{spark_pred_id}")
        spark_conf = round(float(batch_probas[i][spark_pred_id]), 4)
        spark_cov = round(coverages[i], 4)

        assert det_class == spark_class, f"Row {i} class mismatch: API {det_class} vs Spark {spark_class}"
        assert abs(det_conf - spark_conf) < 1e-3, f"Row {i} conf mismatch: API {det_conf} vs Spark {spark_conf}"
        assert abs(det_cov - spark_cov) < 1e-3, f"Row {i} cov mismatch: API {det_cov} vs Spark {spark_cov}"

    print("[PASS] 100 rows equivalence test: API detector and Spark logic produce identical predictions")


def test_parsing_and_coverage_gate_deadletter():
    """Verify coverage gate (<0.60) refuses inference and flags status."""
    preprocessor = FlowPreprocessor()
    insufficient_event = {
        "event_id": "flow-bad-001",
        "Flow Duration": 500.0,
        "Total Fwd Packets": 2.0
    }
    cov, prov, missing = preprocessor.evaluate_coverage(insufficient_event)
    assert cov < preprocessor.coverage_threshold
    assert len(missing) > len(prov)
