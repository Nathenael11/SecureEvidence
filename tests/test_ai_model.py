# -*- coding: utf-8 -*-
"""
Unit Tests for CICIDS2017 AI Threat Detection Engine & Explainability
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import json
import pytest
import numpy as np
from ai_engine.detector import ThreatDetector, CICIDS_ATTACK_CLASSES

@pytest.fixture(scope="module")
def cicids_fixtures():
    with open("tests/fixtures/cicids2017_test_samples.json", "r", encoding="utf-8") as f:
        return json.load(f)

def test_attack_classes_schema():
    """Verify CICIDS2017 target classes schema and complete 12-class taxonomy."""
    assert len(CICIDS_ATTACK_CLASSES) == 12
    assert CICIDS_ATTACK_CLASSES[0] == "BENIGN"
    assert "DDoS" in CICIDS_ATTACK_CLASSES.values()
    assert "PortScan" in CICIDS_ATTACK_CLASSES.values()
    assert "Web_Attack" in CICIDS_ATTACK_CLASSES.values()

def test_detector_inference_ddos(cicids_fixtures):
    """Verify full-featured DDoS flow triggers threat detection and pure DDoS classification."""
    detector = ThreatDetector()
    ddos_flow = cicids_fixtures["DDoS"]
    pred = detector.predict(ddos_flow)
    assert pred["is_threat"] is True
    assert pred["has_disagreement"] is False
    assert pred["threat_category"] == "DDoS"
    assert pred["severity"] == "CRITICAL"
    assert pred["can_anchor"] is True

def test_detector_inference_benign(cicids_fixtures):
    """Verify benign traffic classification."""
    detector = ThreatDetector()
    benign_flow = cicids_fixtures["BENIGN"]
    pred = detector.predict(benign_flow)
    assert pred["is_threat"] is False
    assert pred["threat_category"] == "BENIGN"
    assert pred["severity"] == "LOW"
    assert pred["can_anchor"] is True

def test_displayed_label_equals_argmax_of_probabilities(cicids_fixtures):
    """
    Requirement 1: Displayed threat_category equals the argmax of class_probabilities
    when there is no model/rule disagreement.
    """
    detector = ThreatDetector()
    flows = [
        cicids_fixtures["BENIGN"],
        cicids_fixtures.get("PortScan", cicids_fixtures["BENIGN"])
    ]
    for flow in flows:
        pred = detector.predict(flow)
        if not pred.get("has_disagreement", False) and pred.get("status") == "CLASSIFIED":
            probs = pred["class_probabilities"]
            max_class = max(probs.items(), key=lambda item: item[1])[0]
            assert pred["threat_category"] == max_class, (
                f"Threat category '{pred['threat_category']}' does not match argmax '{max_class}' of probabilities: {probs}"
            )

def test_model_rule_disagreement_detection(cicids_fixtures):
    """
    Requirement 1: If heuristic rule and model diverge, system must set has_disagreement=True
    and label as 'MODEL/RULE DISAGREEMENT - analyst review required'.
    """
    detector = ThreatDetector()
    disagree_flow = cicids_fixtures["Disagreement_Sample"]
    pred = detector.predict(disagree_flow)
    assert "has_disagreement" in pred
    assert pred["has_disagreement"] is True
    assert pred["threat_category"] == "MODEL/RULE DISAGREEMENT - analyst review required"
    assert pred["severity"] == "UNDETERMINED"
    assert pred["can_anchor"] is False
    assert pred["disagreement_message"] is not None

def test_treeshap_feature_contributions_vary_with_input(cicids_fixtures):
    """
    Requirement 4: Feature contributions must vary with input and not be hardcoded constants.
    """
    detector = ThreatDetector()
    flow_a = cicids_fixtures["DDoS"]
    flow_b = cicids_fixtures["BENIGN"]

    pred_a = detector.predict(flow_a)
    pred_b = detector.predict(flow_b)

    xai_a = pred_a.get("feature_attributions", [])
    xai_b = pred_b.get("feature_attributions", [])

    assert len(xai_a) > 0
    assert len(xai_b) > 0

    scores_a = [item["impact_score"] for item in xai_a]
    scores_b = [item["impact_score"] for item in xai_b]

    assert scores_a != scores_b, "TreeSHAP impact scores did not change between disparate traffic flows!"

def test_feature_coverage_calculation():
    """
    Requirement 10: Feature coverage percentage must be computed accurately
    and warn / refuse when below threshold.
    """
    detector = ThreatDetector()
    sparse_flow = {
        "target_asset": "Sparse-Asset",
        "flow_duration": 100.0
    }
    pred = detector.predict(sparse_flow)
    assert "feature_coverage_pct" in pred
    assert pred["feature_coverage_pct"] < 50.0
    assert pred["status"] == "INSUFFICIENT_DATA"
    assert pred["can_anchor"] is False
    assert len(pred["missing_features"]) > 50

def test_metadata_attack_classes_matches_label_encoder():
    """Item 5: Assert metadata['attack_classes'] == list(label_encoder.classes_)."""
    import os, joblib, json
    meta_path = "ai_engine/models/model_metadata.json"
    encoder_path = "ai_engine/models/label_encoder.joblib"
    assert os.path.exists(meta_path)
    assert os.path.exists(encoder_path)

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    encoder = joblib.load(encoder_path)

    assert meta["attack_classes"] == list(encoder.classes_)

def test_eval_report_keys_and_ablation():
    """Item 23: Verify ai_engine/models/eval_report.json has required metrics and ablation."""
    import os, json
    report_path = "ai_engine/models/eval_report.json"
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Support both flat top-level layout and nested stratified_split_results layout
    metrics = data.get("stratified_split_results") or data
    assert "macro_f1" in metrics, f"Missing macro_f1, keys={list(data.keys())}"
    assert "per_class_metrics" in metrics
    assert isinstance(metrics["per_class_metrics"], dict)
    # Ablation study for Destination Port
    ablation = metrics.get("ablation_study") or data.get("ablation_study") or data.get("destination_port_ablation")
    assert ablation is not None, "Missing ablation study"
    assert "with_destination_port" in ablation
    assert "without_destination_port" in ablation
    # Metadata fields (new schema)
    if "metadata" in data:
        assert data["metadata"]["dedup_before_split"] is True
        assert data["metadata"]["rows_removed_by_dedup"] == 330959


