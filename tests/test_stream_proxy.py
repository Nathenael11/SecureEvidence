# -*- coding: utf-8 -*-
"""
Tests for WSL Stream Proxy and Stream Control Endpoints
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app
from backend.security import create_jwt_token, AuditLogger

client = TestClient(app)

def get_auth_headers(role: str, username: str = "testuser", officer_id: str = "INSA-TEST-01"):
    token, _ = create_jwt_token(
        subject=username,
        role=role,
        full_name=f"Test {role.title()}",
        officer_id=officer_id
    )
    return {"Authorization": f"Bearer {token}"}


def test_stream_status_proxy_running():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "running": True,
        "pipeline_state": "RUNNING",
        "events_scored": 1250,
        "threats_detected": 42,
        "events_per_sec": 210.5,
        "consumer_lag": 5,
        "deadletter_count": 0,
        "timestamp": "2026-10-19T12:00:00Z"
    }

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        res = client.get("/stream/status", headers=get_auth_headers("analyst"))
        assert res.status_code == 200
        data = res.json()
        assert data["running"] is True
        assert data["events_scored"] == 1250
        assert data["consumer_lag"] == 5


def test_stream_status_proxy_stopped_unreachable():
    # When WSL Stream API is unreachable, must return stopped with real zeros, never fake numbers
    with patch("httpx.AsyncClient.get", side_effect=Exception("Connection refused")):
        res = client.get("/stream/status", headers=get_auth_headers("analyst"))
        assert res.status_code == 200
        data = res.json()
        assert data["running"] is False
        assert data["pipeline_state"] == "STOPPED"
        assert data["events_scored"] == 0
        assert data["threats_detected"] == 0
        assert data["events_per_sec"] == 0.0
        assert data["consumer_lag"] == 0
        assert data["unreachable"] is True


def test_stream_alerts_proxy():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "alerts": [
            {
                "event_id": "ev-001",
                "predicted_class": "DDoS",
                "confidence": 0.99,
                "feature_coverage": 1.0,
                "status": "VALID",
                "ground_truth_label": "DDoS"
            }
        ],
        "total": 1
    }

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        res = client.get("/stream/alerts", headers=get_auth_headers("investigator"))
        assert res.status_code == 200
        data = res.json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["event_id"] == "ev-001"


def test_stream_windows_proxy():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "windows": [
            {
                "window_start": "2026-10-19T12:00:00Z",
                "window_end": "2026-10-19T12:01:00Z",
                "event_count": 600,
                "class_counts": {"BENIGN": 500, "DDoS": 100},
                "mean_confidence": 0.985
            }
        ],
        "total": 1
    }

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        res = client.get("/stream/windows", headers=get_auth_headers("court_auditor"))
        assert res.status_code == 200
        data = res.json()
        assert len(data["windows"]) == 1
        assert data["windows"][0]["event_count"] == 600


def test_stream_control_rejects_wrong_role():
    # Analyst cannot control stream pipeline
    res = client.post(
        "/stream/control",
        headers=get_auth_headers("analyst"),
        json={"action": "start", "rate": 200}
    )
    assert res.status_code == 403

    # Court auditor cannot control stream pipeline
    res = client.post(
        "/stream/control",
        headers=get_auth_headers("court_auditor"),
        json={"action": "start", "rate": 200}
    )
    assert res.status_code == 403


def test_stream_control_rejects_invalid_action():
    res = client.post(
        "/stream/control",
        headers=get_auth_headers("investigator"),
        json={"action": "restart_unknown", "rate": 200}
    )
    assert res.status_code == 400


def test_stream_control_rejects_bad_rate():
    # Rate < 1
    res = client.post(
        "/stream/control",
        headers=get_auth_headers("investigator"),
        json={"action": "start", "rate": 0}
    )
    assert res.status_code == 422 or res.status_code == 400

    # Rate > 20000
    res = client.post(
        "/stream/control",
        headers=get_auth_headers("investigator"),
        json={"action": "start", "rate": 25000}
    )
    assert res.status_code == 422 or res.status_code == 400


def test_stream_control_start_success_and_audit_log():
    mock_proc = MagicMock()
    mock_proc.stdout = "Spark streaming pipeline started (PID 12345)"
    mock_proc.stderr = ""

    with patch("subprocess.run", return_value=mock_proc) as mock_sub:
        res = client.post(
            "/stream/control",
            headers=get_auth_headers("investigator", username="inv_nathenael", officer_id="INSA-INV-42"),
            json={"action": "start", "rate": 500}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["action"] == "start"
        assert data["rate"] == 500
        assert "started" in data["output"]

        # Confirm subprocess called with shell=False
        assert mock_sub.called
        kwargs = mock_sub.call_args[1]
        assert kwargs.get("shell") is False

        # Confirm audit log entry recorded
        recent_logs = AuditLogger.get_recent_logs(10)
        matching = [l for l in recent_logs if l.get("endpoint") == "/stream/control"]
        assert len(matching) > 0
        last_entry = matching[0]
        assert "start" in last_entry.get("details", "")
        assert "500" in last_entry.get("details", "")


def test_stream_control_cloud_fallback_start_and_stop():
    """Verify that in environments without WSL (e.g. Render cloud containers), stream starts in-process."""
    with patch("shutil.which", return_value=None), \
         patch("backend.main.ensure_stream_api_running", return_value=False):
        # Start stream
        res_start = client.post(
            "/stream/control",
            headers=get_auth_headers("investigator", username="inv_nathenael", officer_id="INSA-INV-42"),
            json={"action": "start", "rate": 300}
        )
        assert res_start.status_code == 200
        data_start = res_start.json()
        assert data_start["status"] == "SUCCESS"
        assert "started" in data_start["output"]

        # Check status while cloud stream is running
        with patch("httpx.AsyncClient.get", side_effect=Exception("No WSL stream api")):
            res_status = client.get("/stream/status", headers=get_auth_headers("analyst"))
            assert res_status.status_code == 200
            data_status = res_status.json()
            assert data_status["running"] is True
            assert data_status["pipeline_state"] == "RUNNING"
            assert data_status["events_per_sec"] >= 0.0

        # Stop stream
        res_stop = client.post(
            "/stream/control",
            headers=get_auth_headers("investigator", username="inv_nathenael", officer_id="INSA-INV-42"),
            json={"action": "stop"}
        )
        assert res_stop.status_code == 200
        data_stop = res_stop.json()
        assert data_stop["status"] == "SUCCESS"
        assert "stopped" in data_stop["output"]
