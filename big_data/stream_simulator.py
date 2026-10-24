# -*- coding: utf-8 -*-
"""
SecureEvidence: Real-time Telemetry Stream Simulator
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: Big Data & AI Engineering (INSA)

Generates live streaming network logs for local demonstration and benchmarking.
Uses RFC 5737 documentation IP ranges and neutral fictitious infrastructure assets.
Emits full-schema CICIDS2017 features to satisfy the feature coverage gate.
"""

import os
import json
import random
import time
from typing import Dict, Any, Generator, List

DOCUMENTATION_IPS_INTERNAL = [
    "192.0.2.10", "192.0.2.20", "192.0.2.50", "192.0.2.100"
]

DOCUMENTATION_IPS_EXTERNAL = [
    "198.51.100.45", "198.51.100.88", "203.0.113.15", "203.0.113.99"
]

NEUTRAL_ASSETS = [
    "National-Gateway-Demo-01",
    "Commercial-Core-Switch-02",
    "Central-Interbank-Switch-01",
    "Sensor-Node-Alpha",
    "Public-Web-DMZ"
]

# Cache 77 feature names from model_metadata.json
_FEATURE_COLUMNS_CACHE: List[str] = []

def _get_feature_columns() -> List[str]:
    global _FEATURE_COLUMNS_CACHE
    if not _FEATURE_COLUMNS_CACHE:
        meta_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai_engine", "models", "model_metadata.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    _FEATURE_COLUMNS_CACHE = meta.get("feature_columns", [])
            except Exception:
                pass
    return _FEATURE_COLUMNS_CACHE

def generate_live_event() -> Dict[str, Any]:
    """Generate a single live network telemetry event formatted for CICIDS2017 inference."""
    scenario = random.choices(
        ["normal", "ddos", "portscan", "ssh_patator", "web_attack", "botnet", "dos_hulk"],
        weights=[0.55, 0.12, 0.09, 0.08, 0.06, 0.05, 0.05]
    )[0]
    
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    feature_cols = _get_feature_columns()
    
    # Initialize base flow payload with all 77 schema columns set to baseline 0.0
    flow: Dict[str, Any] = {col: 0.0 for col in feature_cols}
    
    flow.update({
        "timestamp": timestamp,
        "event_id": f"INSA-TEL-{time.time_ns()}",
        "target_asset": random.choice(NEUTRAL_ASSETS),
        "source_ip": random.choice(DOCUMENTATION_IPS_EXTERNAL),
        "destination_ip": random.choice(DOCUMENTATION_IPS_INTERNAL),
        "protocol": "TCP"
    })
    
    if scenario == "normal":
        flow.update({
            "source_ip": random.choice(DOCUMENTATION_IPS_INTERNAL),
            "destination_ip": "192.0.2.1",
            "Flow Duration": round(random.uniform(10000.0, 450000.0), 1),
            "Flow Packets/s": round(random.uniform(5.0, 35.0), 1),
            "Flow Bytes/s": round(random.uniform(5000.0, 35000.0), 1),
            "Total Fwd Packets": float(random.randint(8, 25)),
            "Total Backward Packets": float(random.randint(6, 20)),
            "SYN Flag Count": 0.0,
            "RST Flag Count": 0.0,
            "PSH Flag Count": 1.0,
            "ACK Flag Count": 1.0,
            "Down/Up Ratio": 1.2,
            "Init_Win_bytes_forward": 29200.0,
            "Average Packet Size": round(random.uniform(80.0, 320.0), 1)
        })
    elif scenario == "dos_hulk":
        flow.update({
            "target_asset": "National-Gateway-Demo-01",
            "Flow Duration": 39897118.51,
            "Total Fwd Packets": 0.0,
            "Total Backward Packets": 3388.27,
            "Total Length of Fwd Packets": 22533.93,
            "Total Length of Bwd Packets": 4645197.72,
            "Fwd Packet Length Max": 2677.62,
            "Fwd Packet Length Min": 221.97,
            "Fwd Packet Length Mean": 185.46,
            "Fwd Packet Length Std": 788.96,
            "Bwd Packet Length Max": 3623.91,
            "Bwd Packet Length Min": 102.32,
            "Bwd Packet Length Mean": 1452.11,
            "Bwd Packet Length Std": 1527.78,
            "Flow Bytes/s": 46574184.57,
            "Flow Packets/s": 45.0,
            "Init_Win_bytes_forward": 65535.0,
            "Init_Win_bytes_backward": 26847.0
        })
    elif scenario == "ddos":
        flow.update({
            "target_asset": "National-Gateway-Demo-01",
            "Flow Duration": round(random.uniform(500.0, 3500.0), 1),
            "Flow Packets/s": round(random.uniform(2500.0, 8500.0), 1),
            "Flow Bytes/s": round(random.uniform(500000.0, 3500000.0), 1),
            "Total Fwd Packets": float(random.randint(800, 2500)),
            "Total Backward Packets": 2.0,
            "SYN Flag Count": 1.0,
            "RST Flag Count": 0.0,
            "Init_Win_bytes_forward": 8192.0
        })
    elif scenario == "portscan":
        flow.update({
            "target_asset": "Sensor-Node-Alpha",
            "Flow Duration": round(random.uniform(20.0, 500.0), 1),
            "Flow Packets/s": round(random.uniform(400.0, 1500.0), 1),
            "Total Fwd Packets": 2.0,
            "Total Backward Packets": 1.0,
            "SYN Flag Count": 1.0,
            "RST Flag Count": 1.0,
            "Init_Win_bytes_forward": 1024.0
        })
    elif scenario == "ssh_patator":
        flow.update({
            "target_asset": "Commercial-Core-Switch-02",
            "Flow Duration": round(random.uniform(25000.0, 95000.0), 1),
            "Flow Packets/s": round(random.uniform(45.0, 120.0), 1),
            "Total Fwd Packets": float(random.randint(25, 60)),
            "Total Backward Packets": float(random.randint(20, 50)),
            "RST Flag Count": 1.0,
            "PSH Flag Count": 1.0,
            "ACK Flag Count": 1.0,
            "Init_Win_bytes_forward": 14600.0
        })
    else:  # web_attack
        flow.update({
            "target_asset": "Public-Web-DMZ",
            "Flow Duration": round(random.uniform(5000.0, 45000.0), 1),
            "Flow Packets/s": round(random.uniform(25.0, 90.0), 1),
            "Flow Bytes/s": round(random.uniform(15000.0, 85000.0), 1),
            "Total Fwd Packets": float(random.randint(15, 45)),
            "Total Backward Packets": float(random.randint(15, 45)),
            "PSH Flag Count": 1.0,
            "ACK Flag Count": 1.0,
            "Init_Win_bytes_forward": 29200.0
        })
    
    return flow

def stream_events(count: int = 10, delay_sec: float = 0.1) -> Generator[Dict[str, Any], None, None]:
    """Yield a stream of network telemetry events."""
    for _ in range(count):
        yield generate_live_event()
        if delay_sec > 0:
            time.sleep(delay_sec)
