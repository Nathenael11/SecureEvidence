# -*- coding: utf-8 -*-
"""
SecureEvidence: Sensor Log Ingestion Service
Author: Nathenael Ermias nathenaelermias13@gmail.com
Design: Digital Forensics Prototype (INSA)

Parses network security sensor logs (Suricata EVE JSON and Zeek conn.log)
and calculates honest feature coverage against the 77 CICIDS2017 flow feature schema.
Does not invent unobserved fields or fill arbitrary constants.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

TOTAL_CICIDS_FEATURE_COUNT = 77

class SensorLogIngestionService:
    """Parses network security sensor logs with transparent feature coverage calculation."""

    @classmethod
    def calculate_coverage(cls, observed_features: List[str]) -> Tuple[float, List[str]]:
        """Compute fraction of 77 CICFlowMeter features actually observed."""
        count = len(observed_features)
        coverage = round(count / TOTAL_CICIDS_FEATURE_COUNT, 4)
        return coverage, observed_features

    @classmethod
    def parse_suricata_eve(cls, eve_record: Dict[str, Any], min_coverage: float = 0.05) -> Dict[str, Any]:
        """
        Transform Suricata EVE JSON log into flow telemetry with honest coverage metrics.
        Rejects records missing core identifiers (src_ip, dest_ip).
        Does not invent missing packet or byte counts.
        """
        src_ip = eve_record.get("src_ip")
        dest_ip = eve_record.get("dest_ip")
        if not src_ip or not dest_ip:
            raise ValueError("Suricata EVE log parsing failed: 'src_ip' and 'dest_ip' are required.")

        event_type = eve_record.get("event_type", "flow")
        flow_data = eve_record.get("flow", {})
        tcp_data = eve_record.get("tcp", {})
        alert_data = eve_record.get("alert", {})
        timestamp = eve_record.get("timestamp") or datetime.now(timezone.utc).isoformat()

        derived_features: List[str] = []
        flow_telemetry: Dict[str, Any] = {
            "sensor_type": "Suricata-IDS/IPS",
            "event_type": event_type,
            "timestamp": timestamp,
            "target_asset": f"Gateway-{dest_ip.replace('.', '-')}",
            "source_ip": src_ip,
            "destination_ip": dest_ip
        }

        # Age / Flow duration
        age_sec = None
        if "age" in flow_data:
            try:
                age_sec = float(flow_data["age"])
                flow_telemetry["flow_duration"] = age_sec * 1000000.0
                derived_features.append("Flow Duration")
            except (ValueError, TypeError):
                pass

        # Forward / Backward Packets
        fwd_pkts = flow_data.get("pkts_toserver", eve_record.get("pkts_toserver"))
        if fwd_pkts is not None:
            flow_telemetry["total_fwd_packets"] = float(fwd_pkts)
            derived_features.append("Total Fwd Packets")

        bwd_pkts = flow_data.get("pkts_toclient", eve_record.get("pkts_toclient"))
        if bwd_pkts is not None:
            flow_telemetry["total_backward_packets"] = float(bwd_pkts)
            derived_features.append("Total Backward Packets")

        # Forward / Backward Bytes
        fwd_bytes = flow_data.get("bytes_toserver", eve_record.get("bytes_toserver"))
        if fwd_bytes is not None:
            flow_telemetry["total_length_fwd_packets"] = float(fwd_bytes)
            derived_features.append("Total Length of Fwd Packets")

        bwd_bytes = flow_data.get("bytes_toclient", eve_record.get("bytes_toclient"))
        if bwd_bytes is not None:
            flow_telemetry["total_length_bwd_packets"] = float(bwd_bytes)
            derived_features.append("Total Length of Bwd Packets")

        # Packet and Byte rates (only if both count and duration exist)
        if age_sec is not None and age_sec > 0:
            if fwd_pkts is not None or bwd_pkts is not None:
                total_pkts = float(fwd_pkts or 0) + float(bwd_pkts or 0)
                flow_telemetry["flow_packets_s"] = total_pkts / age_sec
                derived_features.append("Flow Packets/s")

            if fwd_bytes is not None or bwd_bytes is not None:
                total_bytes = float(fwd_bytes or 0) + float(bwd_bytes or 0)
                flow_telemetry["flow_bytes_s"] = total_bytes / age_sec
                derived_features.append("Flow Bytes/s")

        # Flags (only recorded if tcp section present)
        if tcp_data:
            if "syn" in tcp_data or alert_data.get("signature"):
                flow_telemetry["syn_flag_count"] = 1 if tcp_data.get("syn", False) or "syn" in str(alert_data.get("signature", "")).lower() else 0
                derived_features.append("SYN Flag Count")
            if "rst" in tcp_data:
                flow_telemetry["rst_flag_count"] = 1 if tcp_data.get("rst", False) else 0
                derived_features.append("RST Flag Count")
            if "ack" in tcp_data:
                flow_telemetry["ack_flag_count"] = 1 if tcp_data.get("ack", False) else 0
                derived_features.append("ACK Flag Count")

        # Ratios (only if both fwd and bwd exist)
        if fwd_pkts is not None and bwd_pkts is not None and float(fwd_pkts) > 0:
            flow_telemetry["down_up_ratio"] = round(float(bwd_pkts) / float(fwd_pkts), 2)
            derived_features.append("Down/Up Ratio")

        coverage, derived_list = cls.calculate_coverage(derived_features)
        if coverage < min_coverage:
            raise ValueError(f"Telemetry feature coverage ({coverage*100:.1f}%) is below minimum required ({min_coverage*100:.1f}%).")

        flow_telemetry["feature_coverage"] = coverage
        flow_telemetry["derived_features_count"] = len(derived_list)
        flow_telemetry["total_schema_features"] = TOTAL_CICIDS_FEATURE_COUNT
        flow_telemetry["coverage_warning"] = (
            f"Partial feature extraction from EVE summary ({len(derived_list)}/77 features). "
            "Full PCAP recommended for complete statistical flow moments."
        )
        flow_telemetry["raw_log_record"] = eve_record
        return flow_telemetry

    @classmethod
    def parse_zeek_conn_log(cls, zeek_record: Dict[str, Any], min_coverage: float = 0.05) -> Dict[str, Any]:
        """Transform Zeek conn.log JSON record into normalized telemetry with honest coverage metrics."""
        src_ip = zeek_record.get("id.orig_h") or zeek_record.get("src_ip")
        dest_ip = zeek_record.get("id.resp_h") or zeek_record.get("dest_ip")
        if not src_ip or not dest_ip:
            raise ValueError("Zeek conn.log parsing failed: 'id.orig_h' and 'id.resp_h' are required.")

        derived_features: List[str] = []
        flow_telemetry: Dict[str, Any] = {
            "sensor_type": "Zeek-NSM",
            "timestamp": zeek_record.get("ts") or datetime.now(timezone.utc).isoformat(),
            "target_asset": f"Gateway-{dest_ip.replace('.', '-')}",
            "source_ip": src_ip,
            "destination_ip": dest_ip
        }

        duration_s = None
        if "duration" in zeek_record:
            try:
                duration_s = float(zeek_record["duration"])
                flow_telemetry["flow_duration"] = duration_s * 1000000.0
                derived_features.append("Flow Duration")
            except (ValueError, TypeError):
                pass

        if "orig_pkts" in zeek_record:
            flow_telemetry["total_fwd_packets"] = float(zeek_record["orig_pkts"])
            derived_features.append("Total Fwd Packets")

        if "resp_pkts" in zeek_record:
            flow_telemetry["total_backward_packets"] = float(zeek_record["resp_pkts"])
            derived_features.append("Total Backward Packets")

        if "orig_bytes" in zeek_record:
            flow_telemetry["total_length_fwd_packets"] = float(zeek_record["orig_bytes"])
            derived_features.append("Total Length of Fwd Packets")

        if "resp_bytes" in zeek_record:
            flow_telemetry["total_length_bwd_packets"] = float(zeek_record["resp_bytes"])
            derived_features.append("Total Length of Bwd Packets")

        if duration_s is not None and duration_s > 0:
            if "orig_pkts" in zeek_record and "resp_pkts" in zeek_record:
                flow_telemetry["flow_packets_s"] = (float(zeek_record["orig_pkts"]) + float(zeek_record["resp_pkts"])) / duration_s
                derived_features.append("Flow Packets/s")
            if "orig_bytes" in zeek_record and "resp_bytes" in zeek_record:
                flow_telemetry["flow_bytes_s"] = (float(zeek_record["orig_bytes"]) + float(zeek_record["resp_bytes"])) / duration_s
                derived_features.append("Flow Bytes/s")

        if "conn_state" in zeek_record:
            cs = str(zeek_record["conn_state"])
            flow_telemetry["syn_flag_count"] = 1 if cs in ["S0", "REJ"] else 0
            flow_telemetry["rst_flag_count"] = 1 if cs == "RSTO" else 0
            derived_features.extend(["SYN Flag Count", "RST Flag Count"])

        coverage, derived_list = cls.calculate_coverage(derived_features)
        if coverage < min_coverage:
            raise ValueError(f"Telemetry feature coverage ({coverage*100:.1f}%) is below minimum required ({min_coverage*100:.1f}%).")

        flow_telemetry["feature_coverage"] = coverage
        flow_telemetry["derived_features_count"] = len(derived_list)
        flow_telemetry["total_schema_features"] = TOTAL_CICIDS_FEATURE_COUNT
        flow_telemetry["coverage_warning"] = (
            f"Partial feature extraction from Zeek conn.log ({len(derived_list)}/77 features). "
            "Full PCAP recommended for complete statistical flow moments."
        )
        flow_telemetry["raw_log_record"] = zeek_record
        return flow_telemetry
