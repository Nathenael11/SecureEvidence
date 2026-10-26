#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureEvidence: Spark Structured Streaming Threat Detection Engine
Consumes raw network flow events from Kafka topic flows.raw, enforces strict schema,
routes invalid payloads to flows.deadletter with error reasons, executes vectorized
XGBoost inference via foreachBatch, writes alerts to alerts.scored and SQLite
~/securevidence_stream/data/stream_results.db, and calculates 1-minute tumbling window metrics.
"""

import os
import sys
import json
import sqlite3
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List

# Add stream directory to path for flow_preprocessor
STREAM_ROOT = os.path.expanduser("~/securevidence_stream")
if STREAM_ROOT not in sys.path:
    sys.path.insert(0, STREAM_ROOT)

from ai_engine.flow_preprocessor import FlowPreprocessor, normalize_key

try:
    from pyspark.sql import SparkSession
    from pyspark.sql.functions import (
        col, from_json, to_json, struct, current_timestamp,
        window, count, avg, collect_list, udf, to_timestamp
    )
    from pyspark.sql.types import (
        StringType, StructType, StructField, DoubleType, LongType, MapType
    )
except ImportError:
    SparkSession = None

import xgboost as xgb
from xgboost import XGBClassifier
import numpy as np

try:
    from kafka import KafkaProducer
except ImportError:
    KafkaProducer = None


class HighThroughputLogPipeline:
    """
    High-volume log processing pipeline capable of running in PySpark cluster mode
    or high-throughput vectorized stream emulation mode for local/cloud environments.
    Maintained for backward compatibility with existing tests and local service.
    """

    def __init__(self, batch_size: int = 1000):
        self.batch_size = batch_size
        self.total_processed = 0
        self.total_threats_detected = 0
        self.author = "Nathenael Ermias"

    def process_event_batch(self, events: List[Dict[str, Any]], detector=None) -> Dict[str, Any]:
        """Process a micro-batch of network log telemetry."""
        import time
        start_time = time.time()

        results = []
        threats = []
        asset_stats = {}

        for event in events:
            asset = event.get("target_asset", "Unknown-Asset")
            asset_stats[asset] = asset_stats.get(asset, 0) + 1

            if detector:
                pred = detector.predict(event)
                results.append({
                    "event_id": event.get("event_id", f"LOG-{time.time_ns()}"),
                    "prediction": pred,
                    "raw_event": event
                })
                if pred.get("is_threat"):
                    threats.append({
                        "event_id": event.get("event_id"),
                        "threat_category": pred.get("threat_category"),
                        "severity": pred.get("severity"),
                        "confidence": pred.get("confidence"),
                        "source_ip": event.get("source_ip"),
                        "target_asset": asset
                    })
            else:
                is_threat = (
                    event.get("packet_rate", 0) > 300 or
                    event.get("byte_entropy", 0) > 6.5 or
                    event.get("failed_logins", 0) > 3 or
                    event.get("serror_rate", 0) > 0.5
                )
                results.append({"is_threat": is_threat, "event": event})
                if is_threat:
                    threats.append(event)

        duration = time.time() - start_time
        self.total_processed += len(events)
        self.total_threats_detected += len(threats)
        throughput_eps = round(len(events) / max(duration, 0.0001), 2)

        return {
            "batch_size": len(events),
            "processing_duration_sec": round(duration, 4),
            "throughput_events_per_sec": throughput_eps,
            "threats_detected_count": len(threats),
            "threat_ratio": round(len(threats) / max(len(events), 1), 4),
            "asset_distribution": asset_stats,
            "threat_incidents": threats[:10],
            "total_lifetime_processed": self.total_processed,
            "author_credit": "Nathenael Ermias (INSA Big Data Specialization)"
        }


class ModelHolder:
    """Singleton to load XGBoost model, preprocessor, and Kafka producer once per Spark executor/driver."""
    _instance = None

    @classmethod
    def get_instance(cls, models_dir: str, kafka_bootstrap: str = "127.0.0.1:9092"):
        if cls._instance is None:
            cls._instance = cls(models_dir, kafka_bootstrap)
        return cls._instance

    def __init__(self, models_dir: str, kafka_bootstrap: str = "127.0.0.1:9092"):
        self.models_dir = os.path.expanduser(models_dir)
        self.preprocessor = FlowPreprocessor(models_dir=self.models_dir)
        self.model_path = os.path.join(self.models_dir, "threat_detector_xgb.json")
        self.model = XGBClassifier()
        self.model.load_model(self.model_path)
        
        # Load classes from metadata
        raw_classes = self.preprocessor.metadata.get("attack_classes", {})
        if isinstance(raw_classes, list):
            self.classes = {i: str(v) for i, v in enumerate(raw_classes)}
        elif isinstance(raw_classes, dict):
            self.classes = {int(k): str(v) for k, v in raw_classes.items()}
        else:
            self.classes = {0: "BENIGN", 1: "Bot", 2: "DDoS", 3: "DoS GoldenEye",
                            4: "DoS Hulk", 5: "DoS Slowhttptest", 6: "DoS slowloris",
                            7: "FTP-Patator", 8: "Other_Attack", 9: "PortScan",
                            10: "SSH-Patator", 11: "Web_Attack"}

        self.producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            acks=1,
            linger_ms=10,
            batch_size=65536
        )



def init_sqlite_db(db_path: str):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA busy_timeout=5000;")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS stream_alerts (
        event_id TEXT PRIMARY KEY,
        event_time TEXT,
        scored_at TEXT,
        predicted_class TEXT,
        confidence REAL,
        feature_coverage REAL,
        status TEXT,
        ground_truth_label TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        target_asset TEXT,
        is_threat INTEGER
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS window_stats (
        window_start TEXT,
        window_end TEXT,
        event_count INTEGER,
        threat_count INTEGER,
        benign_count INTEGER,
        mean_confidence REAL,
        top_source_ips TEXT,
        class_distribution TEXT,
        created_at TEXT,
        PRIMARY KEY (window_start, window_end)
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_time ON stream_alerts(event_time);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON stream_alerts(status);")
    conn.commit()
    conn.close()


def process_micro_batch(batch_df, batch_id, models_dir: str, db_path: str, kafka_bootstrap: str):
    """
    ForeachBatch callback: performs strict validation, deadletter routing,
    vectorized XGBoost inference, SQLite idempotent upsert, and alert publication.
    """
    if batch_df.isEmpty():
        return

    holder = ModelHolder.get_instance(models_dir, kafka_bootstrap)
    preprocessor = holder.preprocessor
    model = holder.model
    classes = holder.classes
    producer = holder.producer

    records = [row.asDict() for row in batch_df.collect()]
    if not records:
        return

    valid_events = []
    deadletter_events = []

    for r in records:
        raw_val = r.get("value")
        if not raw_val:
            deadletter_events.append({"raw_value": None, "reason": "Empty Kafka message payload", "rejected_at": datetime.now(timezone.utc).isoformat()})
            continue

        try:
            payload = json.loads(raw_val) if isinstance(raw_val, str) else raw_val
        except Exception as e:
            deadletter_events.append({"raw_value": str(raw_val)[:500], "reason": f"Malformed JSON: {str(e)}", "rejected_at": datetime.now(timezone.utc).isoformat()})
            continue

        if not isinstance(payload, dict):
            deadletter_events.append({"raw_value": str(payload)[:500], "reason": "Payload is not a JSON object", "rejected_at": datetime.now(timezone.utc).isoformat()})
            continue

        event_id = payload.get("event_id")
        if not event_id:
            deadletter_events.append({"raw_value": payload, "reason": "Missing required field: event_id", "rejected_at": datetime.now(timezone.utc).isoformat()})
            continue

        valid_events.append(payload)

    # Route dead-letter events to Kafka flows.deadletter
    for dead in deadletter_events:
        producer.send("flows.deadletter", key=None, value=dead)

    if not valid_events:
        producer.flush()
        return

    # Separate events into sufficient data vs insufficient data using the shared coverage gate
    to_score_events = []
    to_score_indices = []
    results = [None] * len(valid_events)

    for idx, ev in enumerate(valid_events):
        feat_dict = ev.get("features", {})
        cov, prov, missing = preprocessor.evaluate_coverage(feat_dict)
        if cov < preprocessor.coverage_threshold:
            # Gated: refuse inference, do not predict class
            results[idx] = {
                "event_id": ev["event_id"],
                "event_time": ev.get("event_time", datetime.now(timezone.utc).isoformat()),
                "scored_at": datetime.now(timezone.utc).isoformat(),
                "predicted_class": "INSUFFICIENT_DATA",
                "confidence": 0.0,
                "feature_coverage": round(cov, 4),
                "status": "INSUFFICIENT_DATA",
                "ground_truth_label": ev.get("ground_truth_label", "UNKNOWN"),
                "source_ip": ev.get("source_ip", "UNKNOWN"),
                "destination_ip": ev.get("destination_ip", "UNKNOWN"),
                "target_asset": ev.get("target_asset", "UNKNOWN"),
                "is_threat": 0
            }
        else:
            to_score_events.append(feat_dict)
            to_score_indices.append(idx)

    # Vectorized batch scoring for all eligible flows
    if to_score_events:
        scaled_matrix, covs = preprocessor.extract_batch(to_score_events)
        probas = model.predict_proba(scaled_matrix)
        preds = np.argmax(probas, axis=1)

        for i, idx in enumerate(to_score_indices):
            ev = valid_events[idx]
            pred_id = int(preds[i])
            pred_class = classes.get(pred_id, f"Class_{pred_id}")
            conf = float(probas[i][pred_id])
            is_threat = 1 if pred_id != 0 else 0

            results[idx] = {
                "event_id": ev["event_id"],
                "event_time": ev.get("event_time", datetime.now(timezone.utc).isoformat()),
                "scored_at": datetime.now(timezone.utc).isoformat(),
                "predicted_class": pred_class,
                "confidence": round(conf, 4),
                "feature_coverage": round(covs[i], 4),
                "status": "CLASSIFIED",
                "ground_truth_label": ev.get("ground_truth_label", "UNKNOWN"),
                "source_ip": ev.get("source_ip", "UNKNOWN"),
                "destination_ip": ev.get("destination_ip", "UNKNOWN"),
                "target_asset": ev.get("target_asset", "UNKNOWN"),
                "is_threat": is_threat
            }

    # Write scored results to Kafka alerts.scored
    for res in results:
        producer.send("alerts.scored", key=res["event_id"], value=res)
    producer.flush()

    # Idempotent SQLite upsert
    conn = sqlite3.connect(db_path, timeout=10.0)
    cur = conn.cursor()
    cur.execute("BEGIN IMMEDIATE;")
    cur.executemany("""
    INSERT INTO stream_alerts (
        event_id, event_time, scored_at, predicted_class, confidence,
        feature_coverage, status, ground_truth_label, source_ip, destination_ip, target_asset, is_threat
    ) VALUES (
        :event_id, :event_time, :scored_at, :predicted_class, :confidence,
        :feature_coverage, :status, :ground_truth_label, :source_ip, :destination_ip, :target_asset, :is_threat
    ) ON CONFLICT(event_id) DO UPDATE SET
        scored_at = excluded.scored_at,
        predicted_class = excluded.predicted_class,
        confidence = excluded.confidence,
        feature_coverage = excluded.feature_coverage,
        status = excluded.status,
        is_threat = excluded.is_threat;
    """, results)
    conn.commit()
    conn.close()

    # Update window_stats directly from stream_alerts table in batch
    try:
        w_conn = sqlite3.connect(db_path, timeout=5.0)
        w_cur = w_conn.cursor()
        w_cur.execute("""
        SELECT 
            strftime('%Y-%m-%dT%H:%M:00', event_time) as w_start,
            strftime('%Y-%m-%dT%H:%M:00', datetime(event_time, '+1 minute')) as w_end,
            COUNT(*) as event_count,
            SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threat_count,
            SUM(CASE WHEN is_threat = 0 THEN 1 ELSE 0 END) as benign_count,
            AVG(CASE WHEN status != 'INSUFFICIENT_DATA' AND confidence > 0.0 THEN confidence ELSE NULL END) as mean_conf
        FROM stream_alerts
        WHERE event_time IS NOT NULL
        GROUP BY w_start
        ORDER BY w_start DESC
        LIMIT 5;
        """)
        for w_start, w_end, ev_cnt, thr_cnt, ben_cnt, mean_c in w_cur.fetchall():
            if not w_start:
                continue
            conf_val = round(float(mean_c), 4) if mean_c is not None else None
            w_cur.execute("""
            INSERT INTO window_stats (
                window_start, window_end, event_count, threat_count, benign_count,
                mean_confidence, top_source_ips, class_distribution, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(window_start, window_end) DO UPDATE SET
                event_count = excluded.event_count,
                threat_count = excluded.threat_count,
                benign_count = excluded.benign_count,
                mean_confidence = excluded.mean_confidence,
                created_at = excluded.created_at;
            """, (w_start, w_end, ev_cnt, thr_cnt or 0, ben_cnt or 0, conf_val, "[]", "{}", datetime.now(timezone.utc).isoformat()))
        w_conn.commit()
        w_conn.close()
    except Exception:
        pass


def process_window_batch(batch_df, batch_id, db_path: str):
    """
    ForeachBatch callback for 1-minute tumbling windows:
    Persists aggregated window metrics into window_stats table.
    """
    if batch_df.isEmpty():
        return

    rows = batch_df.collect()
    if not rows:
        return

    conn = sqlite3.connect(db_path, timeout=10.0)
    cur = conn.cursor()
    cur.execute("BEGIN IMMEDIATE;")

    for row in rows:
        r = row.asDict()
        w = r.get("window")
        w_start = w.start.isoformat() if hasattr(w, "start") else str(w)
        w_end = w.end.isoformat() if hasattr(w, "end") else str(w)

        ev_count = int(r.get("event_count", 0))
        threat_count = int(r.get("threat_count", 0))
        benign_count = int(r.get("benign_count", 0))
        mean_conf = float(r.get("mean_confidence", 0.0))
        top_ips = json.dumps(r.get("top_source_ips", []))
        class_dist = json.dumps(r.get("class_distribution", {}))
        now_ts = datetime.now(timezone.utc).isoformat()

        cur.execute("""
        INSERT INTO window_stats (
            window_start, window_end, event_count, threat_count, benign_count,
            mean_confidence, top_source_ips, class_distribution, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(window_start, window_end) DO UPDATE SET
            event_count = excluded.event_count,
            threat_count = excluded.threat_count,
            benign_count = excluded.benign_count,
            mean_confidence = excluded.mean_confidence,
            top_source_ips = excluded.top_source_ips,
            class_distribution = excluded.class_distribution,
            created_at = excluded.created_at;
        """, (w_start, w_end, ev_count, threat_count, benign_count, mean_conf, top_ips, class_dist, now_ts))

    conn.commit()
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="SecureEvidence Spark Streaming Threat Processor")
    parser.add_argument("--models-dir", default="~/securevidence_stream/models", help="Model directory")
    parser.add_argument("--db-path", default="~/securevidence_stream/data/stream_results.db", help="SQLite DB path")
    parser.add_argument("--bootstrap", default="127.0.0.1:9092", help="Kafka bootstrap")
    parser.add_argument("--checkpoint-dir", default="~/securevidence_stream/checkpoints", help="Spark checkpoint path")
    args = parser.parse_args()

    models_dir = os.path.expanduser(args.models_dir)
    db_path = os.path.expanduser(args.db_path)
    checkpoint_dir = os.path.expanduser(args.checkpoint_dir)
    os.makedirs(checkpoint_dir, exist_ok=True)

    init_sqlite_db(db_path)

    # Initialize Spark Session (local[2], driver memory <= 2g)
    # Include cached spark-sql-kafka connector JARs
    ivy_jars = [
        os.path.expanduser("~/.ivy2/jars/org.apache.spark_spark-sql-kafka-0-10_2.12-3.5.3.jar"),
        os.path.expanduser("~/.ivy2/jars/org.apache.spark_spark-token-provider-kafka-0-10_2.12-3.5.3.jar"),
        os.path.expanduser("~/.ivy2/jars/org.apache.kafka_kafka-clients-3.4.1.jar"),
        os.path.expanduser("~/.ivy2/jars/org.apache.commons_commons-pool2-2.11.1.jar"),
        os.path.expanduser("~/.ivy2/jars/org.apache.hadoop_hadoop-client-runtime-3.3.4.jar"),
        os.path.expanduser("~/.ivy2/jars/org.apache.hadoop_hadoop-client-api-3.3.4.jar"),
        os.path.expanduser("~/.ivy2/jars/org.lz4_lz4-java-1.8.0.jar"),
        os.path.expanduser("~/.ivy2/jars/org.xerial.snappy_snappy-java-1.1.10.5.jar"),
        os.path.expanduser("~/.ivy2/jars/org.slf4j_slf4j-api-2.0.7.jar"),
        os.path.expanduser("~/.ivy2/jars/commons-logging_commons-logging-1.1.3.jar"),
        os.path.expanduser("~/.ivy2/jars/com.google.code.findbugs_jsr305-3.0.0.jar")
    ]
    jars_str = ",".join([j for j in ivy_jars if os.path.exists(j)])

    builder = SparkSession.builder \
        .appName("SecureEvidence-Streaming-Processor") \
        .master("local[2]") \
        .config("spark.driver.memory", "2g") \
        .config("spark.network.timeout", "600s") \
        .config("spark.executor.heartbeatInterval", "60s") \
        .config("spark.sql.streaming.checkpointLocation", os.path.join(checkpoint_dir, "spark_main")) \
        .config("spark.sql.shuffle.partitions", "2")

    if jars_str:
        builder = builder.config("spark.jars", jars_str)

    spark = builder.getOrCreate()

    spark.sparkContext.setLogLevel("WARN")

    print("[*] Spark Structured Streaming session started.")
    print(f"[*] Reading from Kafka {args.bootstrap} on topic flows.raw...")

    # 1. Read Kafka Stream
    raw_stream = spark.readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", args.bootstrap) \
        .option("subscribe", "flows.raw") \
        .option("startingOffsets", "earliest") \
        .option("maxOffsetsPerTrigger", "2000") \
        .option("failOnDataLoss", "false") \
        .option("kafka.request.timeout.ms", "60000") \
        .option("kafka.session.timeout.ms", "30000") \
        .load()

    scoring_query = raw_stream.selectExpr("CAST(key AS STRING)", "CAST(value AS STRING)") \
        .writeStream \
        .foreachBatch(lambda df, bid: process_micro_batch(df, bid, models_dir, db_path, args.bootstrap)) \
        .option("checkpointLocation", os.path.join(checkpoint_dir, "scoring_checkpoint")) \
        .start()

    print("[+] Streaming query active. Awaiting termination...")
    try:
        scoring_query.awaitTermination()
    except Exception as e:
        print(f"[!] Spark streaming terminated: {e}")
        try:
            scoring_query.stop()
        except Exception:
            pass


if __name__ == "__main__":
    main()
