#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureEvidence: Real Streaming Pipeline Benchmark
Benchmarks sustained throughput and p50/p95/p99 end-to-end latency
across offered loads: 500, 1000, 2000, 5000, 10000 events/sec.
Each test runs for 60 s after a 10 s warm-up. Stops at the first load that cannot be sustained.
Real measurements only — counts only events processed within the publication window.
"""

import os
import sys
import time
import json
import uuid
import sqlite3
import argparse
import numpy as np
from datetime import datetime, timezone
from kafka import KafkaProducer


def get_env_info():
    """Dynamically determine host environment metrics."""
    mem_gb = "N/A"
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    mem_gb = f"{kb / (1024 * 1024):.1f} GB"
                    break
    except Exception:
        pass
    return f"Single Host / Laptop (WSL Ubuntu 22.04, Co-located Kafka, Spark, and Python Producer; RAM: {mem_gb})"


def run_benchmark_load(offered_rate: int, data_path: str, db_path: str, bootstrap="127.0.0.1:9092"):
    print(f"\n=======================================================")
    print(f"[*] Testing offered load: {offered_rate} events/s")
    print(f"=======================================================")

    producer = KafkaProducer(
        bootstrap_servers=bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks=1,
        linger_ms=5,
        batch_size=65536
    )

    # 1. Warm-up (10 s)
    warmup_duration = 10
    print(f"[*] Warming up pipeline for {warmup_duration} s at {offered_rate} ev/s...")
    warmup_events = offered_rate * warmup_duration
    batch_size = max(1, min(100, offered_rate // 10))
    delay = batch_size / float(offered_rate)

    sent = 0
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            if sent >= warmup_events:
                break
            record = json.loads(line)
            eid = f"warmup-{uuid.uuid4().hex[:12]}"
            event = {
                "event_id": eid,
                "event_time": datetime.now(timezone.utc).isoformat(),
                "ground_truth_label": record.get("ground_truth_label", "BENIGN"),
                "source": "replay of recorded CICIDS2017 flows",
                "features": record.get("features", {})
            }
            producer.send("flows.raw", key=eid, value=event)
            sent += 1
            if sent % batch_size == 0:
                producer.flush()
                time.sleep(delay)

    producer.flush()
    print(f"[+] Warm-up complete: {sent} events sent.")

    # 2. Main benchmark measurement window (60 s)
    test_duration = 60
    total_to_send = offered_rate * test_duration
    print(f"[*] Starting 60 s measurement run: {total_to_send:,} events target...")

    event_send_times = {}
    test_event_ids = set()

    send_start_mono = time.monotonic()
    send_start_wall = time.time()
    sent_test = 0

    with open(data_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    idx = 0
    num_lines = len(lines)

    while sent_test < total_to_send and (time.monotonic() - send_start_mono) < (test_duration + 5):
        line = lines[idx % num_lines]
        idx += 1
        record = json.loads(line)
        eid = f"bench-{uuid.uuid4().hex[:16]}"
        now_dt = datetime.now(timezone.utc)
        now_ts = time.time()
        event = {
            "event_id": eid,
            "event_time": now_dt.isoformat(),
            "ground_truth_label": record.get("ground_truth_label", "BENIGN"),
            "source": "replay of recorded CICIDS2017 flows",
            "features": record.get("features", {})
        }
        event_send_times[eid] = now_ts
        test_event_ids.add(eid)
        producer.send("flows.raw", key=eid, value=event)
        sent_test += 1

        if sent_test % batch_size == 0:
            producer.flush()
            time.sleep(delay)

    producer.flush()
    actual_send_duration = max(0.001, time.monotonic() - send_start_mono)
    actual_publish_rate = sent_test / actual_send_duration
    send_window_end_wall = send_start_wall + actual_send_duration

    print(f"[+] Published {sent_test:,} benchmark events in {actual_send_duration:.2f} s (measured publish rate: {actual_publish_rate:.1f} ev/s).")

    # 3. Wait for Spark processing to complete
    print("[*] Polling database for processed records...")
    time.sleep(3)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    scored_records = []
    poll_start = time.time()
    while time.time() - poll_start < 25:
        cur.execute("SELECT event_id, event_time, scored_at FROM stream_alerts WHERE event_id LIKE 'bench-%'")
        rows = cur.fetchall()
        scored_records = [r for r in rows if r[0] in test_event_ids]
        if len(scored_records) >= len(test_event_ids) * 0.95:
            break
        time.sleep(2)

    conn.close()

    scored_count = len(scored_records)
    print(f"[+] Scored {scored_count:,} / {len(test_event_ids):,} benchmark events.")

    # 4. Latency calculations and window-accurate throughput
    scored_in_window = 0
    latencies_ms = []
    for eid, etime_str, stime_str in scored_records:
        try:
            t_event = datetime.fromisoformat(etime_str.replace("Z", "+00:00")).timestamp()
            t_scored = datetime.fromisoformat(stime_str.replace("Z", "+00:00")).timestamp()
            if t_scored <= send_window_end_wall:
                scored_in_window += 1
            diff_s = t_scored - t_event
            if 0.0 <= diff_s < 3600:
                lat_ms = max(1.0, diff_s * 1000.0)
                latencies_ms.append(lat_ms)
        except Exception:
            pass

    if not latencies_ms:
        latencies_ms = [0.0]

    p50 = float(np.percentile(latencies_ms, 50))
    p95 = float(np.percentile(latencies_ms, 95))
    p99 = float(np.percentile(latencies_ms, 99))

    sustained_rate_window = scored_in_window / float(actual_send_duration)
    # Considered sustained only if >=85% of events were scored strictly inside the send window
    is_sustained = (scored_in_window >= len(test_event_ids) * 0.85)

    result = {
        "offered_rate": offered_rate,
        "measured_publish_rate": round(actual_publish_rate, 1),
        "sent_count": sent_test,
        "scored_count": scored_count,
        "scored_in_window": scored_in_window,
        "sustained_rate": round(sustained_rate_window, 1),
        "p50_latency_ms": round(p50, 1),
        "p95_latency_ms": round(p95, 1),
        "p99_latency_ms": round(p99, 1),
        "is_sustained": is_sustained
    }

    print(f"[*] Result: Sustained={is_sustained} | PubRate={result['measured_publish_rate']} ev/s | In-Window Rate={result['sustained_rate']} ev/s | p50={p50:.1f}ms | p95={p95:.1f}ms")
    return result


def main():
    default_data = os.getenv("STREAM_DATA_PATH", os.path.expanduser("~/securevidence_stream/data/test_flows.jsonl"))
    default_db = os.getenv("STREAM_DB_PATH", os.path.expanduser("~/securevidence_stream/data/stream_results.db"))

    parser = argparse.ArgumentParser(description="Benchmark SecureEvidence Streaming Pipeline")
    parser.add_argument("--data", default=default_data, help="Path to flows jsonl file")
    parser.add_argument("--db", default=default_db, help="Path to stream SQLite database")
    parser.add_argument("--bootstrap", default="127.0.0.1:9092", help="Kafka bootstrap servers")
    parser.add_argument("--out", default="docs/STREAM_BENCHMARK.md", help="Output Markdown report path")
    args = parser.parse_args()

    loads = [500, 1000, 2000, 5000, 10000]
    results = []

    print("[*] Starting SecureEvidence Streaming Pipeline Benchmark")
    print(f"[*] Environment: {get_env_info()}")
    print(f"[*] Target loads: {loads} events/sec")

    for load in loads:
        res = run_benchmark_load(load, args.data, args.db, args.bootstrap)
        results.append(res)
        if not res["is_sustained"]:
            print(f"[!] Pipeline cannot sustain {load} events/sec in real-time. Halting benchmark progression.")
            break

    # Format Markdown Report
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    report_lines = [
        "# Streaming Pipeline Benchmark Report",
        "",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        "**Pipeline Architecture:** Apache Kafka (KRaft) -> Spark Structured Streaming -> XGBoost  ",
        "**Source Data:** Replay of recorded CICIDS2017 flows (held-out test split)  ",
        f"**Environment:** {get_env_info()}  ",
        "",
        "## Empirical Performance Measurements",
        "",
        "| Nominal Load (ev/s) | Measured Publish Rate (ev/s) | Sustained Rate in Window (ev/s) | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | Status |",
        "|---|---|---|---|---|---|---|"
    ]

    for r in results:
        status_str = "SUSTAINED" if r["is_sustained"] else "SATURATED / CEILING"
        report_lines.append(
            f"| {r['offered_rate']:,} | {r['measured_publish_rate']:,} | {r['sustained_rate']:,} | {r['p50_latency_ms']} | {r['p95_latency_ms']} | {r['p99_latency_ms']} | {status_str} |"
        )

    max_sustained = max([r["sustained_rate"] for r in results if r["is_sustained"]] or [0])
    report_lines.extend([
        "",
        "## Architectural Notes & Constraints",
        "",
        f"- **Maximum Observed Sustained Throughput:** {max_sustained:,} events/second.",
        "- **Shared Hardware Baseline:** All components (Python publisher, Kafka broker, and Spark Structured Streaming driver) run on a single development machine/laptop within WSL Ubuntu 22.04. In production, producers and cluster nodes would be physically separated across dedicated network interfaces.",
        "- **In-Window Throughput Accounting:** Reported sustained rates reflect events scored strictly within the active publication window, preventing delayed micro-batch drains from inflating real-time processing figures.",
        "- **Spark Consumer Checkpointing:** Spark Structured Streaming maintains partition offsets within checkpoint metadata rather than Kafka consumer groups."
    ])

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")

    print(f"\n[+] Benchmark complete. Saved report to {args.out}")


if __name__ == "__main__":
    main()
