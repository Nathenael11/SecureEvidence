#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureEvidence: Replay Recorded CICIDS2017 Flows
Replays recorded network flows from the held-out test split into Kafka topic flows.raw.
Label: 'replay of recorded CICIDS2017 flows' (no live sensors claimed).
"""

import os
import sys
import time
import json
import uuid
import signal
import argparse
from datetime import datetime, timezone
from kafka import KafkaProducer


class FlowReplayer:
    def __init__(self, data_path: str, bootstrap_servers: str = "127.0.0.1:9092", topic: str = "flows.raw"):
        self.data_path = os.path.expanduser(data_path)
        self.topic = topic
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            acks=1,
            linger_ms=10,
            batch_size=32768
        )
        self.running = True
        signal.signal(signal.SIGINT, self._handle_stop)
        signal.signal(signal.SIGTERM, self._handle_stop)

    def _handle_stop(self, signum, frame):
        print("\n[*] Gracefully stopping replay...")
        self.running = False

    def replay(self, rate: int = 100, limit: int = 0, loop: bool = False):
        """
        Replay flows at specified rate (events/sec).
        rate: events per second (1..20000)
        limit: max events to send (0 = unlimited / entire file)
        loop: restart from beginning if end of file reached
        """
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"Replay data file not found: {self.data_path}")

        print(f"[*] Starting replay of recorded CICIDS2017 flows")
        print(f"[*] Target Topic: {self.topic} | Target Rate: {rate} events/s | Limit: {limit or 'Unlimited'} | Loop: {loop}")

        sent_count = 0
        start_mono = time.monotonic()
        last_report_mono = start_mono
        last_report_count = 0

        # Delay between batches for rate limiting
        # Batch size dynamically tuned based on rate
        batch_size = max(1, min(50, rate // 10))
        delay = batch_size / float(rate)

        while self.running:
            with open(self.data_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not self.running:
                        break
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                    except Exception:
                        continue

                    event_id = f"flow-{uuid.uuid4().hex[:16]}"
                    event_time = datetime.now(timezone.utc).isoformat()
                    features = record.get("features", {})
                    ground_truth = record.get("ground_truth_label", "UNKNOWN")

                    event = {
                        "event_id": event_id,
                        "event_time": event_time,
                        "ground_truth_label": ground_truth,
                        "source": "replay of recorded CICIDS2017 flows",
                        "source_ip": features.get("source_ip", f"198.51.100.{1 + (sent_count % 250)}"),
                        "destination_ip": features.get("destination_ip", "192.0.2.1"),
                        "target_asset": features.get("target_asset", "National-Gateway-Demo-01"),
                        "features": features
                    }

                    # Use event_id as Kafka partition key to distribute across partitions
                    self.producer.send(self.topic, key=event_id, value=event)
                    sent_count += 1

                    if sent_count % batch_size == 0:
                        self.producer.flush()
                        time.sleep(delay)

                    now_mono = time.monotonic()
                    if now_mono - last_report_mono >= 5.0:
                        duration = now_mono - last_report_mono
                        delta_count = sent_count - last_report_count
                        actual_rate = delta_count / duration
                        print(f"[{time.strftime('%X')}] Replayed {sent_count:,} events | Current rate: {actual_rate:.1f} events/s")
                        last_report_mono = now_mono
                        last_report_count = sent_count

                    if limit > 0 and sent_count >= limit:
                        self.running = False
                        break

            if not loop:
                break

        self.producer.flush()
        total_time = max(0.001, time.monotonic() - start_mono)
        overall_rate = sent_count / total_time
        print(f"[+] Replay finished: {sent_count:,} events sent in {total_time:.2f} s ({overall_rate:.1f} events/s)")
        return sent_count


def main():
    parser = argparse.ArgumentParser(description="Replay recorded CICIDS2017 flows to Kafka flows.raw")
    parser.add_argument("--data", default="~/securevidence_stream/data/test_flows.jsonl", help="Path to flows jsonl file")
    parser.add_argument("--rate", type=int, default=200, help="Replay rate (events/second)")
    parser.add_argument("--limit", type=int, default=1000, help="Total events to send (0 = unlimited)")
    parser.add_argument("--loop", action="store_true", help="Loop dataset indefinitely")
    parser.add_argument("--bootstrap", default="127.0.0.1:9092", help="Kafka bootstrap servers")
    parser.add_argument("--topic", default="flows.raw", help="Target Kafka topic")

    args = parser.parse_args()

    replayer = FlowReplayer(data_path=args.data, bootstrap_servers=args.bootstrap, topic=args.topic)
    replayer.replay(rate=args.rate, limit=args.limit, loop=args.loop)


if __name__ == "__main__":
    main()
