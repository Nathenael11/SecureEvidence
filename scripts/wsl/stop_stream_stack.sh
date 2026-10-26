#!/usr/bin/env bash
set -uo pipefail

KAFKA_DIR="$HOME/kafka"
KAFKA_BIN="$KAFKA_DIR/bin"

echo "[*] Stopping Kafka streaming stack..."
if [ -d "$KAFKA_DIR" ]; then
    "$KAFKA_BIN/kafka-server-stop.sh" 2>/dev/null || true
fi

pkill -f "kafka.Kafka" 2>/dev/null || true
echo "[+] Kafka stopped."
