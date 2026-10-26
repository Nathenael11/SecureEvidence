#!/usr/bin/env bash
set -euo pipefail

KAFKA_DIR="$HOME/kafka"
KAFKA_DATA="$HOME/kafka-data"
KAFKA_BIN="$KAFKA_DIR/bin"

echo "[*] Checking if Kafka KRaft broker is running..."
if pgrep -f "kafka.Kafka" > /dev/null; then
    echo "[+] Kafka is already running."
else
    echo "[*] Starting Kafka KRaft daemon..."
    cd "$KAFKA_DIR"
    export KAFKA_HEAP_OPTS="-Xmx1G -Xms1G"
    bin/kafka-server-start.sh -daemon config/kraft/server.properties
    echo "[*] Waiting for Kafka broker to bind on 127.0.0.1:9092..."
    for i in {1..30}; do
        if nc -z 127.0.0.1 9092 2>/dev/null || (echo > /dev/tcp/127.0.0.1/9092) 2>/dev/null; then
            echo "[+] Kafka broker port 9092 is ready."
            break
        fi
        sleep 1
    done
fi

echo "[*] Verifying / creating required topics..."
# 1. flows.raw (3 partitions)
"$KAFKA_BIN/kafka-topics.sh" --bootstrap-server 127.0.0.1:9092 --create --if-not-exists \
    --topic flows.raw --partitions 3 --replication-factor 1

# 2. alerts.scored
"$KAFKA_BIN/kafka-topics.sh" --bootstrap-server 127.0.0.1:9092 --create --if-not-exists \
    --topic alerts.scored --partitions 3 --replication-factor 1

# 3. flows.deadletter
"$KAFKA_BIN/kafka-topics.sh" --bootstrap-server 127.0.0.1:9092 --create --if-not-exists \
    --topic flows.deadletter --partitions 1 --replication-factor 1

echo "[+] Topics created / verified:"
"$KAFKA_BIN/kafka-topics.sh" --bootstrap-server 127.0.0.1:9092 --list
