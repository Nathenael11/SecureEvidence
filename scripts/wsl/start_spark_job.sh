#!/usr/bin/env bash
set -euo pipefail

DEST_DIR="$HOME/securevidence_stream"
PID_FILE="$DEST_DIR/spark_processor.pid"
LOG_FILE="$DEST_DIR/logs/spark_processor.log"
SCRIPT_PATH="/mnt/c/google-cloud-serverless-app/SecureEvidence/big_data/spark_stream_processor.py"

mkdir -p "$DEST_DIR/logs"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "[+] Spark streaming processor is already running (PID $PID)."
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

echo "[*] Launching Spark Structured Streaming processor..."
export SPARK_LOCAL_IP="127.0.0.1"
export PYTHONUNBUFFERED="1"
export PYSPARK_PYTHON="/usr/bin/python3"
export PYSPARK_DRIVER_PYTHON="/usr/bin/python3"

nohup python3 -u "$SCRIPT_PATH" \
    --models-dir "$DEST_DIR/models" \
    --db-path "$DEST_DIR/data/stream_results.db" \
    --bootstrap "127.0.0.1:9092" \
    --checkpoint-dir "$DEST_DIR/checkpoints" \
    > "$LOG_FILE" 2>&1 &

NEW_PID=$!
echo "$NEW_PID" > "$PID_FILE"
echo "[+] Spark streaming processor launched with PID $NEW_PID."
echo "[*] Waiting for initialization..."
sleep 5

if kill -0 "$NEW_PID" 2>/dev/null; then
    echo "[+] Spark processor successfully running."
else
    echo "[-] Spark processor failed to start. Last log lines:"
    tail -n 25 "$LOG_FILE"
    exit 1
fi
