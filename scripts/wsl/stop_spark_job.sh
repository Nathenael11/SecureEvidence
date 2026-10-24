#!/usr/bin/env bash
set -uo pipefail

DEST_DIR="$HOME/securevidence_stream"
PID_FILE="$DEST_DIR/spark_processor.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "[*] Stopping Spark streaming processor (PID $PID)..."
    kill -15 "$PID" 2>/dev/null || true
    for i in {1..10}; do
        if ! kill -0 "$PID" 2>/dev/null; then
            echo "[+] Spark processor stopped cleanly."
            rm -f "$PID_FILE"
            exit 0
        fi
        sleep 1
    done
    echo "[*] Forcing termination of PID $PID..."
    kill -9 "$PID" 2>/dev/null || true
    rm -f "$PID_FILE"
fi

pkill -f "spark_stream_processor.py" 2>/dev/null || true
echo "[+] Spark streaming processor stopped."
