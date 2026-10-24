#!/usr/bin/env bash
set -euo pipefail

DEST_DIR="$HOME/securevidence_stream"
PID_FILE="$DEST_DIR/stream_api.pid"
LOG_FILE="$DEST_DIR/logs/stream_api.log"
SCRIPT_PATH="/mnt/c/google-cloud-serverless-app/SecureEvidence/stream_api/app.py"

mkdir -p "$DEST_DIR/logs"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "[+] Stream API is already running (PID $PID)."
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

echo "[*] Launching Stream API on 127.0.0.1:8100..."
nohup python3 "$SCRIPT_PATH" > "$LOG_FILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PID_FILE"

sleep 2
if kill -0 "$NEW_PID" 2>/dev/null; then
    echo "[+] Stream API successfully running on port 8100 (PID $NEW_PID)."
else
    echo "[-] Stream API failed to start. Last log lines:"
    tail -n 20 "$LOG_FILE"
    exit 1
fi
