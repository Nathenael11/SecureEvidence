#!/usr/bin/env bash
set -uo pipefail

DEST_DIR="$HOME/securevidence_stream"
PID_FILE="$DEST_DIR/stream_api.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "[*] Stopping Stream API (PID $PID)..."
    kill -15 "$PID" 2>/dev/null || true
    rm -f "$PID_FILE"
fi

pkill -f "stream_api/app.py" 2>/dev/null || true
echo "[+] Stream API stopped."
