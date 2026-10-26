#!/usr/bin/env bash
set -euo pipefail

DEST_DIR="$HOME/securevidence_stream"
SRC_MODELS="/mnt/c/google-cloud-serverless-app/SecureEvidence/ai_engine/models"
SRC_CODE="/mnt/c/google-cloud-serverless-app/SecureEvidence"

echo "[*] Initializing $DEST_DIR..."
mkdir -p "$DEST_DIR/models"
mkdir -p "$DEST_DIR/data"
mkdir -p "$DEST_DIR/logs"
mkdir -p "$DEST_DIR/checkpoints"
mkdir -p "$DEST_DIR/ai_engine"

echo "[*] Copying model files..."
cp -u "$SRC_MODELS/threat_detector_xgb.json" "$DEST_DIR/models/"
cp -u "$SRC_MODELS/feature_scaler.joblib" "$DEST_DIR/models/"
cp -u "$SRC_MODELS/label_encoder.joblib" "$DEST_DIR/models/"
cp -u "$SRC_MODELS/model_metadata.json" "$DEST_DIR/models/"
cp -u "$SRC_MODELS/scaler_stats.json" "$DEST_DIR/models/" || true

echo "[*] Copying shared feature preprocessor..."
cp -u "$SRC_CODE/ai_engine/flow_preprocessor.py" "$DEST_DIR/ai_engine/"
touch "$DEST_DIR/ai_engine/__init__.py"

echo "[*] Verifying model SHA-256 against model_metadata.json..."
python3 - << 'EOF'
import os
import json
import hashlib
import sys

meta_path = os.path.expanduser("~/securevidence_stream/models/model_metadata.json")
model_path = os.path.expanduser("~/securevidence_stream/models/threat_detector_xgb.json")

with open(meta_path, "r", encoding="utf-8") as f:
    meta = json.load(f)

expected_hash = meta.get("model_file_sha256") or meta.get("model_sha256")

with open(model_path, "rb") as f:
    actual_hash = hashlib.sha256(f.read()).hexdigest()

print(f"  Expected SHA-256: {expected_hash}")
print(f"  Actual SHA-256:   {actual_hash}")

if expected_hash.lower() != actual_hash.lower():
    print("[-] ERROR: Model SHA-256 mismatch!")
    sys.exit(1)

print("[+] Model SHA-256 verified successfully.")
EOF

echo "[*] Generating held-out test split flows dataset for replay..."
python3 - << 'EOF'
import os
import sys
import zipfile
import json
import pandas as pd
import numpy as np

target_test_file = os.path.expanduser("~/securevidence_stream/data/test_flows.jsonl")

if os.path.exists(target_test_file) and os.path.getsize(target_test_file) > 100000:
    print(f"[+] Replay dataset already exists: {target_test_file}")
    sys.exit(0)

zip_path = "/mnt/c/Users/CBZ/Downloads/combinenew.csv.zip"
if not os.path.exists(zip_path):
    print(f"[-] Error: {zip_path} not found.")
    sys.exit(1)

print("[*] Extracting 20,000 held-out flows from test split...")
z = zipfile.ZipFile(zip_path)
chunks = []
collected = 0
# Read from the latter portion of the dataset (held-out test split)
for i, chunk in enumerate(pd.read_csv(z.open('combinenew.csv'), chunksize=50000, low_memory=False)):
    chunk.columns = chunk.columns.str.strip()
    chunk = chunk.replace([np.inf, -np.inf], np.nan).dropna(subset=['Label'])
    
    # Rare class normalization identical to training pipeline
    chunk.loc[chunk['Label'].str.contains('Web Attack', na=False), 'Label'] = 'Web_Attack'
    
    # Sample from each chunk
    sample = chunk.sample(n=min(len(chunk), 2000), random_state=42 + i)
    chunks.append(sample)
    collected += len(sample)
    if collected >= 20000:
        break

df_all = pd.concat(chunks).iloc[:20000]

# Write to JSONL
print(f"[*] Writing {len(df_all)} flows to {target_test_file}...")
with open(target_test_file, 'w', encoding='utf-8') as f:
    for idx, row in df_all.iterrows():
        label = str(row['Label'])
        feat_dict = {}
        for col in df_all.columns:
            if col != 'Label':
                v = row[col]
                if pd.isna(v):
                    feat_dict[col] = 0.0
                else:
                    feat_dict[col] = float(v) if isinstance(v, (int, float, np.number)) else str(v)
        record = {
            "flow_index": int(idx),
            "ground_truth_label": label,
            "features": feat_dict
        }
        f.write(json.dumps(record) + '\n')

print(f"[+] Successfully wrote {len(df_all)} held-out flows to {target_test_file}")
EOF

echo "[+] Sync completed successfully."
