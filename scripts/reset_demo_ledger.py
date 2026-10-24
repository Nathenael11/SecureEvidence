# -*- coding: utf-8 -*-
"""
SecureEvidence: Reset Demo Ledger Script
Backs up current data/ledger.db, then initializes a fresh, valid hash-chained ledger.
"""

import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

DATA_DIR = os.path.join(BASE_DIR, "data")
LEDGER_PATH = os.path.join(DATA_DIR, "ledger.db")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")


def reset_demo_ledger():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"ledger_backup_{ts}.db")

    if os.path.exists(LEDGER_PATH):
        # 1. Back up existing ledger
        shutil.copy2(LEDGER_PATH, backup_file)
        print(f"[+] Backed up existing ledger to: {backup_file}")

        # Also backup wal/shm if present
        for ext in ["-wal", "-shm"]:
            wal_file = LEDGER_PATH + ext
            if os.path.exists(wal_file):
                shutil.copy2(wal_file, os.path.join(BACKUP_DIR, f"ledger_backup_{ts}.db{ext}"))
                try:
                    os.remove(wal_file)
                except Exception:
                    pass

        try:
            os.remove(LEDGER_PATH)
        except Exception as e:
            print(f"[!] Warning removing old ledger: {e}")

    # 2. Initialize fresh ledger
    from blockchain.ledger_store import SqliteLedgerStore
    store = SqliteLedgerStore(LEDGER_PATH)
    verif = store.verify_chain()
    head = store.get_chain_head()
    store.close()

    print(f"[+] Fresh ledger initialized at: {LEDGER_PATH}")
    print(f"[+] Chain verification: {verif}")
    print(f"[+] Chain head block #{head.get('id')} hash: {head.get('record_hash', '')[:16]}...")
    return backup_file


if __name__ == "__main__":
    reset_demo_ledger()
