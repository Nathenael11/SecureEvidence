# -*- coding: utf-8 -*-
"""
SecureEvidence: CLI Management Utility
Usage:
  python -m backend.manage create-user --username <username> --role <role> --name <full_name>
  python -m backend.manage verify-ledger
  python -m backend.manage export-ledger [--out <filename>]
"""

import os
import sys
import json
import argparse
import getpass
from backend.user_store import create_user, VALID_ROLES

def main():
    parser = argparse.ArgumentParser(description="SecureEvidence Management CLI")
    subparsers = parser.add_subparsers(dest="command")

    # create-user
    create_parser = subparsers.add_parser("create-user", help="Create a new administrative or officer user")
    create_parser.add_argument("--username", required=True, help="Unique username")
    create_parser.add_argument("--role", required=True, choices=list(VALID_ROLES), help="RBAC Role")
    create_parser.add_argument("--name", required=False, default=None, help="Full Name of the user")

    # verify-ledger
    subparsers.add_parser("verify-ledger", help="Cryptographically verify all blocks in the ledger hash chain")

    # export-ledger
    export_parser = subparsers.add_parser("export-ledger", help="Export entire evidence ledger records as JSON")
    export_parser.add_argument("--out", required=False, default=None, help="Optional output JSON file path")

    args = parser.parse_args()

    if args.command == "create-user":
        full_name = args.name or args.username
        password = getpass.getpass("Enter password (minimum 12 characters): ")
        if len(password) < 12:
            print("Error: Password must be at least 12 characters long.", file=sys.stderr)
            sys.exit(1)
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)

        try:
            user = create_user(
                username=args.username,
                full_name=full_name,
                role=args.role,
                password=password
            )
            print(f"[OK] User '{user['username']}' created successfully with role '{user['role']}'.")
        except Exception as e:
            print(f"Error creating user: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "verify-ledger":
        from blockchain.ledger_store import get_ledger_store
        store = get_ledger_store()
        res = store.verify_chain()
        if res.get("ok"):
            print(f"[OK] {res['message']} | Head Hash: {res.get('head_hash')}")
            sys.exit(0)
        else:
            print(f"[FAIL] {res.get('message')} (First broken block ID: {res.get('broken_id')})", file=sys.stderr)
            sys.exit(1)

    elif args.command == "export-ledger":
        from blockchain.ledger_store import get_ledger_store
        store = get_ledger_store()
        records = store.get_all_records()
        out_json = json.dumps(records, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out_json)
            print(f"[OK] Exported {len(records)} records to {args.out}")
        else:
            print(out_json)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
