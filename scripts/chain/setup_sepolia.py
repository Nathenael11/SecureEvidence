# -*- coding: utf-8 -*-
"""
scripts/chain/setup_sepolia.py
Automated setup and deployment preparation for Ethereum Sepolia testnet.

SECURITY RULES:
- Never print, log, commit or ask for private keys.
- Keys live only in .env (git-ignored and untracked).
- Redact keys in all logs and errors.
- Never try to create accounts, solve CAPTCHAs, use faucets, or sign up for RPC providers.
- If RPC URL is missing or balance < 0.02 ETH, print 5-line checklist and exit 0 without failing.
"""

import os
import sys
import json
import subprocess
from eth_account import Account
from web3 import Web3

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ENV_FILE = os.path.join(PROJECT_DIR, ".env")
DEPLOYMENTS_DIR = os.path.join(PROJECT_DIR, "deployments")
DEPLOYMENT_FILE = os.path.join(DEPLOYMENTS_DIR, "sepolia.json")

HARDHAT_LOCAL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
REQUIRED_BALANCE_WEI = Web3.to_wei(0.02, "ether")

def verify_git_safety():
    try:
        res = subprocess.run(
            ["git", "ls-files", ".env"],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True
        )
        if ".env" in res.stdout:
            raise RuntimeError("CRITICAL SECURITY ERROR: .env is tracked in git! Untrack it immediately.")
    except Exception as e:
        if "CRITICAL" in str(e):
            raise

def read_env() -> dict:
    env_vars = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    k, v = stripped.split("=", 1)
                    env_vars[k.strip()] = v.strip()
    return env_vars

def write_env(updates: dict):
    verify_git_safety()
    env_vars = read_env()
    env_vars.update(updates)

    lines = []
    written_keys = set()
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    k = stripped.split("=", 1)[0].strip()
                    if k in env_vars:
                        lines.append(f"{k}={env_vars[k]}\n")
                        written_keys.add(k)
                        continue
                lines.append(line if line.endswith("\n") else line + "\n")

    for k, v in env_vars.items():
        if k not in written_keys:
            lines.append(f"{k}={v}\n")

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)

def main():
    verify_git_safety()
    env = read_env()

    # (a) Check SUBMITTER_PRIVATE_KEY
    private_key = env.get("SUBMITTER_PRIVATE_KEY")
    if not private_key or private_key.lower() == HARDHAT_LOCAL_KEY.lower():
        acct = Account.create()
        private_key = acct.key.hex()
        if not private_key.startswith("0x"):
            private_key = f"0x{private_key}"
        write_env({
            "SUBMITTER_PRIVATE_KEY": private_key,
            "CHAIN_ID": "11155111",
            "EXPLORER_BASE_URL": "https://sepolia.etherscan.io",
            "CONFIRMATIONS": "2"
        })
        address = acct.address
    else:
        try:
            acct = Account.from_key(private_key)
            address = acct.address
        except Exception:
            acct = Account.create()
            private_key = acct.key.hex()
            if not private_key.startswith("0x"):
                private_key = f"0x{private_key}"
            write_env({"SUBMITTER_PRIVATE_KEY": private_key})
            address = acct.address

    print(f"Submitter address: {address}")

    # (b) check CHAIN_RPC_URL and balance
    rpc_url = env.get("CHAIN_RPC_URL") or env.get("SEPOLIA_RPC_URL")
    balance_wei = 0
    rpc_ok = False

    if rpc_url and not ("127.0.0.1" in rpc_url or "localhost" in rpc_url):
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))
            if w3.is_connected():
                rpc_ok = True
                balance_wei = w3.eth.get_balance(address)
        except Exception:
            rpc_ok = False

    # (c) if RPC URL is missing or balance < 0.02 ETH, print 5-line checklist and STOP
    if not rpc_ok or balance_wei < REQUIRED_BALANCE_WEI:
        balance_eth = Web3.from_wei(balance_wei, "ether") if rpc_ok else 0
        print(f"Current Sepolia balance: {balance_eth} ETH (Minimum required: 0.02 ETH)")
        print("1. Get a Sepolia RPC URL (Alchemy or a public endpoint) and put it in .env as CHAIN_RPC_URL.")
        print(f"2. Fund {address} with Sepolia test ETH from a faucet (the pk910 PoW faucet needs no mainnet balance).")
        print("3. Re-run this script.")
        sys.exit(0)

    # (d) Once both are fine, deploy to Sepolia and anchor
    print(f"Sepolia balance verified: {Web3.from_wei(balance_wei, 'ether')} ETH. Deploying...")

    deploy_cmd = ["npm.cmd" if os.name == "nt" else "npm", "run", "deploy:sepolia"]
    deploy_env = os.environ.copy()
    deploy_env["CHAIN_RPC_URL"] = rpc_url
    deploy_env["SUBMITTER_PRIVATE_KEY"] = private_key
    deploy_env["SERVICE_ADDRESS"] = address
    res = subprocess.run(deploy_cmd, cwd=PROJECT_DIR, env=deploy_env, capture_output=True, text=True)
    if res.returncode != 0:
        clean_out = res.stdout.replace(private_key, "[REDACTED]")
        clean_err = res.stderr.replace(private_key, "[REDACTED]")
        print(f"Sepolia deployment failed:\n{clean_out}\n{clean_err}")
        sys.exit(1)

    if not os.path.exists(DEPLOYMENT_FILE):
        print("Error: deployments/sepolia.json was not generated.")
        sys.exit(1)

    with open(DEPLOYMENT_FILE, "r", encoding="utf-8") as f:
        deploy_meta = json.load(f)
        contract_addr = deploy_meta["contractAddress"]

    write_env({
        "CHAIN_MODE": "sepolia",
        "CHAIN_RPC_URL": rpc_url,
        "CHAIN_ID": "11155111",
        "CONTRACT_ADDRESS": contract_addr,
        "EXPLORER_BASE_URL": "https://sepolia.etherscan.io",
        "CONFIRMATIONS": "2"
    })
    print(f"EvidenceTracker deployed to Sepolia at: {contract_addr}")

    sys.path.insert(0, PROJECT_DIR)
    from blockchain.web3_client import Web3EvidenceClient
    client = Web3EvidenceClient(
        rpc_url=rpc_url,
        contract_address=contract_addr,
        chain_mode="sepolia",
        chain_id=11155111,
        submitter_private_key=private_key,
        explorer_base_url="https://sepolia.etherscan.io",
        confirmations=2
    )

    import uuid
    test_case_id = f"INSA-SEPOLIA-{uuid.uuid4().hex[:6].upper()}"
    receipt = client.store_evidence(
        case_id=test_case_id,
        incident_type="BENIGN",
        target_asset="National-Gateway-Sepolia-01",
        raw_evidence={"network": "sepolia", "verification": "live_testnet_anchor"},
        investigator="demo_investigator"
    )

    tx_hash = receipt.get("tx_hash")
    explorer_link = f"https://sepolia.etherscan.io/tx/{tx_hash}"
    print(f"Test record anchored successfully.")
    print(f"Tx Hash: {tx_hash}")
    print(f"Explorer: {explorer_link}")

if __name__ == "__main__":
    main()
