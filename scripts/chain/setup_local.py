# -*- coding: utf-8 -*-
"""
scripts/chain/setup_local.py
One command that starts the local Hardhat node (if not running), deploys EvidenceTracker,
sets up Hardhat account #0 as local service key, and writes local configuration to .env.
Safe to re-run (idempotent).
SECURITY: Prints ONLY addresses; never prints private keys.
"""

import os
import sys
import time
import json
import subprocess
import urllib.request
import urllib.error

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ENV_FILE = os.path.join(PROJECT_DIR, ".env")
DEPLOYMENTS_DIR = os.path.join(PROJECT_DIR, "deployments")
DEPLOYMENT_FILE = os.path.join(DEPLOYMENTS_DIR, "localhost.json")

# Standard Hardhat Account #0 (Publicly known local test credentials)
HARDHAT_ACCOUNT_0_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
HARDHAT_ACCOUNT_0_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
RPC_URL = "http://127.0.0.1:8545"
CHAIN_ID = "31337"

def check_rpc(url: str) -> bool:
    req = urllib.request.Request(
        url,
        data=b'{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}',
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            return "result" in data
    except Exception:
        return False

def start_node_if_needed():
    if check_rpc(RPC_URL):
        return
    ps_script = os.path.join(os.path.dirname(__file__), "start_local_node.ps1")
    if os.path.exists(ps_script):
        subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", ps_script], check=True, cwd=PROJECT_DIR)
    else:
        # Fallback background start
        subprocess.Popen(["npx", "hardhat", "node"], cwd=PROJECT_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Wait up to 30s
    for _ in range(60):
        time.sleep(0.5)
        if check_rpc(RPC_URL):
            return
    raise RuntimeError("Failed to connect to local Hardhat node at " + RPC_URL)

def deploy_contract() -> str:
    # Run hardhat deploy script to localhost
    env = os.environ.copy()
    env["SERVICE_ADDRESS"] = HARDHAT_ACCOUNT_0_ADDR
    cmd = ["npx.cmd" if os.name == "nt" else "npx", "hardhat", "run", "scripts/deploy.js", "--network", "localhost"]
    res = subprocess.run(cmd, cwd=PROJECT_DIR, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Deploy failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
    
    if not os.path.exists(DEPLOYMENT_FILE):
        raise RuntimeError("deployments/localhost.json was not created.")
    
    with open(DEPLOYMENT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        return data["contractAddress"]

def update_env(contract_address: str):
    env_vars = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env_vars[k.strip()] = v.strip()

    env_vars["CHAIN_MODE"] = "local"
    env_vars["CHAIN_RPC_URL"] = RPC_URL
    env_vars["CHAIN_ID"] = CHAIN_ID
    env_vars["CONTRACT_ADDRESS"] = contract_address
    env_vars["SUBMITTER_PRIVATE_KEY"] = HARDHAT_ACCOUNT_0_KEY
    env_vars["CONFIRMATIONS"] = "1"
    env_vars["HEAD_ANCHOR_EVERY"] = "10"
    env_vars.setdefault("EXPLORER_BASE_URL", "")

    # Write back
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
    start_node_if_needed()
    contract_addr = deploy_contract()
    update_env(contract_addr)
    # Output rule: Print only addresses
    print(f"Deployer address: {HARDHAT_ACCOUNT_0_ADDR}")
    print(f"Service address:  {HARDHAT_ACCOUNT_0_ADDR}")
    print(f"Contract address: {contract_addr}")

if __name__ == "__main__":
    main()
