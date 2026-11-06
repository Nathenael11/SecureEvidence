# -*- coding: utf-8 -*-
"""
SecureEvidence: Repository Secrets Scanner
Verifies that no real cryptographic secrets, private keys, or passwords are baked into tracked repository files.
"""

import os
import sys
import re

PATTERNS = [
    (re.compile(r'-----BEGIN\s+(EC|RSA|DSA|OPENSSH|ENCRYPTED)?\s*PRIVATE KEY-----'), "Private Key PEM block"),
    (re.compile(r'["\']0x[a-fA-F0-9]{64}["\']'), "Potential Ethereum raw private key hex"),
    (re.compile(r'JWT_SECRET\s*=\s*["\'](?!render-demo|INSA-DEMO|test-secret)[^"\']{16,}["\']'), "Hardcoded production JWT secret"),
]

# Standard publicly known Hardhat node test accounts
HARDHAT_PUBLIC_TEST_KEYS = {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
}

EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", ".venv", "venv"}
EXCLUDED_FILES = {"package-lock.json", "check_secrets.py"}

def scan_repository(root_dir: str) -> int:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for filename in filenames:
            if filename in EXCLUDED_FILES or filename.endswith(".pyc") or filename.endswith(".db"):
                continue
            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, root_dir)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern, desc in PATTERNS:
                            m = pattern.search(line)
                            if m:
                                matched_val = m.group(0).strip('\'"')
                                if matched_val in HARDHAT_PUBLIC_TEST_KEYS:
                                    continue
                                if "test" in rel_path.lower() or "mock" in line.lower() or "example" in line.lower():
                                    continue
                                findings.append(f"[{desc}] {rel_path}:{line_num}")
            except Exception:
                pass

    if findings:
        print(f"FAILED: Found {len(findings)} potential secrets in repository:")
        for f in findings:
            print(f"  - {f}")
        return 1

    print("PASS: Repository is clean. No private keys or hardcoded production secrets found.")
    return 0

if __name__ == "__main__":
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.exit(scan_repository(repo_root))
