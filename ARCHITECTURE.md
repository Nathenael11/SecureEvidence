# SecureEvidence System Architecture & Threat Model

This document outlines the technical architecture, cryptographic verification mechanics, and STRIDE threat analysis for **SecureEvidence**, an AI threat detection and digital forensic evidence integrity platform designed for the Information Network Security Administration (INSA) of Ethiopia.

---

## 1. High-Level System Architecture

SecureEvidence enforces strict non-repudiation and tamper detection across digital forensics workflows through a dual-layer storage and verification pipeline:

```text
+-----------------------------------------------------------------------------------+
|                            INGESTION & AI TRIAGE LAYER                            |
|  - Synthetic / Replayed NetFlow Telemetry (CICIDS2017 Benchmark)                  |
|  - Coverage Gating: Telemetry coverage < 60% rejected (INSUFFICIENT_DATA)         |
|  - Inference: XGBoost multi-class classifier + TreeSHAP feature attributions      |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                             EVIDENCE CANONICALIZATION                             |
|  - Sorted-key compact UTF-8 JSON serialization                                    |
|  - 256-bit SHA-256 digest computation (evidence_hash, raw_artifact_hash)          |
|  - SECP256R1 ECDSA officer signature generation                                   |
+-----------------------------------------+-----------------------------------------+
                                          |
                     +--------------------+--------------------+
                     |                                         |
                     v                                         v
+------------------------------------+   +------------------------------------------+
|       PRIMARY STORAGE LAYER        |   |       EXTERNAL ANCHORING LAYER           |
| (SQLite Persistent Hash Chain)     |   | (EvidenceTracker.sol on EVM Node)        |
| - Atomic BEGIN IMMEDIATE write     |   | - CHAIN_MODE=off | local | sepolia       |
| - SHA-256 prev_hash sequence       |   | - Hashes only: evidence, raw, model      |
| - Append-only SQLite triggers      |   | - Periodic ledger head anchor            |
| - Local custody timeline           |   | - Nonce tracking, retries & backoff      |
+------------------------------------+   +------------------------------------------+
```

---

## 2. Hybrid Storage Architecture

### Primary Store: SQLite Hash-Chained Ledger
- **Engine**: SQLite in WAL (Write-Ahead Logging) mode with `BUSY_TIMEOUT = 5000ms`.
- **Integrity**: Each record embeds a canonical SHA-256 hash chaining `prev_hash` to the preceding block's `record_hash`.
- **Enforcement**: Database triggers (`trg_ledger_prevent_delete`, `trg_ledger_prevent_update`) abort any unauthorized modification or deletion at the engine level. Status progression occurs strictly from `active` to `superseded` via a governed transaction specifying `superseded_by`.

### Secondary Store: Independent EVM Chain Anchoring
- **Smart Contract (`EvidenceTracker.sol`)**:
  - `storeEvidence(evidenceHash, rawArtifactHash, merkleRoot, caseId, incidentType, targetAsset, investigator, ipfsCid)`
  - `anchorLedgerHead(headHash, recordCount)` — enforces strictly monotonic record counters; reverts if `recordCount` decreases.
  - Role-based permissions via OpenZeppelin `AccessControl` (`AUDITOR_ROLE`, `ANALYST_ROLE`, `DEFAULT_ADMIN_ROLE`).
- **Data Minimization (Hashes Only)**:
  - Anchored on-chain: 32-byte cryptographic fingerprints (`evidenceHash`, `rawArtifactHash`, `modelHash`, `headHash`).
  - Never placed on-chain: Raw telemetry, packet payloads, officer personal names, internal network topologies, or IP addresses.

---

## 3. Verification & Disagreement Mechanics

1. **Local Verification**:
   - Computes canonical SHA-256 digest of submitted JSON artifact.
   - Compares against local SQLite record hash and checks sequential `prev_hash` chain linkage.
2. **On-Chain Verification**:
   - Calls `getEvidenceRecord(evidenceHash)` on `EvidenceTracker.sol`.
   - Confirms block number, timestamp, and transaction receipt stored in `chain_receipts`.
3. **Discrepancy Detection**:
   - `LOCAL/CHAIN DISAGREEMENT`: If local DB record differs from on-chain anchored hash, system raises a critical alert and blocks subsequent anchoring until an administrator reviews and acknowledges.
   - `TRUNCATED`: If local database record count is less than the latest on-chain anchored head count or the hash at that count differs, the system halts anchoring to prevent operating on a rolled-back or truncated database.
4. **Atomic Fallback Guard**:
   - In `CHAIN_MODE=local` or `CHAIN_MODE=sepolia`, chain anchoring must succeed before SQLite commits. If the RPC node is down, wrong chain ID is detected, or gas is insufficient, the system returns HTTP 503 and leaves the SQLite ledger completely unchanged.

---

## 4. STRIDE Threat Model

| Threat Category | Threat Description | Security Controls & Mitigations | Residual Risks |
| :--- | :--- | :--- | :--- |
| **Spoofing Identity** | Adversary attempts to forge investigator attribution or replay evidence tokens. | Identity bound strictly to authenticated JWT claims (`full_name`, `sub`, `officer_id`). Request body spoofing is rejected. Submitter service address is role-authenticated on-chain via `AccessControl`. | Key custody: In local/demo mode, private keys reside in `.env`. Production requires hardware security modules (HSM) and client-side signing. |
| **Tampering with Data** | Insider or intruder alters historical evidence records, timestamps, or log entries. | SQLite append-only triggers reject `UPDATE`/`DELETE`. SHA-256 hash chaining flags any modified byte. On-chain fingerprints detect recomputed local databases. | Chain reorg / testnet reset: Deep reorganizations on public testnets could invalidate recent transactions. Handled via multiple confirmation checks (2 confirmations on Sepolia). |
| **Repudiation** | Submitter or investigator denies having created or verified an evidence record. | Officer SECP256R1 ECDSA digital signatures, append-only custodial audit logs, on-chain transaction receipts with verifiable tx hash and block number. | Timestamp authority: Timestamps are internal server clock time, not legally certified RFC 3161 timestamps. |
| **Information Disclosure** | Leakage of classified infrastructure telemetry or citizen network communications. | Hashes only: Zero raw packet data, IP addresses, or personal data sent to the blockchain. All raw artifacts stored only on private local filesystems. | Payload guessing: Extremely low-entropy payloads could theoretically be targeted by precomputation; prevented by structured canonical serialization with incident IDs and timestamps. |
| **Denial of Service** | Flooding backend or exhausting EVM gas balances with high-volume anchoring requests. | Sliding-window IP rate limiters, coverage gating (<60% coverage rejected), transaction gas bounds (500,000 gas limit), and exponential backoff retry logic. | RPC provider availability: Outage of public/third-party RPC endpoints causes 503 fallback. Mitigated in production by private consortium validator nodes. |
| **Elevation of Privilege** | Attacker calls administrative functions such as `anchorLedgerHead` or alters system roles. | FastAPI RBAC dependencies (`require_role`), OpenZeppelin on-chain role checks (`AUDITOR_ROLE`, `DEFAULT_ADMIN_ROLE`), Argon2id password hashing with account lockout. | RPC trust: Reliance on an untrusted external RPC endpoint could permit spoofing view calls. Mitigated by chain ID verification and internal hash-chain validation. |

---

## 5. Summary of Residual Risks

1. **RPC Provider Trust**: A malicious or compromised RPC endpoint could spoof view queries (`getEvidenceRecord`). In production, INSA must run dedicated, authenticated validator nodes.
2. **Private Key Custody**: Storing `SUBMITTER_PRIVATE_KEY` in environment files is suitable only for testnets and demonstration. Production requires HSM-backed key management (FIPS 140-2 Level 3).
3. **Public Testnet Reset & Reorganizations**: Public testnets (such as Sepolia) are subject to periodic deprecation, hard resets, and ephemeral chain reorgs. Long-term evidentiary preservation requires an Ethiopian national consortium network.
4. **RFC 3161 Timestamping**: Server-generated ISO 8601 timestamps provide technical sequence tracking but lack external legal authority certification until integrated with a licensed Trust Service Provider (TSP).
