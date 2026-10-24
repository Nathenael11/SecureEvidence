# SecureEvidence
### AI Threat Detection & Court-Admissible Blockchain Evidence Ledger for INSA

[![Python](https://img.shields.io/badge/Python-3.10%2B-amber.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109%2B-ffb300.svg)](https://fastapi.tiangolo.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0%2B-ff6f00.svg)](https://xgboost.readthedocs.io/)
[![Dataset](https://img.shields.io/badge/Dataset-CICIDS2017-blue.svg)](https://www.kaggle.com/datasets/cicdataset/cicids2017)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636.svg)](https://soliditylang.org/)
[![Ethereum](https://img.shields.io/badge/Ethereum-Hardhat-yellow.svg)](https://hardhat.org/)
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing-00e676.svg)]()
[![Author](https://img.shields.io/badge/Author-Nathenael%20Ermias-ffb300.svg)](mailto:nathenaelermias13@gmail.com)

**SecureEvidence** is a cybersecurity forensics and evidence non-repudiation prototype platform designed for the **Information Network Security Administration (INSA)** of Ethiopia. It demonstrates digital evidence integrity and non-repudiation in judicial contexts by integrating **XGBoost AI threat classification**, **PySpark log stream processing**, and **SHA-256 evidence ledger anchoring** (with dual live Ethereum/Besu consortium node and in-memory simulated cryptographic ledger modes).

---

## The Problem Being Solved

### Evidence Admissibility in Ethiopian Courts:
During criminal proceedings in the **Federal High Court** and **Federal Supreme Court** of Ethiopia under *Computer Crime Proclamation No. 958/2016* and *Electronic Signature Proclamation No. 1072/2018* (statutory weight to be evaluated by legal counsel), digital evidence authenticity is a critical concern:

> *"How can the court verify that forensic investigators or third parties did not alter server logs, timestamps, or packet captures after seizing infrastructure?"*

Standard database records and syslog files lack cryptographic non-repudiation. Without mathematical proof of integrity, critical forensic evidence risks being contested.

### The SecureEvidence Architecture:
1. **Real-time Threat Triage**: Evaluates synthetic telemetry mapped to the benchmark **CICIDS2017** dataset with XGBoost and TreeSHAP explainability, gating inference if telemetry coverage is below 60%.
2. **Deterministic Cryptographic Digest**: The raw flow features, classification, model metadata, and investigator attribution are serialized to canonical JSON and hashed with **SHA-256**.
3. **Ledger Anchoring**: The 256-bit hash and ECDSA officer signature are anchored to the simulated cryptographic ledger or live Ethereum smart contract (EvidenceTracker.sol).
4. **Court Tamper Verification**: Any post-incident modification (even a single bit or packet count change) alters the calculated hash, failing verification and proving tampering. Unaltered evidence confirms matching against the anchored record.

---

## System Architecture

```text
                                    +-----------------------------------------------+
                                    |     ETHIOPIAN CRITICAL INFRASTRUCTURE         |
                                    |  (Ethio Telecom, CBE, NBE, Gov Gateways)      |
                                    +-----------------------+-----------------------+
                                                            | NetFlow / IP Flow Data
                                                            v
                                    +-----------------------------------------------+
                                    |        1. BIG DATA INGESTION LAYER            |
                                    |     (PySpark High-Throughput Stream)          |
                                    +-----------------------+-----------------------+
                                                            | Flow Feature Extraction
                                                            v
                                    +-----------------------------------------------+
                                    |        2. AI THREAT DETECTION ENGINE          |
                                    |       (XGBoost - CICIDS2017 Benchmark)        |
                                    |   - DDoS                 - PortScan           |
                                    |   - Botnet Infiltration  - Brute Force        |
                                    |   - SQL Injection        - BENIGN             |
                                    +-----------------------+-----------------------+
                                                            | Threat Diagnosis & Telemetry
                                                            v
                                    +-----------------------------------------------+
                                    |          3. BACKEND FORENSIC API              |
                                    |          (FastAPI & SHA-256 Engine)           |
                                    +-----------+-----------------------+-----------+
                                                |                       |
                  SHA-256 Evidence Digest       |                       | REST API & UI
                                                v                       v
            +-----------------------------------------------+   +-----------------------------------------------+
            |     4. EVIDENCE LEDGER LAYER                  |   |     5. FORENSIC ANALYST CONSOLE               |
            | (Solidity Contract / Simulated Cryptographic) |   | (Amber / Charcoal Command Dashboard)          |
            |   - Deterministic SHA-256 Digest Anchoring    |   |   - Preset Scenario Buttons (Demo)            |
            |   - ECDSA Officer Signatures (SECP256R1)      |   |   - Real-Time TreeSHAP Feature Attributions   |
            |   - Integrity & Tamper Detection Engine       |   |   - Interactive Tamper-Testing Engine         |
            +-----------------------------------------------+   |   - Printable Federal Court Certificate       |
                                                                +-----------------------------------------------+
```

---

## Technical Overview

### 1. AI Threat Detection Engine (`ai_engine/`)
- **Dataset**: Canadian Institute for Cybersecurity **CICIDS2017** ([Kaggle Dataset](https://www.kaggle.com/datasets/cicdataset/cicids2017)).
- **Features Extracted**: Flow Duration, Total Fwd Packets, Total Backward Packets, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Packet Length Mean, SYN Flag Count, Down/Up Ratio, Init_Win_bytes_forward, and related flow attributes.
- **Threat Classes & MITRE ATT&CK Mapping**:
  - DDoS -> MITRE **T1498.001** (Direct Network Flood)
  - PortScan -> MITRE **T1046** (Network Service Discovery)
  - Botnet_Infiltration -> MITRE **T1071.001** (C2 Protocols)
  - Web_Attack_Brute_Force -> MITRE **T1110.001** (Password Guessing)
  - Web_Attack_SQL_Injection -> MITRE **T1190** (Exploit Public-Facing Application)
  - BENIGN -> Baseline Network Operation
- **Jupyter Notebook (`ai_engine/threat_detection.ipynb`)**: Contains complete exploratory data analysis (EDA), correlation matrices, distribution plots, data cleaning, stratified 80/20 train/test split, XGBoost training, confusion matrix visualizations, and feature importance rankings.

### 2. Big Data Processing (`big_data/`)
- **Real Streaming Pipeline (Kafka + Spark Structured Streaming + XGBoost)**: Production-grade streaming pipeline running in WSL Ubuntu-22.04.
  - **Source Telemetry**: Replay of recorded CICIDS2017 flows from the held-out test split (never training rows).
  - **Kafka Ingestion**: High-throughput broker running in KRaft mode with topics `flows.raw` (3 partitions), `alerts.scored` (3 partitions), and `flows.deadletter` (1 partition).
  - **Spark Structured Streaming Engine**: `big_data/spark_stream_processor.py` processes raw flows with strict JSON schema validation, vectorizes features through shared `ai_engine.flow_preprocessor` with coverage gating (<60% routes to `INSUFFICIENT_DATA`), performs inference with XGBoost loaded once per executor, and idempotently upserts scored alerts and 1-minute window statistics into SQLite `stream_results.db`.
  - **Stream API & Control**: Read-only WSL service on `127.0.0.1:8100` proxied via FastAPI backend `/stream/status`, `/stream/alerts`, `/stream/windows`, and `/stream/control` (governed execution with full audit log chain tracking).
  - **Analyst Integration**: Streaming detections are preliminary operational telemetry; legal evidence anchoring remains strictly governed by manual analyst review.

### 3. Blockchain Evidence Ledger (`blockchain/`)
- **Smart Contract (contracts/EvidenceTracker.sol)**: Solidity ^0.8.20 contract maintaining forensic audit logs, event topics (EvidenceStored, EvidenceVerified), and role-based access control.
- **Dual-Mode Web3 Client (web3_client.py & ledger_store.py)**: Connects to live Ethereum/Hardhat RPC nodes (`LIVE CHAIN` mode) or operates a local, persistent SQLite hash-chained cryptographic ledger (`SIMULATED LEDGER` mode, with in-memory fallback for testing). Evidence hashes are SHA-256 hash-chained (each block's `prev_hash` links to the prior block's `record_hash`).

### 3b. Ledger Storage & Hash Chain Architecture
- **Persistent SQLite Hash Chain**: When `LEDGER_BACKEND=sqlite` (default), records are stored in `data/ledger.db` with WAL mode, foreign keys, and busy timeout. Each block calculates a canonical SHA-256 digest over sorted-key compact UTF-8 JSON of all fields.
- **Single-Writer Concurrency**: Appends execute inside atomic `BEGIN IMMEDIATE` transactions, reading the current chain head and writing the incremented block to prevent forks.
- **Append-Only Triggers**: SQLite triggers enforce append-only integrity by raising `ABORT` on unauthorized `UPDATE` or `DELETE` statements on `ledger_records`, `custody_entries`, and `audit_log_entries`. The only permitted mutation is a governed status transition from `active` to `superseded` accompanied by an explicit pointer to the replacement block ID (`superseded_by`).
- **What the Hash Chain Proves**:
  - Proves sequential ordering and mathematical integrity of the records.
  - Detects any retrospective modification of payload content, officer identity, timestamp, or parent linkage via `verify_chain()`.
  - Ensures local tamper evidence without requiring heavy external infrastructure.
- **What the Hash Chain Does NOT Prove**:
  - Does NOT provide decentralized multi-party consensus: an adversary with direct filesystem access to `ledger.db` can drop triggers or recompute and rewrite the entire hash chain from an arbitrary block forward.
  - This is why cryptographic chain verification (`verify_chain()`) and external anchoring are necessary.
### 3c. Blockchain Anchoring (CHAIN_MODE=off|local|sepolia)
SecureEvidence features real end-to-end blockchain anchoring on Ethereum-compatible networks (local Hardhat or Sepolia testnet), operating alongside the persistent SQLite ledger:

- **What Is Anchored (Hashes Only)**:
  - Evidence canonical SHA-256 fingerprint (evidenceHash)
  - Raw network artifact SHA-256 digest (`rawArtifactHash`)
  - Machine learning model metadata & label encoder digest (merkleRoot / modelHash)
  - Ledger periodic chain head hash (`headHash`) with monotonic record counter (`recordCount`)
- **What Is NOT Anchored**:
  - No raw telemetry, payload bytes, or packet streams
  - No investigator or analyst names or personal data
  - No internal network topologies or real IP addresses
- **Local Node Setup**:
  1. Run python scripts/chain/setup_local.py. This starts a local Hardhat node in the background on port 8545, deploys EvidenceTracker.sol, grants necessary roles to the submitter account, and configures .env (CHAIN_MODE=local, CHAIN_ID=31337).
  2. Safe to re-run anytime (idempotent).
- **Sepolia Testnet Setup**:
  1. Run python scripts/chain/setup_sepolia.py.
  2. If credentials or funds are insufficient, it displays the setup checklist:
     ```
     1. Get a Sepolia RPC URL (Alchemy or a public endpoint) and put it in .env as CHAIN_RPC_URL.
     2. Fund <address> with Sepolia test ETH from a faucet (the pk910 PoW faucet needs no mainnet balance).
     3. Re-run this script.
     ```
  3. Once funded, re-running deploys the contract to Sepolia, updates .env, anchors a live test record, and outputs the transaction URL on Etherscan.
- **Architecture & System Limitations**:
  - Public test networks (Sepolia) and single local nodes are non-production test harnesses; a single local node is not decentralized.
  - Submitter service key custody in .env is for development and demonstration purposes only. Production deployment requires hardware security modules (HSM) and client-side signing.
  - In national sovereign deployment, EvidenceTracker would be hosted on a permissioned consortium network with INSA-operated validator nodes.
  - Public test network records are not legal timestamps. See [ARCHITECTURE.md](ARCHITECTURE.md) for full system specifications and the STRIDE threat model.

### 4. Forensic Analyst Console (`frontend/`)
- **UI Design**: Official INSA Navy & Steel design system (#0B2A4A Navy, #1F6FB2 Steel Blue, #F3F6FA Clean Surface) adhering to Ethiopian government cybersecurity standards.
- **Company Logos**: Official logos for **INSA**, **Ethio Telecom**, **Commercial Bank of Ethiopia (CBE)**, and **National Bank of Ethiopia (NBE)**.
- **Tamper Simulation Engine**: Interactive JSON editor allowing analysts to modify a single byte and observe immediate cryptographic rejection.
- **Court Certificate Generator**: Modal generating exportable and printable **FDRE Federal High Court Digital Evidence Certificates**.

---

## Quick Start & Installation

### 1. Clone & Environment Setup
```bash
git clone https://github.com/Nathenael11/SecureEvidence.git
cd SecureEvidence

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Pre-trained AI Artifacts
The production XGBoost model (`threat_detector_xgb.json`), standard scaler, and class metadata are pre-trained and serialized in `ai_engine/models/`. No training step is needed.

### 3. Verification & Automated Tests
The system was rigorously verified using:
1. **Python Backend Test Suite**:
   ```bash
   pytest tests/test_api.py tests/test_auth.py tests/test_ai_model.py -v
   ```
2. **Smart Contract Test Suite**:
   ```bash
   cd blockchain && npx hardhat test
   ```
3. **Manual Interactive UI Walkthrough**: Comprehensive interactive verification of threat triage, TreeSHAP feature attributions, dispute resolution, hash-chain anchoring, and official court certificate generation.

### 4. User Authentication & Separation of Duties

No administrative passwords or production secret keys are committed to the repository.

- **Demo Mode Notice (`DEMO_MODE=true`)**: The `DEMO_MODE=true` setting in `.env` is intended **exclusively for evaluation and prototype demonstration**. In demo mode, accounts are seeded across all four core forensic roles to demonstrate **Separation of Duties**:
  - `demo_investigator` (Role: `investigator`): Ingests telemetry, executes AI detection, and anchors verified records to the cryptographic ledger.
  - `demo_analyst` (Role: `analyst`): Reviews model/heuristic disagreements, records written justifications, and exports STIX 2.1 intelligence bundles.
  - `demo_auditor` (Role: `court_auditor`): Verifies evidence integrity, downloads court certificates, and inspects immutable API audit trails.
  - `demo_admin` (Role: `system_admin`): Administers node configuration and manages infrastructure services.
  
  In any production environment, **`DEMO_MODE=false` must be configured**, which strictly enforces a high-entropy `JWT_SECRET` and disables pre-seeded passwords.

- **Suricata Ingestion & Feature Coverage**:
  Raw Suricata EVE flow records provide approximately 12 basic telemetry fields out of the 77 features expected by the CICIDS2017 AI model. Rather than silently zero-filling or hallucinating the remaining 65 statistical parameters (such as packet length variance, IAT metrics, or sub-flow counts), SecureEvidence strictly enforces a 60% coverage threshold (`FEATURE_COVERAGE_THRESHOLD = 0.60`). Raw Suricata EVE records evaluate to ~15.6% coverage and are safely flagged as `INSUFFICIENT_DATA`. For full AI threat classification, flows extracted with CICFlowMeter or complete network telemetry extractors should be used.

- **Production User Creation (CLI)**:
```bash
python -m backend.manage create-user --username <username> --full-name "<Full Name>" --role <analyst|investigator|court_auditor|system_admin>
```
The CLI prompts interactively for a secure password (minimum 12 characters, hashed with bcrypt).

### 5. Start the Application Server
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Navigate to: **http://localhost:8000**

---

## REST API Reference

| Method | Endpoint | Access Role | Description |
|---|---|---|---|
| POST | `/auth/login` | Public | Authenticates credentials, returns short-lived access JWT + httpOnly refresh cookie |
| POST | `/auth/refresh` | Public (Cookie) | Rotates refresh token and returns fresh access token |
| POST | `/auth/logout` | Authenticated | Revokes refresh token and clears session |
| GET | `/auth/me` | Authenticated | Returns authenticated user profile, full name, and role |
| GET | `/health` | Public | Returns system diagnostics, active ledger mode, and component status |
| POST | `/detect` | Analyst, Inv, Admin | Evaluates network telemetry with XGBoost, TreeSHAP, and coverage gate |
| POST | `/ingest/suricata` | Analyst, Inv, Admin | Ingests Suricata EVE record and extracts flow features |
| POST | `/evidence/store` | Investigator, Admin | Anchors digital evidence to the ledger (identity bound to authenticated token) |
| POST | `/evidence/verify` | Authenticated | Verifies payload against ledger with byte-level discrepancy checking |
| POST | `/evidence/verify-public` | Public (Rate-limited) | Allows external auditors / court officials to verify raw JSON or hashes |
| GET | `/evidence/download/{hash}` | Authenticated | Downloads canonical forensic evidence artifact for verification |
| GET | `/evidence` | Authenticated | Lists anchored evidence records from active ledger |
| GET | `/evidence/{hash}` | Authenticated | Fetches single anchored record by SHA-256 hash |
| GET | `/cases` | Authenticated | Lists all registered cases and associated evidence hashes |
| GET | `/cases/{case_id}` | Authenticated | Returns evidence items and chain of custody for a case |
| GET | `/stats` | Authenticated | Returns verifications run, mismatches detected, and ledger row count |
| POST | `/stream/simulate` | Authenticated | Simulates PySpark micro-batch stream processing |

Interactive Swagger documentation is available at **http://localhost:8000/docs**.

---

## Directory Structure

```text
SecureEvidence/
├── .github/workflows/ci.yml        # GitHub Actions CI workflow
├── ai_engine/
│   ├── models/                     # Serialized XGBoost model, scaler & metadata
│   ├── detector.py                 # Production inference engine & MITRE mapper
│   └── threat_detection.ipynb      # Model development, EDA & evaluation notebook
├── backend/
│   ├── services/                   # Singleton services (Detection, Evidence, Logs)
│   ├── config.py                   # Environment configuration & constants
│   ├── main.py                     # FastAPI REST API & static routing
│   ├── manage.py                   # CLI user management (create-user)
│   ├── schemas.py                  # Pydantic validation models
│   ├── security.py                 # JWT auth, token rotation, brute-force protection
│   └── user_store.py               # SQLite user store (argon2id passwords)
├── big_data/
│   ├── spark_stream_processor.py   # PySpark micro-batch stream processor
│   └── stream_simulator.py         # Telemetry generator
├── blockchain/
│   ├── contracts/EvidenceTracker.sol  # Solidity smart contract
│   ├── chain_of_custody.py         # Chain-of-custody entry builder
│   ├── digital_signature.py        # ECDSA officer signature helpers
│   ├── local_timestamp.py          # Internal timestamp authority
│   ├── merkle_tree.py              # SHA-256 Merkle tree implementation
│   └── web3_client.py              # Dual-mode Web3 & cryptographic ledger client
├── frontend/
│   ├── images/                     # Official logos (INSA, Ethio Telecom, CBE, NBE)
│   ├── css/styles.css              # Amber & Charcoal theme stylesheet
│   ├── js/app.js                   # Analyst console client-side logic
│   └── index.html                  # Web UI entry point
├── tests/
│   ├── fixtures/                   # JSON test fixtures (CICIDS2017 samples)
│   ├── conftest.py                 # Shared pytest fixtures
│   ├── test_ai_model.py            # AI inference & model integrity tests
│   ├── test_api.py                 # API endpoint & lifecycle tests
│   ├── test_auth.py                # Auth, role matrix & security tests
│   ├── test_big_data.py            # Stream ingestion tests
│   ├── test_big_data_stream.py     # Stream equivalence tests
│   ├── test_blockchain.py          # Canonicalization & tamper detection tests
│   ├── test_blockchain_real.py     # Real blockchain node integration tests
│   ├── test_e2e_playwright.py      # End-to-end browser tests
│   ├── test_ledger_sqlite.py       # SQLite hash-chain ledger tests
│   └── test_stream_proxy.py        # Stream proxy routing tests
├── .gitignore                      # Excludes __pycache__, node_modules, *.db, etc.
├── Dockerfile                      # Container build manifest
├── docker-compose.yml              # Compose configuration
├── requirements.txt                # Python dependencies (pinned)
├── run_web.bat                     # Windows quick-start script
└── README.md                       # This file
```

---

## System Comparison & Technical Differentiation

| Architectural Dimension | Traditional Forensic Logging (Syslog / SIEM) | SecureEvidence Prototype Platform |
| :--- | :--- | :--- |
| **Tamper Detection** | Post-facto log audits (vulnerable to log deletion) | Cryptographic Avalanche: Any 1-bit alteration causes immediate hash mismatch |
| **Judicial Admissibility** | Disputed routinely under Proclamation No. 958/2016 | Deterministic SHA-256 evidence anchoring with internal cryptographic timestamps and dual-mode ledger support |
| **Officer Non-Repudiation** | Usernames / Database access records | Cryptographic SECP256R1 ECDSA digital signatures per officer. **DEMO KEY CUSTODY**: In DEMO_MODE, officer ECDSA P-256 key pairs are generated server-side — this is not for production. In production, officers must sign client-side using hardware tokens (HSM/smart cards). |
| **Chain of Custody** | Paper forms or mutable DB timestamps | Cryptographically hash-linked sequential chain of custody entries |
| **AI Explainability** | Black-box alerts | Feature Attributions (XAI) outputting top 5 drivers with percentage impact |
| **Threat Intelligence** | Proprietary alert formats | OASIS STIX 2.1 Threat Intelligence Bundles with MITRE ATT&CK alignment |
| **Ledger Mode Transparency** | N/A (Often misleadingly marketed as blockchain) | Explicit multi-mode architecture: SQLite hash-chained primary ledger with independent on-chain cryptographic anchoring (CHAIN_MODE=off|local|sepolia) |

---

## Limitations & Future Work

1. **Hardware Security Modules (HSM):** While current officer key pairs utilize SECP256R1 ECDSA cryptography, enterprise production deployment requires anchoring private keys inside FIPS 140-2 Level 3 Hardware Security Modules or smart cards. In DEMO_MODE, keys are generated server-side — **DEMO KEY CUSTODY, not for production**.
2. **Confidential Computing (Intel SGX / AMD SEV):** To protect raw telemetry during AI inference from untrusted host hypervisors, future iterations will execute XGBoost inside confidential enclaves.
3. **Consensus Finality on EVM:** The production blockchain network will operate as an Ethereum IBFT 2.0 / PoA permissioned consortium across INSA, the Federal High Court, and the Ministry of Innovation and Technology (MInT).
4. **Zero-Knowledge Evidence Proofs (zk-SNARKs):** Implementing zk-SNARKs will allow defense counsel to verify that an evidence record exists and meets specific predicates without revealing sensitive national infrastructure IPs.
5. **Slither static analysis not run:** `slither-analyzer` is not installed in the project venv. Solidity security analysis requires Linux/WSL: `pip install slither-analyzer && slither blockchain/contracts/`.
6. **42 remaining pytest warnings:** Most are third-party library deprecations (httpx/starlette, anyio, websockets, sklearn pickle version, joblib/NumPy 2.5). One project-owned warning was fixed (`HTTP_422_UNPROCESSABLE_ENTITY` → `HTTP_422_UNPROCESSABLE_CONTENT`). The rest require upstream package upgrades.
7. **MFA not implemented:** Multi-Factor Authentication (TOTP, FIDO2/WebAuthn) is listed as a future work item. Current authentication uses argon2id password hashing with account lockout after 5 failures.
8. **No real RFC 3161 TSA:** Timestamps are generated by an internal server-side clock (`blockchain/local_timestamp.py`, labeled "internal timestamp — not RFC 3161"). A real RFC 3161 timestamp authority (e.g., DigiCert, Sectigo) is required for legally binding judicial timestamps. This is future work.

---

## Legal & Regulatory Compliance Notice

> **Admissibility Disclaimer:** Determination of evidence admissibility in criminal or civil proceedings is an exclusive judicial prerogative vested in the presiding judge. SecureEvidence provides technical supporting evidence of data integrity, chain of custody, and cryptographic non-repudiation referencing the FDRE Computer Crime Proclamation (No. 958/2016) and Electronic Signature Proclamation (No. 1072/2018) (to be verified by legal counsel against the official text). It does not issue legal rulings.


---

## Author & Project Information

- **Author**: **Nathenael Ermias**
- **Email**: [nathenaelermias13@gmail.com](mailto:nathenaelermias13@gmail.com)
- **Organization**: Information Network Security Administration (INSA)
- **Project**: *SecureEvidence: AI Threat Detection & Blockchain Evidence Integrity System*

---
## Preset Scenario Model Predictions & Telemetry Coverage

The table below documents the empirical model predictions and triage outcomes across the built-in CICIDS2017 presets evaluated by the inference engine:

| Preset Key | UI Preset Button | Sample Label | Model Prediction | Model Confidence | Triage Outcome | Disagreement Gating |
|---|---|---|---|---|---|---|
| `dos_hulk` | DoS Hulk | DoS Hulk | DoS Hulk | 0.9320 | `DoS Hulk` (Threat Confirmed) | No (Pure Model Match) |
| `ddos` | DDoS | DDoS | DDoS | 1.0000 | `DDoS` (Threat Confirmed) | No (Pure Model Match on full 77 features) |
| `botnet` | PortScan | PortScan | PortScan | 0.9403 | `PortScan` (Threat Confirmed) | No (Pure Model Match on full 77 features) |
| `sqli` | Web Attack | Web Attack | Web_Attack | 0.9960 | `Web Attack` (Threat Confirmed) | No (Pure Model Match on full 77 features) |
| `brute_force` | SSH-Patator | SSH-Patator | SSH-Patator | 0.9999 | `SSH-Patator` (Threat Confirmed) | No (Pure Model Match on full 77 features) |
| `benign` | Benign | BENIGN | BENIGN | 0.9999 | `BENIGN` (Traffic Allowed) | No (Pure Model Match) |
| `disagreement` | Dispute / Model Miss | Disagreement / Model Miss | BENIGN | 0.9999 | `MODEL/RULE DISAGREEMENT` | Yes (Analyst review required prior to anchoring) |

### Telemetry Coverage vs Partial Input Behavior
The production XGBoost multi-class classifier achieves ~1.00 precision and recall for DDoS when evaluated on complete 77-feature rows from the CICIDS2017 test partition. In live operations or minimal manual input forms where only a subset of flow attributes (e.g., 20–30 fields) is provided, `ai_engine.flow_preprocessor` fills missing statistical features with `0.0`. While the 60% coverage gate (`FEATURE_COVERAGE_THRESHOLD = 0.60`) allows such flows to proceed, missing features can cause the model to classify conservatively (e.g. baseline BENIGN) while heuristic rule engines may detect volumetric anomalies, triggering a `MODEL/RULE DISAGREEMENT`. This demonstrates the system's human-in-the-loop safety design: conflicting or low-coverage inferences are gated from ledger anchoring until a forensic analyst provides written justification.

### Single-Machine Benchmarking Realities
In development and prototype evaluation, the flow producer, Apache Kafka broker, Apache Spark Structured Streaming engine, and SQLite sink all execute on a single laptop under WSL Ubuntu-22.04 sharing CPU and RAM. Reported throughput numbers reflect window-accurate in-window measurements (events processed strictly within the send duration window) rather than artificial post-completion averages.

*Developed for national cyber defense and digital forensics in the Federal Democratic Republic of Ethiopia (statutory references to Proclamations No. 958/2016 and No. 1072/2018 to be verified by legal counsel).*
