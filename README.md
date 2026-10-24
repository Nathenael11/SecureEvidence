# SecureEvidence
### AI Threat Detection & Court-Admissible Blockchain Evidence Ledger for INSA

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-46E3B7.svg?style=flat&logo=render&logoColor=white)](https://secureevidence.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0%2B-EB5424.svg)](https://xgboost.readthedocs.io/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636.svg?logo=solidity&logoColor=white)](https://soliditylang.org/)
[![Ethereum](https://img.shields.io/badge/Ethereum-Hardhat-yellow.svg?logo=ethereum&logoColor=white)](https://hardhat.org/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Nathenael%20Ermias-0A66C2.svg?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/nathenael-ermias-753746428?utm_source=share_via&utm_content=profile&utm_medium=member_android)
[![Author](https://img.shields.io/badge/Author-Nathenael%20Ermias-0B2A4A.svg)](mailto:nathenaelermias13@gmail.com)

---

## 🌐 Live Application
The interactive web platform is deployed and live at:  
👉 **[https://secureevidence.onrender.com](https://secureevidence.onrender.com)**

### Quick Demo Access:
| Role | Username | Password | Operational Scope |
| :--- | :--- | :--- | :--- |
| **Investigator** | `demo_investigator` | `DemoTestPassword123!` | AI Threat Detection, TreeSHAP Analysis, Blockchain Anchoring, Integrity Verification |
| **Admin** | `demo_admin` | `DemoTestPassword123!` | System Administration, Audit Logs, Chain Recovery |

*(Or click the one-click quick-fill buttons on the Sign In screen.)*

---

## 📌 Executive Summary
During criminal and cyber warfare proceedings in Ethiopian courts, digital evidence collected by forensic teams is often challenged under *Computer Crime Proclamation No. 958/2016* and *Electronic Signature Proclamation No. 1072/2018*:
> *"How can the court verify that digital evidence, network logs, and packet captures were not altered after being seized?"*

**SecureEvidence** solves this national security challenge by bridging three core technologies:
1. **AI Threat Detection**: High-accuracy classification of malicious traffic using a 12-class XGBoost model trained on benchmark **CICIDS2017** data, with **TreeSHAP** mathematical feature explainability.
2. **Big Data Processing**: High-throughput telemetry ingestion powered by **Apache Spark Structured Streaming** and Kafka event pipelines.
3. **Cryptographic Blockchain Ledger**: Deterministic **SHA-256 canonical hashing** and EVM **Solidity smart contracts** (`EvidenceTracker.sol`), backed by an immutable hash-chained SQLite verifiable ledger.

Any 1-bit alteration in captured evidence immediately triggers a cryptographic hash mismatch, making post-seizure tampering mathematically impossible to conceal.

---

## 🏛️ System Architecture

```text
                                +-----------------------------------------------+
                                |     ETHIOPIAN CRITICAL INFRASTRUCTURE         |
                                |  (Ethio Telecom, CBE, NBE, Gov Gateways)      |
                                +-----------------------+-----------------------+
                                                        | NetFlow / IP Flow Data
                                                        v
                                +-----------------------------------------------+
                                |        1. BIG DATA INGESTION LAYER            |
                                |       (Spark Structured Streaming)            |
                                +-----------------------+-----------------------+
                                                        | Flow Feature Extraction
                                                        v
                                +-----------------------------------------------+
                                |        2. AI THREAT DETECTION ENGINE          |
                                |      (XGBoost + TreeSHAP Explainability)      |
                                +-----------------------+-----------------------+
                                                        | Telemetry & Attribution
                                                        v
                                +-----------------------------------------------+
                                |          3. BACKEND FORENSIC API              |
                                |         (FastAPI & SHA-256 Engine)            |
                                +-----------+-----------------------+-----------+
                                            |                       |
              Deterministic SHA-256 Digest  |                       | REST & WebSockets
                                            v                       v
        +-----------------------------------------------+   +-----------------------------------------------+
        |     4. EVIDENCE BLOCKCHAIN & LEDGER           |   |          5. FORENSIC WEB CONSOLE              |
        |  - Solidity Smart Contract (EVM / Hardhat)    |   |  - Real-Time AI Detection & TreeSHAP          |
        |  - SQLite Verifiable Hash Chain               |   |  - One-Click Blockchain Anchoring             |
        |  - Merkle Tree Proofs & ECDSA Signatures      |   |  - Interactive Tamper-Testing Engine          |
        |  - RFC 8785 Canonical JSON Serialization      |   |  - Printable Federal Court Certificate        |
        +-----------------------------------------------+   +-----------------------------------------------+
```

---

## ⚡ Key Capabilities & Modules

### 1. AI Threat Detection Engine (`ai_engine/`)
* **Benchmark Dataset**: Canadian Institute for Cybersecurity **CICIDS2017**.
* **Model**: 12-class multi-output XGBoost classifier trained on flow features (Flow Duration, Fwd/Bwd Packets, Flow Bytes/s, Packet Length Variance, TCP Flags, etc.).
* **Explainable AI (TreeSHAP)**: Dynamically computes top mathematical feature attributions, explaining *why* the model flagged an anomaly.
* **Coverage Gating**: A strict 60% feature coverage gate prevents zero-fill hallucinations from partial sensor data.

### 2. Blockchain & Cryptographic Ledger (`blockchain/`)
* **Solidity Smart Contract (`contracts/EvidenceTracker.sol`)**: Deployed on EVM with role-based access control, cryptographic Merkle root verification, and event emission.
* **Dual-Layer Ledger**:
  * **On-Chain**: Anchors root hashes to the Ethereum/Hardhat blockchain.
  * **Local Verifiable Ledger**: SQLite database with append-only triggers and a cryptographic hash chain linking each block to the previous block's SHA-256 digest.
* **Digital Signatures**: ECDSA P-256 digital signing for officer non-repudiation.
* **Tamper Proofing**: Modifying any field (case ID, IP address, packet count) immediately breaks chain verification and invalidates the court certificate.

### 3. Big Data Processing (`big_data/`)
* **Spark Structured Streaming Engine**: Processes raw telemetry streams with strict schema validation and vectorized feature pipelines.
* **Sliding Window Aggregation**: 1-minute window metrics and anomaly alerting.
* **Simulation & Replay**: Replays held-out CICIDS2017 flow streams with zero synthetic data drift.

### 4. Forensic Analyst Console (`frontend/`)
* **INSA Official Visual Design**: Navy & Steel design system adhering to Ethiopian institutional standards.
* **Interactive Tamper Testing**: Analysts can tamper with raw JSON payloads in real time to observe cryptographic rejection.
* **Court Evidence Certificates**: Generates exportable, printable **FDRE Federal High Court Digital Evidence Certificates**.

---

## 🚀 Quick Start (Local Setup)

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/Nathenael11/SecureEvidence.git
cd SecureEvidence

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Application
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Open your browser at **http://localhost:8000**.

### 3. Run Automated Tests
```bash
# Python Backend & AI Tests
pytest tests/ -v

# Blockchain Smart Contract Tests
cd blockchain && npx hardhat test
```

---

## 📡 REST API Reference

| Method | Endpoint | Access Role | Description |
|:---|:---|:---|:---|
| `POST` | `/auth/login` | Public | Authenticates credentials, issues JWT access token + refresh cookie |
| `POST` | `/detect` | Investigator, Admin | Evaluates network telemetry with XGBoost & TreeSHAP |
| `POST` | `/evidence/store` | Investigator, Admin | Anchors evidence hash and Merkle root to blockchain/ledger |
| `POST` | `/evidence/verify` | Authenticated | Validates integrity against ledger with byte-level diff |
| `POST` | `/evidence/verify-public` | Public | External verification of raw evidence JSON or SHA-256 hash |
| `GET` | `/evidence` | Authenticated | Lists all anchored forensic records |
| `GET` | `/cases/{case_id}` | Authenticated | Returns chain of custody for an investigation |
| `GET` | `/stats` | Authenticated | Returns operational statistics and ledger health |
| `GET` | `/health` | Public | System status and active ledger diagnostic checks |

*Full interactive OpenAPI documentation is available at `/docs`.*

---

## 📂 Project Structure

```text
SecureEvidence/
├── ai_engine/                      # Machine learning models, XGBoost inference & TreeSHAP
│   ├── detector.py                 # Core detection engine & MITRE mapping
│   ├── flow_preprocessor.py        # 77-feature extraction & coverage gating
│   ├── models/                     # Serialized XGBoost model, scaler & metadata
│   └── threat_detection.ipynb      # Complete EDA & training notebook
├── backend/                        # FastAPI REST API & security layer
│   ├── main.py                     # API routing, CORS & static files
│   ├── security.py                 # JWT authentication & RBAC matrix
│   ├── schemas.py                  # Pydantic data schemas
│   └── services/                   # Detection, Evidence & STIX 2.1 services
├── big_data/                       # Spark Structured Streaming pipeline
├── blockchain/                     # EVM smart contracts & cryptographic ledger
│   ├── contracts/EvidenceTracker.sol # Solidity smart contract
│   ├── ledger_store.py             # SQLite cryptographic hash-chain engine
│   ├── merkle_tree.py              # SHA-256 Merkle root implementation
│   └── web3_client.py              # Web3 Ethereum client & local simulator
├── frontend/                       # Forensic Web Console (HTML, CSS, JS)
├── tests/                          # Automated Pytest & Hardhat test suites
├── Dockerfile                      # Production container configuration
├── render.yaml                     # Render Cloud deployment blueprint
├── requirements.txt                # Python dependencies
└── README.md                       # Project documentation
```

---

## 🙏 Acknowledgments & Special Thanks

I would like to express my sincere gratitude and appreciation to:
* **Information Network Security Administration (INSA)**: For hosting the summer camp program, inspiring this project, and fostering technological innovation in national cyber defense.
* **INSA Summer Camp Crew & Staff**: For their dedication, tireless coordination, and providing an exceptional environment for advanced technical learning.
* **My Mentors**: A heartfelt thank you to **Mikiyas**, **Abreham**, **Inas**, **Hanamariam**, and **Selam** for their invaluable guidance, constructive critiques, and continuous mentorship across Artificial Intelligence, Big Data engineering, and Blockchain systems throughout this journey.

---

## 👨‍💻 Author & Contact

**Nathenael Ermias**
* **Specialization**: AI Engineering, Big Data & Blockchain
* **LinkedIn**: [Nathenael Ermias](https://www.linkedin.com/in/nathenael-ermias-753746428?utm_source=share_via&utm_content=profile&utm_medium=member_android)
* **Email**: [nathenaelermias13@gmail.com](mailto:nathenaelermias13@gmail.com)
* **GitHub**: [@Nathenael11](https://github.com/Nathenael11)

---

## ⚖️ Legal & Regulatory Disclaimer
*Determination of evidence admissibility in criminal or civil proceedings is the exclusive judicial prerogative of the presiding judge. SecureEvidence provides technical supporting evidence of data integrity, chain of custody, and cryptographic non-repudiation referencing FDRE Computer Crime Proclamation (No. 958/2016) and Electronic Signature Proclamation (No. 1072/2018) (statutory weight to be evaluated by legal counsel).*
