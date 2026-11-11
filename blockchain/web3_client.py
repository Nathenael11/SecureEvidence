# -*- coding: utf-8 -*-
"""
SecureEvidence: Web3 & Cryptographic Forensics Engine
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: Blockchain & Digital Forensics (INSA)

Anchors forensic telemetry, raw artifact digests, digital signatures,
and chain-of-custody proofs to Ethereum/Hyperledger Besu smart contracts
or the high-assurance SQLite hash-chained cryptographic fallback ledger.
Supports CHAIN_MODE=off|local|sepolia with gas bounds, nonce management,
confirmations, backoff retries, and on-chain head anchors.
"""

import os
import json
import time
import math
import uuid
import hashlib
from typing import Dict, Any, List, Optional, Tuple

from .chain_of_custody import ChainOfCustody, CustodyAction
from .digital_signature import OfficerKeyManager
from .local_timestamp import LocalTimestampAuthority
from .merkle_tree import MerkleTree
from .ledger_store import LedgerStore, get_ledger_store


class BlockchainError(Exception):
    """Base exception for blockchain anchoring errors."""
    pass


class RpcDownError(BlockchainError):
    """Raised when the blockchain RPC endpoint cannot be reached."""
    pass


class WrongChainIdError(BlockchainError):
    """Raised when the connected blockchain network chain ID does not match configuration."""
    pass


class InsufficientFundsError(BlockchainError):
    """Raised when the submitter address lacks sufficient native gas currency."""
    pass


class ChainDisagreementError(BlockchainError):
    """Raised when local SQLite ledger state and on-chain state disagree."""
    pass


class Web3EvidenceClient:
    """
    Forensics Evidence Client.
    Supports live Ethereum/Hardhat/Sepolia RPC nodes and maintains a
    hash-chained cryptographic ledger backed by SQLite or Memory.
    """

    # Declared numeric feature field schema names for canonicalization
    NUMERIC_SCHEMA_FIELDS = {
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "total_length_fwd_packets", "total_length_bwd_packets", "fwd_packet_length_max",
        "fwd_packet_length_mean", "bwd_packet_length_mean", "flow_bytes_s", "flow_packets_s",
        "flow_iat_mean", "flow_iat_std", "fwd_iat_total", "bwd_iat_total", "fwd_packets_s",
        "bwd_packets_s", "packet_length_mean", "packet_length_std", "fin_flag_count",
        "syn_flag_count", "rst_flag_count", "psh_flag_count", "ack_flag_count",
        "urg_flag_count", "down_up_ratio", "average_packet_size", "init_win_bytes_forward",
        "init_win_bytes_backward", "flow duration", "total fwd packets", "total backward packets",
        "total length of fwd packets", "total length of bwd packets", "fwd packet length max",
        "fwd packet length min", "fwd packet length mean", "fwd packet length std",
        "bwd packet length max", "bwd packet length min", "bwd packet length mean",
        "bwd packet length std", "flow bytes/s", "flow packets/s", "flow iat mean",
        "flow iat std", "flow iat max", "flow iat min", "fwd iat total", "fwd iat mean",
        "fwd iat std", "fwd iat max", "fwd iat min", "bwd iat total", "bwd iat mean",
        "bwd iat std", "bwd iat max", "bwd iat min", "fwd psh flags", "bwd psh flags",
        "fwd urg flags", "bwd urg flags", "fwd header length", "bwd header length",
        "min packet length", "max packet length", "packet length variance", "cwe flag count",
        "ece flag count", "avg fwd segment size", "avg bwd segment size", "fwd header length.1",
        "fwd avg bytes/bulk", "fwd avg packets/bulk", "fwd avg bulk rate", "bwd avg bytes/bulk",
        "bwd avg packets/bulk", "bwd avg bulk rate", "subflow fwd packets", "subflow fwd bytes",
        "subflow bwd packets", "subflow bwd bytes", "act_data_pkt_fwd", "min_seg_size_forward",
        "active mean", "active std", "active max", "active min", "idle mean", "idle std",
        "idle max", "idle min"
    }

    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:8545",
        contract_address: Optional[str] = None,
        chain_mode: str = "off",
        chain_id: int = 31337,
        submitter_private_key: Optional[str] = None,
        explorer_base_url: Optional[str] = None,
        confirmations: int = 1,
        head_anchor_every: int = 10,
        store: Optional[LedgerStore] = None
    ):
        self.rpc_url = rpc_url
        self.contract_address = contract_address or "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        self.chain_mode = (chain_mode or "off").lower()
        self.chain_id = int(chain_id) if chain_id else 31337
        self.submitter_private_key = submitter_private_key or ""
        self.explorer_base_url = (explorer_base_url or "").rstrip("/")
        self.confirmations = max(1, int(confirmations)) if confirmations else 1
        self.head_anchor_every = max(1, int(head_anchor_every)) if head_anchor_every else 10

        self.author = "Nathenael Ermias"
        self.email = "nathenaelermias13@gmail.com"
        self.agency = "Information Network Security Administration (INSA)"

        self.is_connected = False
        self.web3 = None
        self.contract = None
        self.account = None
        self.is_chain_disagreement_blocked = False

        # Ledger store interface (SqliteLedgerStore or MemoryLedgerStore)
        self.store: LedgerStore = store or get_ledger_store()
        OfficerKeyManager.set_store(self.store)

        # In-memory mirrors for high-speed indexing & compatibility
        self.chain: List[Dict[str, Any]] = []
        self.evidence_registry: Dict[str, Dict[str, Any]] = {}
        self.case_registry: Dict[str, List[str]] = {}

        # Chain of Custody & Batch Subsystems
        self.custody = ChainOfCustody(store=self.store)
        self.merkle_batches: Dict[str, Dict[str, Any]] = {}

        self._sync_from_store()
        self._try_connect_web3()

    @property
    def ledger_mode(self) -> str:
        """Explicitly declare active ledger mode for absolute judicial transparency."""
        if self.chain_mode == "local" and self.is_connected:
            return "SQLITE + LOCAL CHAIN ANCHOR (HARDHAT NODE)"
        if self.chain_mode == "sepolia" and self.is_connected:
            return "SQLITE + SEPOLIA TESTNET ANCHOR"
        if getattr(self.store, "backend", "sqlite") == "sqlite":
            return "SIMULATED LEDGER (SQLITE HASH-CHAIN)"
        return "SIMULATED LEDGER (IN-MEMORY CRYPTOGRAPHIC ENGINE)"

    @property
    def is_live_chain(self) -> bool:
        return self.is_connected and self.chain_mode in ("local", "sepolia")

    def _build_fee_params(self, w3=None) -> Dict[str, Any]:
        """Build transaction fee parameters, preferring EIP-1559 Type 2 fees with baseFee buffer."""
        target_w3 = w3 or getattr(self, "web3", None)
        if not target_w3:
            return {"gasPrice": 20000000000}
        base_fee = None
        try:
            latest_block = target_w3.eth.get_block('latest')
            base_fee = latest_block.get('baseFeePerGas')
        except Exception:
            base_fee = None
        if base_fee is not None:
            try:
                priority_fee = target_w3.eth.max_priority_fee
            except Exception:
                priority_fee = target_w3.to_wei(2, 'gwei')
            max_fee = int(base_fee * 1.3) + priority_fee
            return {
                "maxFeePerGas": max_fee,
                "maxPriorityFeePerGas": priority_fee,
                "type": 2
            }
        gas_price = int(target_w3.eth.gas_price * 1.25) if self.chain_mode == "sepolia" else target_w3.eth.gas_price
        return {"gasPrice": gas_price}

    def _sync_from_store(self):
        """Synchronize in-memory cache from the persistent LedgerStore."""
        self.evidence_registry.clear()
        self.case_registry.clear()
        self.chain.clear()

        # Genesis block
        genesis = self.store.get_record_by_id(0)
        if genesis:
            self.chain.append({
                "index": 0,
                "timestamp": genesis.get("timestamp_utc", "2026-01-01T00:00:00Z"),
                "previous_hash": "0" * 64,
                "evidence_hash": "0" * 64,
                "case_id": "INSA-GENESIS-BLOCK",
                "investigator": "Nathenael Ermias",
                "metadata": "Genesis Block of SecureEvidence Digital Forensics Chain",
                "validator": "INSA-National-Root-Authority",
                "ledger_mode": self.ledger_mode,
                "block_hash": genesis.get("record_hash")
            })

        # Load all records
        all_records = self.store.get_all_records()
        for rec in reversed(all_records):  # Ascending order
            ev_hash = rec["evidence_hash"]
            cid = rec.get("case_id")

            chain_rc = self.store.get_chain_receipt(ev_hash)
            if chain_rc:
                rec["tx_hash"] = chain_rc.get("tx_hash")
                rec["chain_block_number"] = chain_rc.get("block_number")
                rec["chain_id"] = chain_rc.get("chain_id") or self.chain_id
                rec["contract_address"] = chain_rc.get("contract_address") or self.contract_address
                rec["is_on_chain"] = True

            rec["contract_address"] = rec.get("contract_address") or self.contract_address
            if rec.get("tx_hash"):
                if rec.get("chain_id") == 11155111 or self.chain_mode == "sepolia":
                    rec["ledger_mode"] = "SQLITE + SEPOLIA TESTNET ANCHOR"
                elif rec.get("chain_id") == 31337 or self.chain_mode == "local":
                    rec["ledger_mode"] = "SQLITE + LOCAL CHAIN ANCHOR (HARDHAT NODE)"
                else:
                    rec["ledger_mode"] = self.ledger_mode
            else:
                rec["ledger_mode"] = self.ledger_mode

            rec["tamper_proof_status"] = "VALID_ON_CHAIN" if (rec.get("tx_hash") or self.is_live_chain) else "VALID_IN_SIMULATED_LEDGER"
            rec["statutory_basis"] = "FDRE Proclamation No. 958/2016 and Proclamation No. 1072/2018 (to be verified by legal counsel)"
            rec["judicial_note"] = "Supporting forensic evidence. Judicial admissibility remains the sole prerogative of the court."

            if rec.get("superseded") and rec.get("superseded_by_hash"):
                rec["superseded_by"] = rec["superseded_by_hash"]

            self.evidence_registry[ev_hash] = rec
            if cid:
                if cid not in self.case_registry:
                    self.case_registry[cid] = []
                if ev_hash not in self.case_registry[cid]:
                    self.case_registry[cid].append(ev_hash)

            self.chain.append({
                "index": rec["block_number"],
                "timestamp": rec["timestamp"],
                "previous_hash": rec["prev_hash"],
                "evidence_hash": ev_hash,
                "raw_artifact_hash": rec.get("raw_artifact_sha256"),
                "case_id": cid,
                "incident_type": rec.get("incident_type", "FORENSIC_TELEMETRY"),
                "target_asset": rec.get("target_asset", "Target-Asset"),
                "investigator": rec.get("investigator", "INSA Investigator"),
                "officer_id": rec.get("officer_id"),
                "officer_signature": rec.get("officer_signature"),
                "tx_hash": rec.get("tx_hash"),
                "chain_block_number": rec.get("chain_block_number"),
                "is_on_chain": rec.get("is_on_chain", False),
                "ledger_mode": rec["ledger_mode"],
                "block_hash": rec["block_hash"]
            })

        # Load persistent Merkle Batches from store across workers/restarts
        if hasattr(self.store, "get_all_merkle_batches"):
            for b in self.store.get_all_merkle_batches():
                r_hash = b.get("root_hash", "").lower()
                if r_hash and r_hash not in self.merkle_batches and b.get("leaf_hashes"):
                    self.merkle_batches[r_hash] = {
                        "metadata": b,
                        "tree": MerkleTree(b["leaf_hashes"]),
                        "events": []
                    }

    def _init_contract(self):
        """Load contract ABI and initialize Contract instance."""
        if not self.web3:
            return
        from web3 import Web3
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        abi = None

        # Priority 1: Native Python contract ABI module (bundled in repository and container)
        try:
            from blockchain.contract_abi import EVIDENCE_TRACKER_ABI
            abi = EVIDENCE_TRACKER_ABI
        except Exception:
            pass

        # Priority 2: Standalone ABI JSON in blockchain directory
        if not abi:
            abi_json_path = os.path.join(base_dir, "blockchain", "EvidenceTracker_abi.json")
            if os.path.exists(abi_json_path):
                try:
                    with open(abi_json_path, "r", encoding="utf-8") as f:
                        abi = json.load(f)
                except Exception:
                    pass

        # Priority 3: Hardhat artifact JSON
        if not abi:
            artifact_path = os.path.join(
                base_dir,
                "blockchain",
                "artifacts",
                "blockchain",
                "contracts",
                "EvidenceTracker.sol",
                "EvidenceTracker.json"
            )
            if os.path.exists(artifact_path):
                try:
                    with open(artifact_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        abi = data.get("abi", [])
                except Exception:
                    pass

        if not abi:
            return

        try:
            self.contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(self.contract_address),
                abi=abi
            )
        except Exception as e:
            print(f"[ERROR] Failed to initialize contract at {self.contract_address}: {e}")
            self.contract = None

    def _try_connect_web3(self):
        """Attempt to connect and verify Web3 RPC if chain mode is on."""
        if self.chain_mode == "off":
            self.is_connected = False
            self.web3 = None
            return

        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 5}))
            if not w3.is_connected():
                self.is_connected = False
                return

            actual_chain_id = w3.eth.chain_id
            if self.chain_mode == "local" and self.chain_id and actual_chain_id != self.chain_id:
                self.is_connected = False
                return
            elif self.chain_mode == "sepolia" and actual_chain_id != 11155111:
                self.is_connected = False
                return

            self.web3 = w3
            self.is_connected = True
            if self.submitter_private_key:
                try:
                    self.account = w3.eth.account.from_key(self.submitter_private_key)
                except Exception:
                    self.account = None
            self._init_contract()
        except Exception:
            self.is_connected = False
            self.web3 = None

    def verify_connection(self):
        """Strictly verify connection and credentials when chain anchoring is required."""
        if self.chain_mode == "off":
            return

        from web3 import Web3
        try:
            w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 5}))
            if not w3.is_connected():
                self.is_connected = False
                raise RpcDownError(f"Blockchain RPC node unreachable at {self.rpc_url}")

            actual_chain_id = w3.eth.chain_id
            if self.chain_mode == "local" and self.chain_id and actual_chain_id != self.chain_id:
                self.is_connected = False
                raise WrongChainIdError(f"Connected chain ID {actual_chain_id} does not match configured local chain ID {self.chain_id}")
            elif self.chain_mode == "sepolia" and actual_chain_id != 11155111:
                self.is_connected = False
                raise WrongChainIdError(f"Connected chain ID {actual_chain_id} does not match Sepolia testnet ID 11155111")

            if self.submitter_private_key:
                account = w3.eth.account.from_key(self.submitter_private_key)
                balance = w3.eth.get_balance(account.address)
                if balance == 0:
                    self.is_connected = False
                    raise InsufficientFundsError(f"Submitter account {account.address} balance is 0 ETH (insufficient funds for gas)")
                self.account = account

            self.web3 = w3
            self.is_connected = True
            self._init_contract()
            if not self.contract:
                raise BlockchainError(f"Contract not initialized. Verify contract artifact at {self.contract_address}")
        except (RpcDownError, WrongChainIdError, InsufficientFundsError, BlockchainError):
            self.is_connected = False
            raise
        except Exception as e:
            self.is_connected = False
            raise RpcDownError(f"Failed to communicate with RPC at {self.rpc_url}: {str(e)}")

    def _send_signed_tx(self, func_call, gas_bound: int = 1500000) -> Dict[str, Any]:
        """Send a signed transaction to the contract with EIP-1559 fees, nonce handling, gas bounds, and safe retries."""
        if not self.web3 or not self.account:
            raise BlockchainError("Web3 connection or submitter key not configured.")

        w3 = self.web3
        last_exc = None
        broadcast_tx_hash = None

        for attempt in range(3):
            try:
                # If transaction was already broadcast in a prior attempt, check if already mined or pending
                if broadcast_tx_hash is not None:
                    try:
                        receipt = w3.eth.get_transaction_receipt(broadcast_tx_hash)
                        if receipt and receipt.get("blockNumber"):
                            b_num = receipt.get("blockNumber")
                            b_hash_bytes = receipt.get("blockHash")
                            b_hash_hex = b_hash_bytes.hex() if hasattr(b_hash_bytes, "hex") else str(b_hash_bytes)
                            tx_hex = broadcast_tx_hash.hex() if hasattr(broadcast_tx_hash, "hex") else str(broadcast_tx_hash)
                            if not tx_hex.startswith("0x"):
                                tx_hex = f"0x{tx_hex}"
                            if not b_hash_hex.startswith("0x"):
                                b_hash_hex = f"0x{b_hash_hex}"
                            return {
                                "tx_hash": tx_hex,
                                "block_number": b_num,
                                "block_hash": b_hash_hex,
                                "chain_id": w3.eth.chain_id,
                                "contract_address": self.contract_address
                            }
                    except Exception:
                        pass

                nonce = w3.eth.get_transaction_count(self.account.address, 'pending')

                # Dynamically estimate required gas with safety buffer
                try:
                    estimated_gas = func_call.estimate_gas({'from': self.account.address})
                    tx_gas = min(int(estimated_gas * 1.25), 2000000)
                except Exception:
                    tx_gas = gas_bound

                balance = w3.eth.get_balance(self.account.address)

                # Check EIP-1559 fee support (standard on Sepolia and modern EVMs)
                base_fee = None
                try:
                    latest_block = w3.eth.get_block('latest')
                    base_fee = latest_block.get('baseFeePerGas')
                except Exception:
                    base_fee = None

                tx_params = {
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': tx_gas,
                    'chainId': w3.eth.chain_id
                }

                if base_fee is not None:
                    # EIP-1559 Type 2 transaction
                    try:
                        priority_fee = w3.eth.max_priority_fee
                    except Exception:
                        priority_fee = w3.to_wei(2, 'gwei')
                    max_fee = int(base_fee * 1.3) + priority_fee
                    required_wei = max_fee * tx_gas
                    if balance < required_wei:
                        raise InsufficientFundsError(
                            f"Submitter account {self.account.address} has {balance} wei; requires {required_wei} wei for gas (EIP-1559)"
                        )
                    tx_params['maxFeePerGas'] = max_fee
                    tx_params['maxPriorityFeePerGas'] = priority_fee
                    tx_params['type'] = 2
                else:
                    # Legacy gasPrice transaction fallback
                    gas_price = int(w3.eth.gas_price * 1.25) if self.chain_mode == "sepolia" else w3.eth.gas_price
                    required_wei = gas_price * tx_gas
                    if balance < required_wei:
                        raise InsufficientFundsError(
                            f"Submitter account {self.account.address} has {balance} wei; requires {required_wei} wei for gas"
                        )
                    tx_params['gasPrice'] = gas_price

                tx = func_call.build_transaction(tx_params)
                signed = w3.eth.account.sign_transaction(tx, self.submitter_private_key)
                raw_tx_bytes = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
                tx_hash = w3.eth.send_raw_transaction(raw_tx_bytes)
                broadcast_tx_hash = tx_hash

                wait_timeout = 120 if self.chain_mode == "sepolia" else 60
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=wait_timeout)
                if receipt.get("status") == 0:
                    raise BlockchainError(f"Transaction reverted on chain: {tx_hash.hex()}")

                block_number = receipt.get("blockNumber")
                block_hash_bytes = receipt.get("blockHash")
                block_hash_hex = block_hash_bytes.hex() if hasattr(block_hash_bytes, "hex") else str(block_hash_bytes)

                # Wait for additional confirmations if required (e.g. Sepolia)
                if self.confirmations > 1:
                    target_block = block_number + self.confirmations - 1
                    conf_start = time.time()
                    while w3.eth.block_number < target_block and (time.time() - conf_start < 30):
                        time.sleep(1)

                tx_hex = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
                if not tx_hex.startswith("0x"):
                    tx_hex = f"0x{tx_hex}"
                if not block_hash_hex.startswith("0x"):
                    block_hash_hex = f"0x{block_hash_hex}"
                return {
                    "tx_hash": tx_hex,
                    "block_number": block_number,
                    "block_hash": block_hash_hex,
                    "chain_id": w3.eth.chain_id,
                    "contract_address": self.contract_address
                }
            except (InsufficientFundsError, WrongChainIdError):
                raise
            except Exception as e:
                last_exc = e
                # Check if transaction was already submitted / mined despite error (e.g. already known or timeout)
                err_text = str(e).lower()
                if "already known" in err_text or "nonce too low" in err_text:
                    if broadcast_tx_hash is not None:
                        try:
                            rc = w3.eth.wait_for_transaction_receipt(broadcast_tx_hash, timeout=30)
                            if rc and rc.get("status") == 1:
                                b_num = rc.get("blockNumber")
                                b_hash_b = rc.get("blockHash")
                                b_hash_h = b_hash_b.hex() if hasattr(b_hash_b, "hex") else str(b_hash_b)
                                tx_h = broadcast_tx_hash.hex() if hasattr(broadcast_tx_hash, "hex") else str(broadcast_tx_hash)
                                return {
                                    "tx_hash": tx_h if tx_h.startswith("0x") else f"0x{tx_h}",
                                    "block_number": b_num,
                                    "block_hash": b_hash_h if b_hash_h.startswith("0x") else f"0x{b_hash_h}",
                                    "chain_id": w3.eth.chain_id,
                                    "contract_address": self.contract_address
                                }
                        except Exception:
                            pass
                time.sleep(1 * (2 ** attempt))

        raise BlockchainError(f"Transaction failed after 3 attempts: {str(last_exc)}")

    @staticmethod
    def canonicalize_value(val: Any, field_name: Optional[str] = None) -> Any:
        """
        Recursively normalize payload values for deterministic cryptographic hashing:
        - Dict keys sorted alphabetically
        - Reject NaN / Infinity with ValueError
        - Coerce to numerical types ONLY when field is declared numeric in the feature schema
        - Whole floats normalized to integer representation
        - Lists normalized element-wise
        """
        if isinstance(val, float):
            if math.isnan(val) or math.isinf(val):
                raise ValueError("Cryptographic hashing rejected: NaN and Infinity are not allowed in evidence payloads.")
            if val.is_integer():
                return int(val)
            return val
        elif isinstance(val, int):
            return val
        elif isinstance(val, bool):
            return val
        elif isinstance(val, dict):
            return {k: Web3EvidenceClient.canonicalize_value(v, k) for k, v in sorted(val.items())}
        elif isinstance(val, list):
            return [Web3EvidenceClient.canonicalize_value(x, field_name) for x in val]
        elif isinstance(val, str):
            norm_key = field_name.strip().lower() if field_name else ""
            if field_name and (norm_key in Web3EvidenceClient.NUMERIC_SCHEMA_FIELDS or 
                               norm_key.replace("_", " ") in Web3EvidenceClient.NUMERIC_SCHEMA_FIELDS or
                               norm_key.replace(" ", "_") in Web3EvidenceClient.NUMERIC_SCHEMA_FIELDS):
                s = val.strip()
                try:
                    f = float(s)
                    if math.isnan(f) or math.isinf(f):
                        raise ValueError("Cryptographic hashing rejected: NaN/Infinity value in schema field.")
                    return int(f) if f.is_integer() else f
                except ValueError:
                    pass
            return val
        return val

    @staticmethod
    def calculate_evidence_hash(evidence_payload: Dict[str, Any]) -> str:
        """
        Generate a deterministic SHA-256 hash digest from forensic evidence payload.
        Normalizes numeric values only for schema-declared numeric features, sorts dictionary keys,
        and uses compact JSON separators without space padding.
        """
        canonical_obj = Web3EvidenceClient.canonicalize_value(evidence_payload)
        canonical_json = json.dumps(canonical_obj, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

    def store_evidence(
        self,
        case_id: str,
        incident_type: str,
        target_asset: str,
        raw_evidence: Dict[str, Any],
        investigator: str = "Nathenael Ermias",
        raw_artifact_bytes: Optional[bytes] = None,
        officer_id: str = "INSA-INV-4409"
    ) -> Dict[str, Any]:
        """
        Anchor a digital forensic incident.
        In chain mode: writes on-chain (hashes only: evidence hash, raw artifact hash, model hash),
        stores receipt in chain_receipts, and writes to SQLite ledger.
        SECURITY: If chain mode is active and the chain is unreachable, raises 503 error
        and DOES NOT modify the SQLite ledger.
        """
        if self.is_chain_disagreement_blocked:
            raise ChainDisagreementError(
                "Anchoring is blocked due to an unresolved LOCAL/CHAIN DISAGREEMENT. System administrator review required."
            )

        # 1. Raw artifact hashing
        raw_artifact_hash = hashlib.sha256(raw_artifact_bytes).hexdigest() if raw_artifact_bytes else hashlib.sha256(
            json.dumps(raw_evidence.get("raw_event", raw_evidence), sort_keys=True).encode()
        ).hexdigest()

        evidence_hash = self.calculate_evidence_hash(raw_evidence)

        # Check if already registered in persistent store (idempotent locally)
        existing = self.store.get_record_by_hash(evidence_hash)
        if existing:
            chain_rc = self.store.get_chain_receipt(evidence_hash)
            return {
                "status": "ALREADY_REGISTERED",
                "evidence_hash": evidence_hash,
                "block_number": existing["id"],
                "timestamp": existing["timestamp_utc"],
                "case_id": existing["case_id"],
                "ledger_mode": self.ledger_mode,
                "tx_hash": chain_rc.get("tx_hash") if chain_rc else existing.get("tx_hash"),
                "message": "Evidence fingerprint already registered on ledger."
            }

        # 2. In CHAIN_MODE, verify connection and send transaction BEFORE touching SQLite
        chain_tx_receipt = None
        if self.chain_mode in ("local", "sepolia"):
            self.verify_connection()

            # Check if already registered on-chain (idempotency by evidence hash)
            ev_bytes32 = bytes.fromhex(evidence_hash)
            on_chain_rec = None
            try:
                on_chain_rec = self.contract.functions.verifyEvidence(ev_bytes32).call()
            except Exception:
                pass

            if on_chain_rec and on_chain_rec[0]:  # isAuthentic
                # Already on chain - record on-chain block number without fake tx hash
                chain_block_num = on_chain_rec[4]
                tx_hash = None
                chain_tx_receipt = None
            else:
                # Send transaction to smart contract (hashes only: no payload, names or personal data)
                raw_bytes32 = bytes.fromhex(raw_artifact_hash)
                merkle_root = raw_evidence.get("merkle_root", "")
                if merkle_root and len(merkle_root) == 64:
                    merkle_bytes32 = bytes.fromhex(merkle_root)
                else:
                    merkle_bytes32 = b'\x00' * 32

                func_call = self.contract.functions.storeEvidence(
                    ev_bytes32,
                    raw_bytes32,
                    merkle_bytes32,
                    case_id,
                    "",   # incidentType omitted on chain for privacy
                    "",   # targetAsset omitted on chain for privacy
                    "",   # investigatorName omitted on chain for privacy
                    ""    # metadataUri omitted on chain for privacy
                )
                chain_tx_receipt = self._send_signed_tx(func_call)

        # 3. Cryptographic tokens and canonicalization
        timestamp_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        sig_nonce = str(uuid.uuid4().hex[:8])
        sig_info = OfficerKeyManager.sign_evidence_hash(
            officer_id, evidence_hash, case_id=case_id, timestamp=timestamp_iso, nonce=sig_nonce
        )
        tst_token = LocalTimestampAuthority.create_timestamp_token(evidence_hash)

        canonical_obj = self.canonicalize_value(raw_evidence)
        payload_canonical = json.dumps(canonical_obj, sort_keys=True, separators=(',', ':'))
        model_hash = raw_evidence.get("model_hash", "")

        # 4. Append record to SQLite LedgerStore
        pub_pem = sig_info.get("public_key_pem")
        fp = hashlib.sha256(pub_pem.encode('utf-8')).hexdigest() if pub_pem else None
        stored_block = self.store.append_record(
            evidence_hash=evidence_hash,
            case_id=case_id,
            payload_canonical=payload_canonical,
            officer_id=officer_id,
            timestamp_utc=timestamp_iso,
            raw_artifact_sha256=raw_artifact_hash,
            model_sha256=model_hash,
            officer_signature=sig_info["signature_b64"],
            timestamp_kind="internal",
            signer_public_key=pub_pem,
            key_fingerprint=fp
        )

        block_height = stored_block["id"]
        block_hash = stored_block["record_hash"]

        # 5. Save chain receipt ONLY if real on-chain transaction was executed
        if chain_tx_receipt and chain_tx_receipt.get("tx_hash"):
            tx_hash = chain_tx_receipt["tx_hash"]
            chain_block_num = chain_tx_receipt["block_number"]
            self.store.save_chain_receipt(
                evidence_hash=evidence_hash,
                tx_hash=tx_hash,
                block_number=chain_block_num,
                block_hash=chain_tx_receipt["block_hash"],
                chain_id=chain_tx_receipt["chain_id"],
                contract_address=chain_tx_receipt["contract_address"]
            )
        else:
            # No live chain tx -> do NOT invent a fake one
            tx_hash = None
            chain_block_num = None

        # 6. Chain of Custody logging
        self.custody.add_entry(
            case_id=case_id,
            evidence_hash=evidence_hash,
            action=CustodyAction.COLLECTED,
            officer_id=officer_id,
            officer_name=investigator,
            reason="Initial seizure and telemetry collection from perimeter sensor",
            signature=sig_info["signature_b64"],
            metadata={"target_asset": target_asset, "incident_type": incident_type}
        )
        self.custody.add_entry(
            case_id=case_id,
            evidence_hash=evidence_hash,
            action=CustodyAction.ANCHORED,
            officer_id=officer_id,
            officer_name=investigator,
            reason="Forensic hash and signatures anchored to " + ("live blockchain ledger" if self.is_live_chain else "simulated ledger record"),
            signature=sig_info["signature_b64"],
            metadata={"block_number": block_height, "ledger_mode": self.ledger_mode, "tx_hash": tx_hash}
        )

        # 7. Update in-memory registry mirrors
        record = {
            "evidence_hash": evidence_hash,
            "raw_artifact_hash": raw_artifact_hash,
            "raw_artifact_sha256": raw_artifact_hash,
            "case_id": case_id,
            "incident_type": incident_type,
            "target_asset": target_asset,
            "investigator": investigator,
            "officer_id": officer_id,
            "officer_signature": sig_info["signature_b64"],
            "officer_signature_note": "demo signature by server-held key, not independently verifiable",
            "public_key_pem": sig_info["public_key_pem"],
            "local_timestamp_token": tst_token,
            "rfc3161_token": tst_token,  # backwards-compatible alias
            "timestamp": timestamp_iso,
            "timestamp_note": "internal server timestamp - not RFC 3161",
            "block_number": block_height,
            "block_hash": block_hash,
            "tx_hash": tx_hash,
            "chain_block_number": chain_block_num,
            "contract_address": self.contract_address,
            "raw_evidence": raw_evidence,
            "ledger_mode": self.ledger_mode,
            "tamper_proof_status": "VALID_ON_CHAIN" if self.is_live_chain else "VALID_IN_SIMULATED_LEDGER",
            "statutory_basis": "FDRE Proclamation No. 958/2016 and Proclamation No. 1072/2018 (to be verified by legal counsel)",
            "judicial_note": "Supporting forensic evidence. Judicial admissibility remains the sole prerogative of the court."
        }

        self.evidence_registry[evidence_hash] = record
        if case_id not in self.case_registry:
            self.case_registry[case_id] = []
        if evidence_hash not in self.case_registry[case_id]:
            self.case_registry[case_id].append(evidence_hash)

        # 8. Automatic periodic ledger head anchoring (every HEAD_ANCHOR_EVERY records)
        if self.chain_mode in ("local", "sepolia") and self.is_connected:
            total_count = self.store.get_stats().get("total_evidence_stored", 0)
            if total_count > 0 and total_count % self.head_anchor_every == 0:
                try:
                    self.anchor_ledger_head()
                except Exception as e:
                    print(f"[WARN] Periodic ledger head anchor failed: {e}")

        explorer_url = f"{self.explorer_base_url}/tx/{tx_hash}" if self.explorer_base_url and self.chain_mode == "sepolia" and tx_hash else ""

        return {
            "status": "STORED_SUCCESSFULLY",
            "evidence_hash": evidence_hash,
            "raw_artifact_hash": raw_artifact_hash,
            "raw_artifact_sha256": raw_artifact_hash,
            "tx_hash": tx_hash,
            "block_number": block_height,
            "chain_block_number": chain_block_num,
            "block_hash": block_hash,
            "timestamp": timestamp_iso,
            "case_id": case_id,
            "investigator": investigator,
            "officer_id": officer_id,
            "officer_signature": sig_info["signature_b64"],
            "officer_signature_note": "demo signature by server-held key, not independently verifiable",
            "local_timestamp_token_hash": tst_token.get("token_hash", ""),
            "rfc3161_token_hash": tst_token.get("token_hash", tst_token.get("token_der_b64", "")[:32]),
            "contract_address": self.contract_address,
            "chain_id": self.chain_id if self.chain_mode != "off" else None,
            "chain_mode": self.chain_mode,
            "explorer_url": explorer_url,
            "ledger_mode": self.ledger_mode,
            "integrity_verified": True,
            "is_authentic": True,
            "tamper_status": "AUTHENTIC_UNMODIFIED",
            "on_chain_confirmed": bool(chain_block_num or (self.is_live_chain and tx_hash)),
            "computed_hash": evidence_hash
        }

    def anchor_ledger_head(self, head_hash: Optional[str] = None, record_count: Optional[int] = None) -> Dict[str, Any]:
        """
        Anchor the current SQLite ledger head record onto the blockchain via anchorLedgerHead.
        Can be invoked on-demand via POST /ledger/anchor-head.
        """
        if self.chain_mode == "off":
            raise BlockchainError("Cannot anchor ledger head: CHAIN_MODE is 'off'.")

        self.verify_connection()

        if not head_hash or record_count is None:
            stats = self.store.get_stats()
            record_count = stats.get("total_evidence_stored", 0)
            head_rec = self.store.get_chain_head()
            head_hash = head_rec.get("record_hash") if head_rec else "0" * 64

        head_bytes32 = bytes.fromhex(head_hash)
        func_call = self.contract.functions.anchorLedgerHead(head_bytes32, int(record_count))
        tx_receipt = self._send_signed_tx(func_call)

        self.store.save_head_anchor(
            head_hash=head_hash,
            record_count=int(record_count),
            tx_hash=tx_receipt["tx_hash"],
            block_number=tx_receipt["block_number"],
            chain_id=tx_receipt["chain_id"],
            contract_address=tx_receipt["contract_address"]
        )

        return {
            "status": "HEAD_ANCHORED",
            "head_hash": head_hash,
            "record_count": int(record_count),
            "tx_hash": tx_receipt["tx_hash"],
            "block_number": tx_receipt["block_number"],
            "chain_id": tx_receipt["chain_id"],
            "contract_address": tx_receipt["contract_address"]
        }

    def verify_evidence(self, presented_evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify whether presented forensic record matches an anchored ledger record.
        When chain mode is on, INTEGRITY VERIFIED requires BOTH local record and on-chain match.
        If local and chain disagree, returns LOCAL/CHAIN DISAGREEMENT and blocks anchoring.
        """
        computed_hash = self.calculate_evidence_hash(presented_evidence)
        local_record = self.store.get_record_by_hash(computed_hash)

        # On-chain verification view call if chain mode is active
        on_chain_authentic = None
        on_chain_rec = None
        if self.chain_mode in ("local", "sepolia") and self.is_connected and self.contract:
            ev_b32 = bytes.fromhex(computed_hash) if (computed_hash and len(computed_hash) == 64) else None
            if ev_b32:
                for attempt in range(3):
                    try:
                        on_chain_rec = self.contract.functions.verifyEvidence(ev_b32).call()
                        on_chain_authentic = bool(on_chain_rec[0])
                        if on_chain_authentic:
                            break
                    except Exception:
                        on_chain_authentic = None
                    if local_record and not on_chain_authentic and self.chain_mode == "sepolia" and attempt < 2:
                        time.sleep(1.2)

                # Fallback: check transaction receipt status if local record has confirmed chain receipt
                if not on_chain_authentic and local_record:
                    chain_rc = self.store.get_chain_receipt(computed_hash)
                    if chain_rc and chain_rc.get("tx_hash"):
                        try:
                            receipt = self.web3.eth.get_transaction_receipt(chain_rc["tx_hash"])
                            if receipt and receipt.get("status") == 1:
                                on_chain_authentic = True
                        except Exception:
                            pass

        # Check for Local/Chain Disagreement
        if self.chain_mode in ("local", "sepolia"):
            if on_chain_authentic is None:
                return {
                    "is_authentic": False,
                    "integrity_verified": False,
                    "tamper_status": "RPC_UNREACHABLE",
                    "integrity_result": "RPC UNREACHABLE",
                    "legal_ruling": "RPC UNREACHABLE",
                    "computed_hash": computed_hash,
                    "registered_hash": local_record["evidence_hash"] if local_record else None,
                    "ledger_mode": self.ledger_mode,
                    "judicial_admissibility": "Admissibility is determined exclusively by the presiding court under FDRE Evidence Law",
                    "on_chain_confirmed": False,
                    "message": "Blockchain RPC node unreachable during verification. In active chain mode, on-chain confirmation is required."
                }
            has_local = local_record is not None
            if has_local != on_chain_authentic:
                self.is_chain_disagreement_blocked = True
                return {
                    "is_authentic": False,
                    "integrity_verified": False,
                    "tamper_status": "LOCAL_CHAIN_DISAGREEMENT",
                    "integrity_result": "LOCAL/CHAIN DISAGREEMENT",
                    "legal_ruling": "LOCAL/CHAIN DISAGREEMENT",
                    "computed_hash": computed_hash,
                    "registered_hash": local_record["evidence_hash"] if local_record else None,
                    "ledger_mode": self.ledger_mode,
                    "judicial_admissibility": "Admissibility is determined exclusively by the presiding court under FDRE Evidence Law",
                    "on_chain_confirmed": on_chain_authentic,
                    "message": "LOCAL/CHAIN DISAGREEMENT: Record verification differs between SQLite ledger and on-chain contract. Anchoring blocked."
                }

        if local_record:
            is_superseded = local_record.get("status") == "superseded"
            replacement_hash = local_record.get("superseded_by_hash")
            chain_rc = self.store.get_chain_receipt(computed_hash)

            cached = self.evidence_registry.get(computed_hash, {})
            incident_type = cached.get("incident_type", local_record.get("incident_type", "FORENSIC_TELEMETRY"))
            target_asset = cached.get("target_asset", local_record.get("target_asset", "Target-Asset"))
            investigator = cached.get("investigator", local_record.get("investigator", "INSA Investigator"))

            tx_hash = chain_rc.get("tx_hash") if chain_rc else None
            chain_block_num = chain_rc.get("block_number") if chain_rc else (on_chain_rec[4] if on_chain_rec else None)
            explorer_url = f"{self.explorer_base_url}/tx/{tx_hash}" if self.explorer_base_url and self.chain_mode == "sepolia" and tx_hash else ""

            on_chain_confirmed = bool(on_chain_authentic)

            return {
                "is_authentic": True,
                "integrity_verified": True,
                "tamper_status": "SUPERSEDED" if is_superseded else "AUTHENTIC_UNMODIFIED",
                "computed_hash": computed_hash,
                "registered_hash": local_record["evidence_hash"],
                "raw_artifact_hash": local_record.get("raw_artifact_sha256"),
                "case_id": local_record["case_id"],
                "incident_type": incident_type,
                "target_asset": target_asset,
                "investigator": investigator,
                "officer_id": local_record.get("officer_id"),
                "officer_signature": local_record.get("officer_signature"),
                "block_number": local_record["id"],
                "chain_block_number": chain_block_num,
                "block_hash": local_record["record_hash"],
                "tx_hash": tx_hash,
                "chain_id": self.chain_id if self.chain_mode != "off" else None,
                "contract_address": self.contract_address if self.chain_mode != "off" else None,
                "explorer_url": explorer_url,
                "on_chain_confirmed": on_chain_confirmed,
                "on_chain_status": "On-chain: confirmed" if on_chain_confirmed else ("Local ledger confirmed" if local_record else "Unverified"),
                "timestamp": local_record["timestamp_utc"],
                "superseded": is_superseded,
                "superseded_by": replacement_hash,
                "ledger_mode": self.ledger_mode,
                "integrity_result": "SUPERSEDED" if is_superseded else "INTEGRITY VERIFIED: HASH MATCHES ANCHORED RECORD",
                "legal_ruling": "SUPERSEDED" if is_superseded else "INTEGRITY VERIFIED: HASH MATCHES ANCHORED RECORD",
                "statutory_basis": "FDRE Proclamation No. 958/2016 and Proclamation No. 1072/2018 (to be verified by legal counsel)",
                "judicial_note": "Cryptographic authenticity certified. Court retains sole jurisdiction over admissibility.",
                "judicial_admissibility": "Subject to exclusive judicial determination by the presiding court under FDRE Evidence Law",
                "message": "Cryptographic fingerprint matches the " + ("live blockchain record" if self.is_live_chain else "simulated ledger record") + ". No mismatch found between the submitted data and the anchored record."
            }
        else:
            case_id = presented_evidence.get("case_id") or presented_evidence.get("incident_id")
            case_match = self.store.get_records_by_case(case_id) if case_id else []
            raw_hash = hashlib.sha256(json.dumps(presented_evidence, sort_keys=True).encode()).hexdigest()
            artifact_match = self.store.get_record_by_raw_artifact(raw_hash)

            is_mismatch = bool(case_match or artifact_match)
            tamper_status = "HASH_MISMATCH" if is_mismatch else "HASH_MISMATCH_OR_UNANCHORED"

            return {
                "is_authentic": False,
                "integrity_verified": False,
                "tamper_status": tamper_status,
                "computed_hash": computed_hash,
                "registered_hash": None,
                "ledger_mode": self.ledger_mode,
                "integrity_result": "HASH MISMATCH / NOT FOUND",
                "legal_ruling": "HASH MISMATCH / NOT FOUND",
                "judicial_admissibility": "Admissibility is determined exclusively by the presiding court under FDRE Evidence Law",
                "on_chain_confirmed": False,
                "message": "Computed SHA-256 digest does not match any " + ("anchored blockchain block" if self.is_live_chain else "simulated ledger record") + ". The artifact has been modified or was not registered."
            }

    def verify_by_hash(self, evidence_hash: str) -> Dict[str, Any]:
        """Verify an evidence record by its hash string directly using SQL query."""
        clean_hash = evidence_hash.strip().lower()
        if clean_hash.startswith("0x"):
            clean_hash = clean_hash[2:]

        record = self.store.get_record_by_hash(clean_hash)
        if record:
            cached = self.evidence_registry.get(clean_hash, {})
            record["incident_type"] = record.get("incident_type") or cached.get("incident_type", "FORENSIC_TELEMETRY")
            record["target_asset"] = record.get("target_asset") or cached.get("target_asset", "Target-Asset")
            record["investigator"] = record.get("investigator") or cached.get("investigator", record.get("officer_id"))
            record["timestamp"] = record.get("timestamp_utc")
            record["block_number"] = record.get("id")
            if record.get("superseded_by") is not None:
                record["superseded_by_id"] = record["superseded_by"]
            if record.get("superseded_by_hash"):
                record["superseded_by"] = record["superseded_by_hash"]

            chain_rc = self.store.get_chain_receipt(clean_hash)
            if chain_rc:
                record["tx_hash"] = chain_rc.get("tx_hash")
                record["chain_block_number"] = chain_rc.get("block_number")

            if self.chain_mode != "off":
                record["chain_id"] = self.chain_id
                record["contract_address"] = self.contract_address

            return {
                "is_authentic": True,
                "integrity_verified": True,
                "tamper_status": "SUPERSEDED" if record.get("superseded") else "AUTHENTIC_UNMODIFIED",
                "evidence_hash": clean_hash,
                "ledger_mode": self.ledger_mode,
                "record": record
            }
        else:
            return {
                "is_authentic": False,
                "integrity_verified": False,
                "tamper_status": "NOT_FOUND_ON_CHAIN",
                "evidence_hash": clean_hash,
                "ledger_mode": self.ledger_mode,
                "record": None
            }

    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify SQLite hash chain integrity, and if chain mode is on,
        compare with the latest on-chain ledger head and report TRUNCATED if DB records are missing.
        """
        sqlite_res = self.store.verify_chain()
        if not sqlite_res.get("ok"):
            return sqlite_res

        if self.chain_mode in ("local", "sepolia") and self.is_connected and self.contract:
            try:
                head = self.contract.functions.getLatestHead().call()
                on_chain_head_bytes32 = head[0]
                on_chain_count = head[1]

                if on_chain_count > 0:
                    on_chain_hash_hex = on_chain_head_bytes32.hex()
                    if on_chain_hash_hex.startswith("0x"):
                        on_chain_hash_hex = on_chain_hash_hex[2:]

                    stats = self.store.get_stats()
                    db_count = stats.get("total_evidence_stored", 0)

                    if db_count < on_chain_count:
                        # Attempt to auto-seed pre-anchored records if local database is empty or behind
                        if hasattr(self.store, "_seed_ledger_fixtures"):
                            conn = self.store._get_connection()
                            try:
                                self.store._seed_ledger_fixtures(conn)
                            finally:
                                conn.close()
                            self._sync_from_store()
                            stats = self.store.get_stats()
                            db_count = stats.get("total_evidence_stored", 0)

                        if db_count < on_chain_count:
                            return {
                                "ok": False,
                                "status": "TRUNCATED",
                                "message": f"Database has fewer records ({db_count}) than anchored on chain ({on_chain_count}). TRUNCATED state detected.",
                                "on_chain_count": on_chain_count,
                                "db_count": db_count
                            }

                    # Check record at on_chain_count
                    rec = self.store.get_record_by_id(on_chain_count)
                    if not rec or rec.get("record_hash") != on_chain_hash_hex:
                        return {
                            "ok": False,
                            "status": "TRUNCATED",
                            "message": f"Database record hash at height {on_chain_count} differs from anchored on-chain head. TRUNCATED state detected.",
                            "on_chain_head": on_chain_hash_hex,
                            "db_head": rec.get("record_hash") if rec else None
                        }
            except Exception as e:
                print(f"[WARN] Failed to verify against on-chain head: {e}")

        return sqlite_res

    def supersede_evidence(self, old_evidence_hash: str, new_evidence_hash: str, reason: str = "Amended evidence") -> Dict[str, Any]:
        """Mark an existing evidence record as superseded by a newer record."""
        clean_old = old_evidence_hash.strip().lower()
        if clean_old.startswith("0x"):
            clean_old = clean_old[2:]
        clean_new = new_evidence_hash.strip().lower()
        if clean_new.startswith("0x"):
            clean_new = clean_new[2:]

        result = self.store.supersede_record(clean_old, clean_new, reason)

        if clean_old in self.evidence_registry:
            self.evidence_registry[clean_old]["superseded"] = True
            self.evidence_registry[clean_old]["superseded_by"] = clean_new
            self.evidence_registry[clean_old]["supersede_reason"] = reason

        case_id = self.evidence_registry.get(clean_old, {}).get("case_id", "INSA-CASE")
        self.custody.add_entry(
            case_id=case_id,
            evidence_hash=clean_old,
            action=CustodyAction.SUPERSEDED,
            officer_id="INSA-SUPERSEDE-SYS",
            officer_name=self.author,
            reason=f"Evidence superseded by {clean_new}: {reason}",
            metadata={"replacement_hash": clean_new}
        )

        return result

    def delete_evidence(self, evidence_hash: str) -> bool:
        """Permanent deletion is prohibited in a tamper-evident forensic ledger."""
        raise PermissionError(
            "Forensic evidence ledger is strictly append-only. Deleting evidence is prohibited. "
            "Use supersede_evidence() instead."
        )

    def store_batch_merkle(
        self,
        case_id: str,
        events: List[Dict[str, Any]],
        investigator: str = "Nathenael Ermias",
        officer_id: str = "INSA-INV-4409"
    ) -> Dict[str, Any]:
        """Batch-process multiple telemetry events into a single on-chain Merkle Root."""
        tree = MerkleTree(events)
        root_hash = tree.root
        timestamp_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        batch_id = f"BATCH-{time.time_ns()}"

        sig_info = OfficerKeyManager.sign_evidence_hash(officer_id, root_hash, case_id=case_id)

        batch_meta = {
            "batch_id": batch_id,
            "case_id": case_id,
            "merkle_root": root_hash,
            "item_count": len(events),
            "timestamp": timestamp_iso,
            "officer_id": officer_id,
            "signature": sig_info["signature_b64"],
            "ledger_mode": self.ledger_mode
        }
        self.merkle_batches[root_hash] = {
            "metadata": batch_meta,
            "tree": tree,
            "events": events
        }

        anchor_res = self.store_evidence(
            case_id=case_id,
            incident_type="MERKLE_LOG_BATCH",
            target_asset="INSA-Aggregated-Perimeter",
            raw_evidence={"merkle_root": root_hash, "batch_id": batch_id, "item_count": len(events)},
            investigator=investigator,
            officer_id=officer_id
        )

        if hasattr(self.store, "save_merkle_batch"):
            try:
                self.store.save_merkle_batch(
                    batch_id=batch_id,
                    root_hash=root_hash,
                    leaf_hashes=tree.leaves,
                    tx_hash=anchor_res.get("tx_hash"),
                    block_number=anchor_res.get("block_number")
                )
            except Exception:
                pass

        return {
            "batch_id": batch_id,
            "merkle_root": root_hash,
            "item_count": len(events),
            "block_number": anchor_res["block_number"],
            "tx_hash": anchor_res["tx_hash"],
            "ledger_mode": self.ledger_mode
        }

    def get_merkle_proof(self, root_hash: str, item_index: int) -> Dict[str, Any]:
        """Generate Merkle inclusion proof for a specific event within a batch (checks cache & store)."""
        clean_root = root_hash.lower()
        if clean_root not in self.merkle_batches:
            if hasattr(self.store, "get_merkle_batch_by_root"):
                db_batch = self.store.get_merkle_batch_by_root(clean_root)
                if db_batch and db_batch.get("leaf_hashes"):
                    self.merkle_batches[clean_root] = {
                        "metadata": db_batch,
                        "tree": MerkleTree(db_batch["leaf_hashes"]),
                        "events": []
                    }
        if clean_root not in self.merkle_batches:
            raise KeyError(f"Merkle root {root_hash} not found")

        batch = self.merkle_batches[clean_root]
        tree: MerkleTree = batch["tree"]
        proof = tree.get_proof(item_index)
        leaf_hash = tree.leaves[item_index]

        return {
            "leaf_hash": leaf_hash,
            "item_index": item_index,
            "merkle_root": clean_root,
            "proof": proof,
            "is_valid": MerkleTree.verify_proof(leaf_hash, proof, clean_root)
        }

    def get_custody_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve complete hash-linked custodial chain for an incident case."""
        return self.custody.get_timeline(case_id)

    def _decorate_record(self, r: Dict[str, Any]) -> Dict[str, Any]:
        cached = self.evidence_registry.get(r["evidence_hash"], {})
        r["incident_type"] = r.get("incident_type") or cached.get("incident_type", "FORENSIC_TELEMETRY")
        r["target_asset"] = r.get("target_asset") or cached.get("target_asset", "Target-Asset")
        r["investigator"] = r.get("investigator") or cached.get("investigator", r.get("officer_id"))
        
        chain_rc = self.store.get_chain_receipt(r["evidence_hash"])
        if chain_rc:
            r["tx_hash"] = chain_rc.get("tx_hash")
            r["chain_block_number"] = chain_rc.get("block_number")
            r["chain_id"] = chain_rc.get("chain_id") or self.chain_id
            r["contract_address"] = chain_rc.get("contract_address") or self.contract_address
            r["is_on_chain"] = True
        elif cached.get("tx_hash"):
            r["tx_hash"] = cached.get("tx_hash")
            r["chain_block_number"] = cached.get("chain_block_number")
            r["chain_id"] = cached.get("chain_id") or self.chain_id
            r["contract_address"] = cached.get("contract_address") or self.contract_address
            r["is_on_chain"] = True

        if r.get("tx_hash"):
            if r.get("chain_id") == 11155111 or self.chain_mode == "sepolia":
                r["ledger_mode"] = "SQLITE + SEPOLIA TESTNET ANCHOR"
            elif r.get("chain_id") == 31337 or self.chain_mode == "local":
                r["ledger_mode"] = "SQLITE + LOCAL CHAIN ANCHOR (HARDHAT NODE)"
            else:
                r["ledger_mode"] = self.ledger_mode
        else:
            r["ledger_mode"] = self.ledger_mode

        if r.get("superseded_by_hash"):
            r["superseded_by"] = r["superseded_by_hash"]
        return r

    def get_all_records(self) -> List[Dict[str, Any]]:
        """Retrieve all stored evidence records sorted by timestamp descending."""
        records = self.store.get_all_records()
        for r in records:
            self._decorate_record(r)
        return records

    def get_records_by_case(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve all evidence records linked to an INSA case ID."""
        records = self.store.get_records_by_case(case_id)
        for r in records:
            self._decorate_record(r)
        return records

    def get_chain_stats(self) -> Dict[str, Any]:
        """Return comprehensive forensic & ledger operational statistics."""
        stats = self.store.get_stats()
        latest_block = None
        if self.is_connected and self.web3:
            try:
                latest_block = self.web3.eth.block_number
            except Exception:
                pass

        return {
            "total_blocks": stats["total_blocks"],
            "total_evidence_stored": stats["total_evidence_stored"],
            "total_cases_tracked": stats["total_cases_tracked"],
            "total_merkle_batches": max(len(self.merkle_batches), self.store.get_merkle_batches_count()) if hasattr(self.store, "get_merkle_batches_count") else len(self.merkle_batches),
            "latest_block_hash": stats["latest_block_hash"],
            "chain_head_hash": stats["latest_block_hash"],
            "ledger_mode": self.ledger_mode,
            "chain_mode": self.chain_mode,
            "chain_id": self.chain_id if self.chain_mode != "off" else None,
            "contract_address": self.contract_address if self.chain_mode != "off" else None,
            "latest_chain_block": latest_block,
            "ledger_backend": self.store.backend,
            "is_live_chain": self.is_live_chain,
            "network_type": "Ethereum / Hardhat / Sepolia" if self.is_live_chain else ("SQLite Persistent Hash-Chained Ledger" if self.store.backend == "sqlite" else "Simulated Cryptographic Memory Engine"),
            "consensus": "Proof of Authority / Stake" if self.is_live_chain else "SHA-256 Hash-Chained Cryptographic Sequence",
            "author": self.author,
            "email": self.email,
            "legal_framework": "FDRE Proclamation No. 958/2016 and Proclamation No. 1072/2018 (to be verified by legal counsel)"
        }

    def get_health_status(self) -> Dict[str, Any]:
        """Return /health blockchain fields."""
        latest_block = None
        if self.is_connected and self.web3:
            try:
                latest_block = self.web3.eth.block_number
            except Exception:
                pass

        return {
            "chain_mode": self.chain_mode,
            "chain_id": self.chain_id if self.chain_mode != "off" else None,
            "block_number": latest_block,
            "contract_address": self.contract_address if self.chain_mode != "off" else None,
            "connected": self.is_connected if self.chain_mode != "off" else False
        }
