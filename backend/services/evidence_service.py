# -*- coding: utf-8 -*-
"""
SecureEvidence: Blockchain Evidence Management Service
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: Blockchain & Digital Forensics (INSA)
"""

from ..config import settings
from blockchain.web3_client import Web3EvidenceClient

class EvidenceService:
    _instance = None

    @classmethod
    def get_instance(cls) -> Web3EvidenceClient:
        if cls._instance is None:
            cls._instance = Web3EvidenceClient(
                rpc_url=settings.CHAIN_RPC_URL,
                contract_address=settings.CONTRACT_ADDRESS,
                chain_mode=settings.CHAIN_MODE,
                chain_id=settings.CHAIN_ID,
                submitter_private_key=settings.SUBMITTER_PRIVATE_KEY,
                explorer_base_url=settings.EXPLORER_BASE_URL,
                confirmations=settings.CONFIRMATIONS,
                head_anchor_every=settings.HEAD_ANCHOR_EVERY
            )
        return cls._instance

    @classmethod
    def reset_instance(cls):
        cls._instance = None
