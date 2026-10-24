# -*- coding: utf-8 -*-
"""
SecureEvidence: Merkle Tree Batch Engine
Author: Nathenael Ermias
Design: Prototype with production-oriented design (INSA)

Implements cryptographic Merkle Trees for high-volume network telemetry batching.
Uses RFC 6962 domain separation:
  - leaf = SHA256(0x00 || data)
  - node = SHA256(0x01 || left || right)
Odd-leaf rule: Promotes the odd leaf/node directly to the next level without duplication
to prevent duplicate-leaf forgery vulnerabilities (e.g. CVE-2012-2459 style ambiguity).
"""

import hashlib
import json
from typing import List, Dict, Any, Tuple, Optional

class MerkleTree:
    """Cryptographic Merkle Tree with domain separation and odd-node promotion."""

    LEAF_PREFIX = b"\x00"
    NODE_PREFIX = b"\x01"

    def __init__(self, items: Optional[List[Any]] = None):
        self.raw_items: List[Any] = items or []
        self.leaves: List[str] = []
        self.levels: List[List[str]] = []
        if items:
            self.build_tree(items)

    @classmethod
    def hash_leaf(cls, item: Any) -> str:
        """
        Compute domain-separated leaf hash: SHA-256(0x00 || serialized_data).
        Guarantees that a leaf hash cannot collide with an internal node hash.
        """
        if isinstance(item, bytes):
            data = item
        elif isinstance(item, str):
            data = item.encode('utf-8')
        elif isinstance(item, dict):
            canonical = json.dumps(item, sort_keys=True, separators=(',', ':'))
            data = canonical.encode('utf-8')
        else:
            data = str(item).encode('utf-8')
        return hashlib.sha256(cls.LEAF_PREFIX + data).hexdigest()

    @classmethod
    def hash_node(cls, left_hex: str, right_hex: str) -> str:
        """
        Compute domain-separated internal node hash: SHA-256(0x01 || left_bytes || right_bytes).
        """
        left_bytes = bytes.fromhex(left_hex)
        right_bytes = bytes.fromhex(right_hex)
        return hashlib.sha256(cls.NODE_PREFIX + left_bytes + right_bytes).hexdigest()

    # Backwards compatibility alias
    @classmethod
    def hash_item(cls, item: Any) -> str:
        return cls.hash_leaf(item)

    @classmethod
    def hash_pair(cls, left: str, right: str) -> str:
        return cls.hash_node(left, right)

    def build_tree(self, items: List[Any]):
        """
        Construct Merkle tree levels.
        When a level has an odd number of elements, the last node is PROMOTED directly
        to the next level (not duplicated).
        """
        self.raw_items = items
        if not items:
            self.leaves = []
            self.levels = [[]]
            return

        self.leaves = [self.hash_leaf(item) for item in items]
        current_level = list(self.leaves)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            i = 0
            while i < len(current_level):
                if i + 1 < len(current_level):
                    next_level.append(self.hash_node(current_level[i], current_level[i + 1]))
                    i += 2
                else:
                    # Promote lone odd node to next level
                    next_level.append(current_level[i])
                    i += 1
            current_level = next_level
            self.levels.append(current_level)

    @property
    def root(self) -> str:
        """Return the 32-byte Merkle root hash (or 64 zero hex if empty)."""
        if not self.levels or not self.levels[-1]:
            return "0" * 64
        return self.levels[-1][0]

    def get_proof(self, index: int) -> List[Dict[str, str]]:
        """
        Generate audit proof for leaf at `index`.
        If a node is promoted (no sibling at that level), no proof step is added for that step.
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds")

        proof = []
        idx = index
        for level in self.levels[:-1]:
            is_right_child = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right_child else idx + 1

            if sibling_idx < len(level):
                proof.append({
                    "sibling_hash": level[sibling_idx],
                    "position": "left" if is_right_child else "right"
                })
            # If lone odd node was promoted, it has no sibling at this level
            idx = idx // 2

        return proof

    @classmethod
    def verify_proof(cls, leaf_hash: str, proof: List[Dict[str, str]], root_hash: str) -> bool:
        """
        Verify that `leaf_hash` belongs to the tree with `root_hash` using the proof.
        """
        current_hash = leaf_hash.lower()
        for step in proof:
            sibling = step["sibling_hash"].lower()
            if step["position"] == "left":
                current_hash = cls.hash_node(sibling, current_hash)
            elif step["position"] == "right":
                current_hash = cls.hash_node(current_hash, sibling)
            else:
                return False
        return current_hash.lower() == root_hash.lower()
