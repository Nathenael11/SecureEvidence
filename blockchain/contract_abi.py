# -*- coding: utf-8 -*-
"""
Auto-generated EvidenceTracker Contract ABI.
Loads the canonical ABI from EvidenceTracker_abi.json.
"""

import os
import json

_ABI_FILE = os.path.join(os.path.dirname(__file__), "EvidenceTracker_abi.json")
if os.path.exists(_ABI_FILE):
    with open(_ABI_FILE, "r", encoding="utf-8") as _f:
        EVIDENCE_TRACKER_ABI = json.load(_f)
else:
    EVIDENCE_TRACKER_ABI = []
