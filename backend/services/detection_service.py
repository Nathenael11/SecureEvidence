"""
SecureEvidence: AI Threat Detection Service
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: AI Engineering (INSA)
"""

import os
from ..config import settings
from ai_engine.detector import ThreatDetector

class DetectionService:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = ThreatDetector(models_dir=settings.MODELS_DIR)
        return cls._instance
