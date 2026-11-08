"""
SecureEvidence: Application Configuration
Author: Nathenael Ermias nathenaelermias13@gmail.com
Design: Prototype with production-oriented design (INSA)
"""

import os
import sys
from pydantic_settings import BaseSettings
from pydantic import ConfigDict

AUTHOR_EMAIL: str = os.getenv("AUTHOR_EMAIL", "nathenaelermias13@gmail.com")
DEMO_MODE: bool = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")
FEATURE_COVERAGE_THRESHOLD: float = float(os.getenv("FEATURE_COVERAGE_THRESHOLD", "0.60"))

# Blockchain auto-detection and defaults
_raw_rpc: str = os.getenv("CHAIN_RPC_URL") or os.getenv("RPC_URL") or "http://127.0.0.1:8545"
_raw_chain_mode: str = (os.getenv("CHAIN_MODE") or "").strip().lower()
_is_sepolia: bool = (
    _raw_chain_mode == "sepolia"
    or os.getenv("CHAIN_ID") == "11155111"
    or any(x in _raw_rpc.lower() for x in ("sepolia", "alchemy.com", "infura.io", "quicknode"))
)
_effective_chain_mode: str = "sepolia" if _is_sepolia else ("local" if _raw_chain_mode == "local" else "off")
_default_chain_id: int = 11155111 if _effective_chain_mode == "sepolia" else 31337
_default_contract: str = (
    "0x2cD0b41b4F77d2BA99aD4c656dfC3c12e6712F4B"
    if _effective_chain_mode == "sepolia"
    else "0x5FbDB2315678afecb367f032d93F642f64180aa3"
)
_default_explorer: str = "https://sepolia.etherscan.io" if _effective_chain_mode == "sepolia" else ""

class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "SecureEvidence"
    APP_VERSION: str = "1.2.0"
    AUTHOR_NAME: str = "Nathenael Ermias"
    AUTHOR_EMAIL: str = AUTHOR_EMAIL
    DEMO_MODE: bool = DEMO_MODE
    FEATURE_COVERAGE_THRESHOLD: float = FEATURE_COVERAGE_THRESHOLD
    AGENCY_NAME: str = "Information Network Security Administration (INSA)"
    JURISDICTION: str = "Federal Democratic Republic of Ethiopia"
    PUBLIC_BASE_URL: str = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000")
    
    # AI Engine Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    MODELS_DIR: str = os.path.join(BASE_DIR, "ai_engine", "models")
    
    # Blockchain Settings
    RPC_URL: str = _raw_rpc
    CONTRACT_ADDRESS: str = os.getenv("CONTRACT_ADDRESS", _default_contract)
    CHAIN_MODE: str = os.getenv("CHAIN_MODE", _effective_chain_mode).lower()
    CHAIN_RPC_URL: str = os.getenv("CHAIN_RPC_URL", _raw_rpc)
    CHAIN_ID: int = int(os.getenv("CHAIN_ID", str(_default_chain_id)))
    SUBMITTER_PRIVATE_KEY: str = os.getenv("SUBMITTER_PRIVATE_KEY", "")
    EXPLORER_BASE_URL: str = os.getenv("EXPLORER_BASE_URL", _default_explorer)
    CONFIRMATIONS: int = int(os.getenv("CONFIRMATIONS", "1" if _effective_chain_mode == "local" else "2"))
    HEAD_ANCHOR_EVERY: int = int(os.getenv("HEAD_ANCHOR_EVERY", "10"))
    
    # Security & JWT Settings
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 15
    AUDIT_LOG_FILE: str = os.path.join(BASE_DIR, "audit_trail.jsonl")
    USER_DB_PATH: str = os.getenv("USER_DB_PATH", os.path.join(BASE_DIR, "users.db"))

    # Ledger Store Settings
    LEDGER_BACKEND: str = os.getenv("LEDGER_BACKEND", "sqlite").lower()
    LEDGER_DB_PATH: str = os.getenv("LEDGER_DB_PATH", os.path.join(BASE_DIR, "data", "ledger.db"))

    # Stream Pipeline Settings
    STREAM_API_URL: str = os.getenv("STREAM_API_URL", "http://127.0.0.1:8100")
    STREAM_WSL_DISTRO: str = os.getenv("STREAM_WSL_DISTRO", "Ubuntu-22.04")
    STREAM_WSL_START_SCRIPT: str = os.getenv("STREAM_WSL_START_SCRIPT", os.path.join(BASE_DIR, "scripts", "wsl", "start_stream_api.sh"))
    STREAM_WSL_START_SPARK_SCRIPT: str = os.getenv("STREAM_WSL_START_SPARK_SCRIPT", os.path.join(BASE_DIR, "scripts", "wsl", "start_spark_job.sh"))
    STREAM_WSL_STOP_SPARK_SCRIPT: str = os.getenv("STREAM_WSL_STOP_SPARK_SCRIPT", os.path.join(BASE_DIR, "scripts", "wsl", "stop_spark_job.sh"))

    @staticmethod
    def to_wsl_path(win_path: str) -> str:
        """Convert a Windows file path to a WSL /mnt/<drive>/... path."""
        drive, path = os.path.splitdrive(os.path.abspath(win_path))
        if drive:
            drive_letter = drive[0].lower()
            rel = path.replace("\\", "/").lstrip("/")
            return f"/mnt/{drive_letter}/{rel}"
        return win_path.replace("\\", "/")

    # API Settings
    API_PREFIX: str = "/api/v1"
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "8000"))

settings = Settings()

# Ensure ledger data directory exists when using SQLite
if settings.LEDGER_BACKEND == "sqlite" and settings.LEDGER_DB_PATH != ":memory:":
    os.makedirs(os.path.dirname(os.path.abspath(settings.LEDGER_DB_PATH)), exist_ok=True)

# Startup assertion: Refuse to start without JWT_SECRET when DEMO_MODE is false
if not settings.DEMO_MODE and not settings.JWT_SECRET:
    raise RuntimeError("CRITICAL CONFIGURATION ERROR: JWT_SECRET environment variable is strictly required when DEMO_MODE is false.")
