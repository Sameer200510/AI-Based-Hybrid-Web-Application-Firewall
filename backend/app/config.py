import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    """Production and Research configuration for AMRSF Web Application Firewall."""
    SECRET_KEY = os.getenv("SECRET_KEY", "amrsf-research-grade-secret-key-2026")
    
    # Database Configuration: supports PostgreSQL via DATABASE_URL or SQLite fallback
    DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'waf_amrsf.db'}")
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # AMRSF Adaptive Layer Weights (sum = 1.0)
    WAF_WEIGHT_SIGNATURE = float(os.getenv("WAF_WEIGHT_SIGNATURE", "0.25"))
    WAF_WEIGHT_ENCODING = float(os.getenv("WAF_WEIGHT_ENCODING", "0.15"))
    WAF_WEIGHT_COMPLEXITY = float(os.getenv("WAF_WEIGHT_COMPLEXITY", "0.10"))
    WAF_WEIGHT_ML = float(os.getenv("WAF_WEIGHT_ML", "0.30"))
    WAF_WEIGHT_BEHAVIORAL = float(os.getenv("WAF_WEIGHT_BEHAVIORAL", "0.10"))
    WAF_WEIGHT_THREAT_INTEL = float(os.getenv("WAF_WEIGHT_THREAT_INTEL", "0.10"))

    # Decision Thresholds (0-100)
    THRESHOLD_ALLOW_MAX = int(os.getenv("THRESHOLD_ALLOW_MAX", "25"))
    THRESHOLD_MONITOR_MAX = int(os.getenv("THRESHOLD_MONITOR_MAX", "50"))
    THRESHOLD_CHALLENGE_MAX = int(os.getenv("THRESHOLD_CHALLENGE_MAX", "75"))
    # Above THRESHOLD_CHALLENGE_MAX (76-100) -> Block

    # Threat Intelligence API Keys (Optional integrations)
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ALIENVAULT_OTX_KEY = os.getenv("ALIENVAULT_OTX_KEY", "")

    # ML Model Artifacts path
    ML_MODEL_DIR = BASE_DIR / "app" / "waf_engine" / "model_artifacts"
