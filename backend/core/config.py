"""
ThreatLens - Configuration & Settings
Enterprise Email Threat Investigation, Forensics, IOC Extraction, Threat Intelligence & Campaign Analysis
"""

import os
import pathlib
from typing import Dict
from dotenv import load_dotenv

# Load local environment variables from .env if present
load_dotenv()

# Static frontend directory (served by FastAPI StaticFiles)
STATIC_DIR: str = str(pathlib.Path(__file__).parent.parent.parent / "frontend")

# Scoring weights for threat signals (Feature 1)
DEFAULT_SIGNAL_WEIGHTS: Dict[str, int] = {
    # Security Signals
    "suspicious_url": 20,
    "suspicious_domain": 15,
    "suspicious_attachment": 20,
    "suspicious_external_ip": 10,
    "spf_failure": 10,
    "dkim_failure": 10,
    "dmarc_failure": 15,
    
    # Content & NLP Signals
    "credential_request": 15,
    "urgent_language": 10,
    "threat_language": 10,
    "account_suspension": 15,
    "otp_request": 15,
    "payment_financial_request": 20,
    "invoice_language": 10,
    "verify_account": 15,
    "suspicious_cta": 10,
    
    # Identity & Sender Signals
    "reply_to_mismatch": 15,
    "return_path_mismatch": 10,
    "display_name_mismatch": 15,
    "suspicious_sender_domain": 15,
    "impersonation_indicator": 20,
    "bec_indicator": 20,
}

# Risk level boundaries
RISK_THRESHOLDS = {
    "LOW": (0, 19),
    "MEDIUM": (20, 39),
    "HIGH": (40, 69),
    "CRITICAL": (70, 100),
}

# Threat Intelligence Configuration (Feature 5)
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

# Mode: "auto" (uses real if API key exists, else mock), "real" (requires keys), "mock" (always mock)
THREAT_INTEL_MODE: str = os.getenv("THREAT_INTEL_MODE", "auto")

# Safety & Rate-limiting controls
MAX_INTEL_LOOKUPS_PER_TYPE: int = int(os.getenv("MAX_INTEL_LOOKUPS_PER_TYPE", "5"))
INTEL_REQUEST_TIMEOUT_SECONDS: float = float(os.getenv("INTEL_REQUEST_TIMEOUT_SECONDS", "8.0"))
INTEL_CACHE_TTL_SECONDS: int = int(os.getenv("INTEL_CACHE_TTL_SECONDS", "3600"))

# App metadata
APP_NAME = "ThreatLens"
APP_VERSION = "2.0.0"
API_PREFIX = "/api/v1"

# ==========================================================
# GraphOps & Neo4j Configuration
# ==========================================================
NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "threatlens_password")
NEO4J_DATABASE: str = os.getenv("NEO4J_DATABASE", "neo4j")
NEO4J_CONNECTION_TIMEOUT_SECONDS: float = float(os.getenv("NEO4J_CONNECTION_TIMEOUT_SECONDS", "5.0"))
NEO4J_MAX_CONNECTION_LIFETIME_SECONDS: float = float(os.getenv("NEO4J_MAX_CONNECTION_LIFETIME_SECONDS", "3600.0"))
NEO4J_MAX_CONNECTION_POOL_SIZE: int = int(os.getenv("NEO4J_MAX_CONNECTION_POOL_SIZE", "50"))

# ==========================================================
# GraphOps Apache Kafka Event Streaming Configuration
# ==========================================================
KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_CLIENT_ID: str = os.getenv("KAFKA_CLIENT_ID", "threatlens-graphops")
KAFKA_CONSUMER_GROUP: str = os.getenv("KAFKA_CONSUMER_GROUP", "threatlens-graphops-workers")
KAFKA_AUTO_OFFSET_RESET: str = os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest")
KAFKA_ENABLE_AUTO_COMMIT: bool = os.getenv("KAFKA_ENABLE_AUTO_COMMIT", "false").lower() in ("true", "1", "yes")
KAFKA_POLL_TIMEOUT_SECONDS: float = float(os.getenv("KAFKA_POLL_TIMEOUT_SECONDS", "1.0"))
KAFKA_MAX_RETRIES: int = int(os.getenv("KAFKA_MAX_RETRIES", "3"))
KAFKA_RETRY_BACKOFF_SECONDS: float = float(os.getenv("KAFKA_RETRY_BACKOFF_SECONDS", "0.5"))
KAFKA_DLQ_ENABLED: bool = os.getenv("KAFKA_DLQ_ENABLED", "true").lower() in ("true", "1", "yes")

# Centralized Topic Configuration
KAFKA_TOPIC_ENDPOINT_EVENTS: str = os.getenv("KAFKA_TOPIC_ENDPOINT_EVENTS", "security.endpoint.events")
KAFKA_TOPIC_IDENTITY_EVENTS: str = os.getenv("KAFKA_TOPIC_IDENTITY_EVENTS", "security.identity.events")
KAFKA_TOPIC_NETWORK_EVENTS: str = os.getenv("KAFKA_TOPIC_NETWORK_EVENTS", "security.network.events")
KAFKA_TOPIC_EMAIL_EVENTS: str = os.getenv("KAFKA_TOPIC_EMAIL_EVENTS", "security.email.events")
KAFKA_TOPIC_FINDINGS: str = os.getenv("KAFKA_TOPIC_FINDINGS", "graphops.findings")
KAFKA_TOPIC_DLQ: str = os.getenv("KAFKA_TOPIC_DLQ", "graphops.events.dlq")

# ==========================================================
# Security, CORS & Governance Configuration
# ==========================================================
# Explicit, environment-appropriate allowed CORS origins (replaces wildcard with credentials)
DEFAULT_CORS_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
]
CORS_ORIGINS_RAW = os.getenv("CORS_ORIGINS", "")
CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()] if CORS_ORIGINS_RAW else DEFAULT_CORS_ORIGINS

# Administrative API Key Protection for Mutating & Governance Operations
ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY", "threatlens_dev_api_key")
REQUIRE_API_KEY: bool = os.getenv("REQUIRE_API_KEY", "false").lower() in ("true", "1", "yes")

# File Upload Security Boundaries
MAX_UPLOAD_SIZE_BYTES: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(10 * 1024 * 1024)))  # 10 MB limit
ALLOWED_UPLOAD_EXTENSIONS = (".eml", ".msg", ".txt")

# ==========================================================
# GraphOps scikit-learn Anomaly Detection Configuration
# ==========================================================
SKLEARN_MODEL_PATH: str = os.getenv("SKLEARN_MODEL_PATH", "backend/data/models/event_isolation_forest.joblib")
SKLEARN_META_PATH: str = os.getenv("SKLEARN_META_PATH", "backend/data/models/event_isolation_forest_meta.json")
SKLEARN_CONTAMINATION: float = float(os.getenv("SKLEARN_CONTAMINATION", "0.08"))
SKLEARN_RANDOM_SEED: int = int(os.getenv("SKLEARN_RANDOM_SEED", "42"))
SKLEARN_ANOMALY_THRESHOLD: float = float(os.getenv("SKLEARN_ANOMALY_THRESHOLD", "0.0"))

# ==========================================================
# GraphOps PyTorch Geometric (PyG) Graph Learning Configuration
# ==========================================================
PYG_MODEL_PATH: str = os.getenv("PYG_MODEL_PATH", "backend/data/models/pyg_structural_gnn.pt")
PYG_META_PATH: str = os.getenv("PYG_META_PATH", "backend/data/models/pyg_structural_gnn_meta.json")
PYG_EMBEDDING_DIM: int = int(os.getenv("PYG_EMBEDDING_DIM", "64"))
PYG_HIDDEN_DIM: int = int(os.getenv("PYG_HIDDEN_DIM", "64"))
PYG_ANOMALY_THRESHOLD: float = float(os.getenv("PYG_ANOMALY_THRESHOLD", "60.0"))
PYG_LEARNING_RATE: float = float(os.getenv("PYG_LEARNING_RATE", "0.01"))
PYG_NUM_EPOCHS: int = int(os.getenv("PYG_NUM_EPOCHS", "100"))
PYG_DEVICE: str = os.getenv("PYG_DEVICE", "cpu")
PYG_MAX_SUBGRAPH_HOPS: int = int(os.getenv("PYG_MAX_SUBGRAPH_HOPS", "2"))
PYG_MAX_SUBGRAPH_NODES: int = int(os.getenv("PYG_MAX_SUBGRAPH_NODES", "200"))

