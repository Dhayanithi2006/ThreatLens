"""
ThreatLens Collector - Reverse Proxy & Deployment Configuration Validation
Tests that Caddy and NGINX configs enforce:
  - HTTPS / TLS termination on port 443
  - Strict payload size limits (4MB)
  - Upstream routing exclusively to FastAPI (127.0.0.1:8000)
  - Strict isolation: Kafka (9092) and Neo4j (7474, 7687) are never exposed to remote endpoints
"""

import re
from pathlib import Path
import pytest


REPO_ROOT = Path(__file__).parent.parent
CADDYFILE = REPO_ROOT / "deploy" / "Caddyfile"
NGINX_CONF = REPO_ROOT / "deploy" / "nginx.conf"


def test_caddyfile_structure_and_security_controls():
    assert CADDYFILE.exists(), f"Missing Caddyfile at {CADDYFILE}"
    content = CADDYFILE.read_text(encoding="utf-8")

    # 1. Port 443 HTTPS binding
    assert ":443" in content or "443" in content, "Caddyfile must bind to port 443"

    # 2. TLS enabled
    assert "tls internal" in content or "tls " in content, "Caddyfile must specify TLS configuration"

    # 3. Payload size limit matches backend 4MB limit
    assert "max_size 4MB" in content, "Caddyfile must enforce 4MB max request body"

    # 4. Reverse proxy to FastAPI
    assert "reverse_proxy 127.0.0.1:8000" in content, "Caddyfile must proxy to 127.0.0.1:8000"

    # 5. Security headers
    assert "Strict-Transport-Security" in content, "HSTS must be enabled"
    assert "X-Content-Type-Options" in content, "nosniff header must be present"

    # 6. Kafka & Neo4j isolation
    assert "9092" not in content, "Kafka port 9092 must NOT be proxied in Caddyfile"
    assert "7474" not in content, "Neo4j HTTP port 7474 must NOT be proxied in Caddyfile"
    assert "7687" not in content, "Neo4j Bolt port 7687 must NOT be proxied in Caddyfile"


def test_nginx_conf_structure_and_security_controls():
    assert NGINX_CONF.exists(), f"Missing nginx.conf at {NGINX_CONF}"
    content = NGINX_CONF.read_text(encoding="utf-8")

    # 1. Port 443 HTTPS binding
    assert "listen 443" in content, "NGINX must listen on port 443 with SSL"

    # 2. HTTP to HTTPS redirect
    assert "return 301 https://" in content, "NGINX must enforce HTTP to HTTPS redirect"

    # 3. Request body size restriction
    assert "client_max_body_size 4M;" in content, "NGINX must enforce 4M client body size"

    # 4. Rate limiting zone for collector ingestion
    assert "limit_req_zone" in content, "NGINX must define rate limiting zone"
    assert "limit_req zone=collector_ingest" in content, "Collector route must apply rate limiting"

    # 5. Reverse proxy upstream routing
    assert "proxy_pass http://127.0.0.1:8000;" in content, "NGINX must forward to 127.0.0.1:8000"

    # 6. Hardened headers
    assert "Strict-Transport-Security" in content, "HSTS must be present"
    assert "X-Content-Type-Options" in content, "nosniff header must be present"

    # 7. Kafka & Neo4j isolation
    assert "9092" not in content, "Kafka port 9092 must NOT be exposed in NGINX"
    assert "7474" not in content, "Neo4j HTTP port 7474 must NOT be exposed in NGINX"
    assert "7687" not in content, "Neo4j Bolt port 7687 must NOT be exposed in NGINX"

