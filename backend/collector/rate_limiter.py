"""
ThreatLens Collector - Sliding-Window Rate Limiter

Provides per-collector request-rate enforcement based on a token-bucket
sliding-window approach stored in process memory.

Limits:
  - MAX_EVENTS_PER_BATCH: controlled by COLLECTOR_MAX_EVENTS_PER_BATCH
  - MAX_REQUESTS_PER_MINUTE: controlled by COLLECTOR_RATE_LIMIT_RPM
"""

import logging
import threading
import time
from collections import deque
from typing import Dict, Deque

from backend.core import config as _cfg

logger = logging.getLogger("threatlens.collector.rate_limiter")

_LOCK = threading.Lock()

# Deque of arrival timestamps per collector_id (sliding window)
_request_windows: Dict[str, Deque[float]] = {}


def _window_for(collector_id: str) -> Deque[float]:
    if collector_id not in _request_windows:
        _request_windows[collector_id] = deque()
    return _request_windows[collector_id]


def check_rate_limit(collector_id: str) -> bool:
    """
    Returns True if the request is within the allowed rate.
    Returns False if the collector has exceeded COLLECTOR_RATE_LIMIT_RPM.

    Thread-safe; uses a sliding 60-second window.
    """
    limit_rpm = _cfg.COLLECTOR_RATE_LIMIT_RPM
    window_sec = 60.0
    now = time.monotonic()

    with _LOCK:
        window = _window_for(collector_id)

        # Evict timestamps outside the 60s window
        cutoff = now - window_sec
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= limit_rpm:
            logger.warning(
                "Rate limit exceeded for collector %s (%d/%d requests in 60s)",
                collector_id, len(window), limit_rpm,
            )
            return False

        window.append(now)
        return True

