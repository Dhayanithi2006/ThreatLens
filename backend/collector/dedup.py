"""
ThreatLens Collector - Ingestion Deduplication Cache

In-memory LRU cache of recently accepted event IDs.
Prevents duplicate delivery from checkpoint races or network retries
from counting as new events before the durable Neo4j check completes.

The Neo4j processor (`kafka_processor.py`) performs the authoritative
durable dedup via MERGE — this layer is an optimistic fast-path guard.
"""

import logging
import threading
from collections import OrderedDict
from typing import Optional

from backend.core import config as _cfg

logger = logging.getLogger("threatlens.collector.dedup")

_LOCK = threading.Lock()
_MAX_SIZE = 50_000  # maximum cached event IDs

_cache: OrderedDict[str, bool] = OrderedDict()


def is_duplicate(event_id: str) -> bool:
    """Returns True if event_id was already seen recently."""
    with _LOCK:
        return event_id in _cache


def mark_seen(event_id: str) -> None:
    """Marks an event_id as seen. Evicts oldest entries when cache is full."""
    with _LOCK:
        if event_id in _cache:
            _cache.move_to_end(event_id)
            return
        _cache[event_id] = True
        if len(_cache) > _MAX_SIZE:
            _cache.popitem(last=False)

