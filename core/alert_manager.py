"""Alert deduplication and management for RAPTOR EDR."""
import hashlib
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# In-memory dedup cache: hash → last_seen
_dedup_cache: dict = {}
_DEDUP_WINDOW_SECONDS = 300  # 5 minutes


def dedup_key(alert: dict) -> str:
    """Generate deduplication key from alert."""
    raw = f"{alert.get('endpoint_id')}:{alert.get('rule_id')}:{alert.get('title')}"
    return hashlib.md5(raw.encode()).hexdigest()


def is_duplicate(alert: dict) -> bool:
    """Return True if an identical alert was seen within the dedup window."""
    key = dedup_key(alert)
    now = datetime.utcnow()
    if key in _dedup_cache:
        last = _dedup_cache[key]
        if (now - last).total_seconds() < _DEDUP_WINDOW_SECONDS:
            return True
    _dedup_cache[key] = now
    return False


def enrich_alert(alert: dict, endpoint: dict) -> dict:
    """Add endpoint context to alert."""
    alert["endpoint_hostname"] = endpoint.get("hostname", "unknown")
    alert["endpoint_ip"] = endpoint.get("ip_address", "")
    alert["endpoint_os"] = endpoint.get("os_type", "")
    return alert


def severity_to_int(severity: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity.upper(), 0)
