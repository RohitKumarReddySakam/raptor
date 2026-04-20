"""
Event processing pipeline for RAPTOR EDR.
Ingests endpoint telemetry, runs rules + classifier, emits alerts.
"""
import logging
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

_rule_engine = None
_classifier_fn = None


def init_processor(rules_dir: str):
    global _rule_engine, _classifier_fn
    from core.rule_engine import RuleEngine
    from core.threat_classifier import classify_event
    _rule_engine = RuleEngine(rules_dir)
    _classifier_fn = classify_event
    logger.info(f"Event processor initialized with {_rule_engine.rule_count} rules")


def process_event(event: dict) -> list:
    """
    Process a single endpoint event.
    Returns list of alert dicts (may be empty).
    """
    alerts = []

    # 1. Rule-based detection
    if _rule_engine:
        matches = _rule_engine.evaluate(event)
        for match in matches:
            alerts.append({
                "id": str(uuid.uuid4()),
                "endpoint_id": event.get("endpoint_id"),
                "event_id": event.get("id"),
                "rule_id": match["rule_id"],
                "rule_name": match["rule_name"],
                "severity": match["severity"],
                "title": match["rule_name"],
                "description": match["description"],
                "mitre_tactic": match["mitre_tactic"],
                "mitre_technique": match["mitre_technique"],
                "detection_method": "rule",
                "created_at": datetime.utcnow().isoformat(),
            })

    # 2. ML/heuristic classification
    if _classifier_fn:
        result = _classifier_fn(event)
        if result["label"] in ("suspicious", "malicious") and not alerts:
            severity = "HIGH" if result["label"] == "malicious" else "MEDIUM"
            alerts.append({
                "id": str(uuid.uuid4()),
                "endpoint_id": event.get("endpoint_id"),
                "event_id": event.get("id"),
                "rule_id": "ML-001",
                "rule_name": "ML Anomaly Detection",
                "severity": severity,
                "title": f"Suspicious activity: {event.get('process_name', 'unknown')}",
                "description": f"ML classifier score {result['score']}: {'; '.join(result['reasons'])}",
                "mitre_tactic": "Unknown",
                "mitre_technique": "Unknown",
                "detection_method": "ml",
                "created_at": datetime.utcnow().isoformat(),
            })

    return alerts


def normalize_event(raw: dict) -> dict:
    """Normalize incoming event telemetry to standard format."""
    return {
        "id": raw.get("id", str(uuid.uuid4())),
        "endpoint_id": raw.get("endpoint_id", ""),
        "event_type": raw.get("event_type", "process"),
        "process_name": str(raw.get("process_name", "") or "").lower(),
        "process_pid": raw.get("process_pid"),
        "parent_process": raw.get("parent_process", ""),
        "cmdline": raw.get("cmdline", ""),
        "file_path": raw.get("file_path", ""),
        "network_dst_ip": raw.get("network_dst_ip", ""),
        "network_dst_port": raw.get("network_dst_port"),
        "username": str(raw.get("username", "") or "").lower(),
        "severity": raw.get("severity", "LOW"),
        "raw_data": raw,
        "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
    }
