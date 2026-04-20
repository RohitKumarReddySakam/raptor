"""
Simulated response actions for RAPTOR EDR.
All actions are recorded and simulated — no actual system changes.
"""
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

VALID_ACTIONS = {
    "isolate_endpoint": "Isolated endpoint from network (simulated)",
    "kill_process": "Terminated malicious process (simulated)",
    "block_ip": "Blocked outbound IP address (simulated)",
    "quarantine_file": "Quarantined malicious file (simulated)",
    "collect_forensics": "Collected forensic artifacts (simulated)",
    "unisolate_endpoint": "Restored endpoint network access (simulated)",
}


def execute_response(action_type: str, target: str, alert_id: str) -> dict:
    """
    Execute (simulate) a response action.
    Returns result dict with status and message.
    """
    if action_type not in VALID_ACTIONS:
        return {
            "status": "FAILED",
            "message": f"Unknown action: {action_type}",
            "executed_at": datetime.utcnow().isoformat(),
        }

    message = VALID_ACTIONS[action_type]
    logger.info(f"[RESPONSE] {action_type} on {target} for alert {alert_id}")

    return {
        "status": "SUCCESS",
        "action": action_type,
        "target": target,
        "message": f"{message}: {target}",
        "executed_at": datetime.utcnow().isoformat(),
        "alert_id": alert_id,
    }
