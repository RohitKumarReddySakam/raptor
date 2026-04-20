"""
RAPTOR EDR — Endpoint Detection & Response Platform
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 1.0.0

Defensive EDR platform for monitoring endpoint telemetry,
detecting threats via YAML rules and heuristics, and coordinating
response actions.
"""

from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime
import os
import json
import uuid
import threading
import time
import logging
import random
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
sio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Models ───────────────────────────────────────────────────────
class Endpoint(db.Model):
    __tablename__ = "endpoints"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = db.Column(db.String(200), nullable=False)
    os_type = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    agent_version = db.Column(db.String(20), default="1.0.0")
    status = db.Column(db.String(20), default="active")
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Float, default=0.0)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "hostname": self.hostname, "os_type": self.os_type,
            "ip_address": self.ip_address, "agent_version": self.agent_version,
            "status": self.status, "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "risk_score": self.risk_score,
        }


class EndpointEvent(db.Model):
    __tablename__ = "endpoint_events"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    endpoint_id = db.Column(db.String(36), db.ForeignKey("endpoints.id"))
    event_type = db.Column(db.String(50))
    process_name = db.Column(db.String(200))
    process_pid = db.Column(db.Integer)
    parent_process = db.Column(db.String(200))
    cmdline = db.Column(db.Text)
    file_path = db.Column(db.Text)
    network_dst_ip = db.Column(db.String(50))
    network_dst_port = db.Column(db.Integer)
    username = db.Column(db.String(100))
    severity = db.Column(db.String(20), default="LOW")
    raw_data = db.Column(db.Text, default="{}")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "endpoint_id": self.endpoint_id, "event_type": self.event_type,
            "process_name": self.process_name, "cmdline": self.cmdline,
            "file_path": self.file_path, "network_dst_ip": self.network_dst_ip,
            "network_dst_port": self.network_dst_port, "username": self.username,
            "severity": self.severity, "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class EDRAlert(db.Model):
    __tablename__ = "edr_alerts"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    endpoint_id = db.Column(db.String(36), db.ForeignKey("endpoints.id"))
    rule_id = db.Column(db.String(50))
    rule_name = db.Column(db.String(200))
    severity = db.Column(db.String(20))
    title = db.Column(db.String(300))
    description = db.Column(db.Text)
    mitre_tactic = db.Column(db.String(100))
    mitre_technique = db.Column(db.String(50))
    status = db.Column(db.String(30), default="new")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        ep = Endpoint.query.get(self.endpoint_id)
        return {
            "id": self.id, "endpoint_id": self.endpoint_id,
            "hostname": ep.hostname if ep else "unknown",
            "rule_id": self.rule_id, "rule_name": self.rule_name,
            "severity": self.severity, "title": self.title,
            "description": self.description, "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique, "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ResponseAction(db.Model):
    __tablename__ = "response_actions"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = db.Column(db.String(36))
    action_type = db.Column(db.String(100))
    target = db.Column(db.String(200))
    status = db.Column(db.String(30), default="PENDING")
    result = db.Column(db.Text)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "alert_id": self.alert_id, "action_type": self.action_type,
            "target": self.target, "status": self.status, "result": self.result,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
        }


# ─── Routes — Pages ───────────────────────────────────────────────
@app.route("/")
def dashboard():
    total_endpoints = Endpoint.query.count()
    active_endpoints = Endpoint.query.filter_by(status="active").count()
    open_alerts = EDRAlert.query.filter_by(status="new").count()
    critical_alerts = EDRAlert.query.filter_by(severity="CRITICAL").count()
    recent_alerts = EDRAlert.query.order_by(EDRAlert.created_at.desc()).limit(5).all()
    return render_template("index.html",
        total_endpoints=total_endpoints, active_endpoints=active_endpoints,
        open_alerts=open_alerts, critical_alerts=critical_alerts,
        recent_alerts=recent_alerts)


@app.route("/endpoints")
def endpoints_page():
    endpoints = Endpoint.query.order_by(Endpoint.last_seen.desc()).all()
    return render_template("endpoints.html", endpoints=endpoints)


@app.route("/endpoint/<ep_id>")
def endpoint_detail(ep_id):
    ep = Endpoint.query.get_or_404(ep_id)
    events = EndpointEvent.query.filter_by(endpoint_id=ep_id).order_by(EndpointEvent.timestamp.desc()).limit(50).all()
    alerts = EDRAlert.query.filter_by(endpoint_id=ep_id).order_by(EDRAlert.created_at.desc()).limit(20).all()
    return render_template("endpoint_detail.html", endpoint=ep, events=events, alerts=alerts)


@app.route("/alerts")
def alerts_page():
    alerts = EDRAlert.query.order_by(EDRAlert.created_at.desc()).all()
    return render_template("alerts.html", alerts=alerts)


# ─── Routes — API ─────────────────────────────────────────────────
@app.route("/api/endpoint/register", methods=["POST"])
def register_endpoint():
    data = request.get_json()
    if not data or not data.get("hostname"):
        return jsonify({"error": "hostname required"}), 400

    # Update existing or create new
    ep = Endpoint.query.filter_by(hostname=data["hostname"]).first()
    if ep:
        ep.ip_address = data.get("ip_address", ep.ip_address)
        ep.agent_version = data.get("agent_version", ep.agent_version)
        ep.status = "active"
        ep.last_seen = datetime.utcnow()
    else:
        ep = Endpoint(
            hostname=data["hostname"],
            os_type=data.get("os_type", "unknown"),
            ip_address=data.get("ip_address", ""),
            agent_version=data.get("agent_version", "1.0.0"),
        )
        db.session.add(ep)

    db.session.commit()
    return jsonify(ep.to_dict()), 201


@app.route("/api/event", methods=["POST"])
def ingest_event():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400

    from core.event_processor import process_event, normalize_event
    from core.alert_manager import is_duplicate, enrich_alert

    normalized = normalize_event(data)
    endpoint_id = normalized.get("endpoint_id")

    # Update endpoint last_seen
    if endpoint_id:
        ep = Endpoint.query.get(endpoint_id)
        if ep:
            ep.last_seen = datetime.utcnow()
            db.session.commit()

    # Store event
    event = EndpointEvent(
        id=normalized["id"],
        endpoint_id=endpoint_id,
        event_type=normalized["event_type"],
        process_name=normalized["process_name"],
        process_pid=normalized.get("process_pid"),
        parent_process=normalized.get("parent_process", ""),
        cmdline=normalized.get("cmdline", ""),
        file_path=normalized.get("file_path", ""),
        network_dst_ip=normalized.get("network_dst_ip", ""),
        network_dst_port=normalized.get("network_dst_port"),
        username=normalized.get("username", ""),
        raw_data=json.dumps(data),
    )
    db.session.add(event)
    db.session.commit()

    # Process for detections
    alert_dicts = process_event(normalized)
    created_alerts = []

    for alert_dict in alert_dicts:
        if is_duplicate(alert_dict):
            continue

        alert = EDRAlert(
            endpoint_id=endpoint_id,
            rule_id=alert_dict["rule_id"],
            rule_name=alert_dict["rule_name"],
            severity=alert_dict["severity"],
            title=alert_dict["title"],
            description=alert_dict["description"],
            mitre_tactic=alert_dict.get("mitre_tactic", ""),
            mitre_technique=alert_dict.get("mitre_technique", ""),
        )
        db.session.add(alert)
        db.session.commit()
        created_alerts.append(alert.to_dict())
        sio.emit("new_alert", alert.to_dict())
        logger.warning(f"[ALERT] {alert.severity}: {alert.title} on {endpoint_id}")

    return jsonify({"event_id": event.id, "alerts_created": len(created_alerts)}), 201


@app.route("/api/event/batch", methods=["POST"])
def ingest_batch():
    data = request.get_json()
    events = data.get("events", []) if data else []
    results = []
    for evt in events[:100]:  # Cap batch size
        with app.test_request_context(json=evt):
            # Process each event
            from core.event_processor import process_event, normalize_event
            normalized = normalize_event(evt)
            alerts = process_event(normalized)
            results.append({"event_id": normalized["id"], "alerts": len(alerts)})
    return jsonify({"processed": len(results)})


@app.route("/api/endpoints")
def get_endpoints():
    eps = Endpoint.query.order_by(Endpoint.last_seen.desc()).all()
    return jsonify({"endpoints": [e.to_dict() for e in eps]})


@app.route("/api/alerts")
def get_alerts():
    alerts = EDRAlert.query.order_by(EDRAlert.created_at.desc()).limit(100).all()
    return jsonify({"alerts": [a.to_dict() for a in alerts]})


@app.route("/api/alert/<alert_id>", methods=["PATCH"])
def update_alert(alert_id):
    alert = EDRAlert.query.get_or_404(alert_id)
    data = request.get_json()
    if "status" in data:
        alert.status = data["status"]
    db.session.commit()
    sio.emit("alert_updated", alert.to_dict())
    return jsonify(alert.to_dict())


@app.route("/api/response", methods=["POST"])
def execute_response():
    from core.response_actions import execute_response as do_response
    data = request.get_json()
    action_type = data.get("action_type")
    target = data.get("target", "")
    alert_id = data.get("alert_id", "")

    result = do_response(action_type, target, alert_id)

    action = ResponseAction(
        alert_id=alert_id,
        action_type=action_type,
        target=target,
        status=result["status"],
        result=result["message"],
    )
    db.session.add(action)
    db.session.commit()

    return jsonify(result)


@app.route("/api/metrics")
def get_metrics():
    return jsonify({
        "total_endpoints": Endpoint.query.count(),
        "active_endpoints": Endpoint.query.filter_by(status="active").count(),
        "isolated_endpoints": Endpoint.query.filter_by(status="isolated").count(),
        "total_alerts": EDRAlert.query.count(),
        "open_alerts": EDRAlert.query.filter_by(status="new").count(),
        "critical_alerts": EDRAlert.query.filter_by(severity="CRITICAL").count(),
        "high_alerts": EDRAlert.query.filter_by(severity="HIGH").count(),
        "resolved_alerts": EDRAlert.query.filter_by(status="resolved").count(),
        "total_events": EndpointEvent.query.count(),
        "response_actions": ResponseAction.query.count(),
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "1.0.0", "timestamp": datetime.utcnow().isoformat()})


@sio.on("connect")
def on_connect():
    logger.info("Client connected")


def _seed_demo_data():
    """Seed demo endpoints and events."""
    hostnames = ["WORKSTATION-001", "SERVER-WEB-01", "DB-SERVER-01", "LAPTOP-DEV-042", "DC-PRIMARY"]
    oses = ["Windows 11 Pro", "Ubuntu 22.04", "Windows Server 2022", "macOS 14", "Windows Server 2022"]

    for i, hostname in enumerate(hostnames):
        ep = Endpoint(
            hostname=hostname,
            os_type=oses[i],
            ip_address=f"192.168.1.{10+i}",
            status="active",
            risk_score=random.uniform(0, 60),
        )
        db.session.add(ep)
    db.session.commit()

    # Seed a few alerts
    eps = Endpoint.query.all()
    for ep in eps[:3]:
        for rule_name, sev, tactic in [
            ("Suspicious PowerShell", "HIGH", "Execution"),
            ("Registry Persistence", "MEDIUM", "Persistence"),
        ]:
            alert = EDRAlert(
                endpoint_id=ep.id,
                rule_id="DEMO-001",
                rule_name=rule_name,
                severity=sev,
                title=rule_name,
                description=f"Demo detection on {ep.hostname}",
                mitre_tactic=tactic,
                mitre_technique="T1059.001",
                status=random.choice(["new", "investigating", "resolved"]),
            )
            db.session.add(alert)
    db.session.commit()


def create_app():
    from core.event_processor import init_processor
    with app.app_context():
        db.create_all()
        if Endpoint.query.count() == 0:
            _seed_demo_data()
        init_processor(app.config["RULES_DIR"])
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5004))
    sio.run(app, host="0.0.0.0", port=port, debug=False)
