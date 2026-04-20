"""Tests for RAPTOR EDR rule engine and threat classifier"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.rule_engine import RuleEngine
from core.threat_classifier import classify_event, _cmdline_entropy
from core.alert_manager import dedup_key, is_duplicate
from core.response_actions import execute_response

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


def test_rule_engine_loads():
    engine = RuleEngine(RULES_DIR)
    assert engine.rule_count > 0


def test_rule_detects_mimikatz():
    engine = RuleEngine(RULES_DIR)
    event = {"process_name": "cmd.exe", "cmdline": "sekurlsa::logonpasswords", "file_path": "", "network_dst_port": None}
    matches = engine.evaluate(event)
    assert len(matches) > 0
    assert any("mimikatz" in m["rule_name"].lower() or "credential" in m["rule_name"].lower() or "sekurlsa" in m["description"].lower() for m in matches)


def test_rule_detects_schtasks():
    engine = RuleEngine(RULES_DIR)
    event = {"process_name": "schtasks.exe", "cmdline": "/create /tn backdoor /tr cmd.exe", "file_path": "", "network_dst_port": None}
    matches = engine.evaluate(event)
    assert any("schedule" in m["rule_name"].lower() or "task" in m["rule_name"].lower() for m in matches)


def test_rule_no_match_benign():
    engine = RuleEngine(RULES_DIR)
    event = {"process_name": "notepad.exe", "cmdline": "notepad.exe C:\\doc.txt", "file_path": "C:\\doc.txt", "network_dst_port": None}
    matches = engine.evaluate(event)
    assert len(matches) == 0


def test_classify_malicious():
    result = classify_event({
        "process_name": "mimikatz.exe",
        "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "file_path": "",
        "username": "root",
        "network_dst_port": None,
    })
    assert result["label"] == "malicious"
    assert result["score"] >= 0.7


def test_classify_benign():
    result = classify_event({
        "process_name": "notepad.exe",
        "cmdline": "notepad.exe readme.txt",
        "file_path": "C:\\readme.txt",
        "username": "user",
        "network_dst_port": None,
    })
    assert result["label"] == "benign"


def test_classify_suspicious_port():
    result = classify_event({
        "process_name": "powershell.exe",
        "cmdline": "powershell -c New-Object Net.Sockets.TCPClient",
        "file_path": "",
        "username": "user",
        "network_dst_port": 4444,
    })
    assert result["label"] in ("suspicious", "malicious")


def test_cmdline_entropy():
    assert _cmdline_entropy("") == 0.0
    assert _cmdline_entropy("aaaa") == 0.0
    assert _cmdline_entropy("abcdefgh") > 2.0


def test_response_action_valid():
    result = execute_response("isolate_endpoint", "192.168.1.10", "alert-123")
    assert result["status"] == "SUCCESS"
    assert "simulated" in result["message"].lower()


def test_response_action_invalid():
    result = execute_response("launch_missile", "192.168.1.10", "alert-123")
    assert result["status"] == "FAILED"
