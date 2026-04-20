"""
YAML-based detection rule engine for RAPTOR EDR.
Loads rules from YAML files and evaluates events against them.
"""
import os
import re
import logging
import yaml

logger = logging.getLogger(__name__)


class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules = []
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str):
        if not os.path.isdir(rules_dir):
            logger.warning(f"Rules directory not found: {rules_dir}")
            return
        for filename in sorted(os.listdir(rules_dir)):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                path = os.path.join(rules_dir, filename)
                try:
                    with open(path) as f:
                        data = yaml.safe_load(f)
                    rules = data.get("rules", [])
                    self.rules.extend(rules)
                    logger.info(f"Loaded {len(rules)} rules from {filename}")
                except Exception as e:
                    logger.error(f"Failed to load {filename}: {e}")
        logger.info(f"Total rules loaded: {len(self.rules)}")

    def evaluate(self, event: dict) -> list:
        """
        Evaluate an event against all rules.
        Returns list of matching rule dicts with match metadata.
        """
        matches = []
        for rule in self.rules:
            if self._rule_matches(rule, event):
                matches.append({
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "severity": rule.get("severity", "MEDIUM"),
                    "mitre_tactic": rule.get("mitre_tactic", ""),
                    "mitre_technique": rule.get("mitre_technique", ""),
                    "description": rule.get("description", ""),
                })
        return matches

    def _rule_matches(self, rule: dict, event: dict) -> bool:
        conditions = rule.get("conditions", {})
        if not conditions:
            return False

        for field, value in conditions.items():
            if not self._check_condition(field, value, event):
                return False
        return True

    def _check_condition(self, field: str, value, event: dict) -> bool:
        event_value = str(event.get(self._field_map(field), "") or "").lower()

        if isinstance(value, list):
            if field.endswith("_contains"):
                return any(str(v).lower() in event_value for v in value)
            # For process_name, network_dst_port: check membership
            return any(str(v).lower() == event_value for v in value)

        if isinstance(value, (int, float)):
            try:
                return int(event.get(self._field_map(field), -1)) == int(value)
            except (ValueError, TypeError):
                return False

        str_val = str(value).lower()
        if field.endswith("_contains"):
            return str_val in event_value
        return str_val == event_value

    def _field_map(self, field: str) -> str:
        # Map rule condition field names to event dict keys
        mapping = {
            "process_name": "process_name",
            "cmdline_contains": "cmdline",
            "file_path_contains": "file_path",
            "network_dst_port": "network_dst_port",
            "username": "username",
        }
        return mapping.get(field, field)

    @property
    def rule_count(self) -> int:
        return len(self.rules)
