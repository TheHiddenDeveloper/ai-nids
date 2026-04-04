"""
Signature Loader
----------------
Parses rules.yaml into a list of compiled Rule objects.
Each Rule.matches(flow) evaluates all conditions against a flow dict.

Supports operators: gt, lt, gte, lte, eq, neq, in, not_in, contains
"""

import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from loguru import logger


# ── Operator registry ─────────────────────────────────────────────────────────

OPS: Dict[str, Callable[[Any, Any], bool]] = {
    "gt":       lambda a, b: float(a) > float(b),
    "lt":       lambda a, b: float(a) < float(b),
    "gte":      lambda a, b: float(a) >= float(b),
    "lte":      lambda a, b: float(a) <= float(b),
    "eq":       lambda a, b: str(a) == str(b) if isinstance(b, str) else a == b,
    "neq":      lambda a, b: str(a) != str(b) if isinstance(b, str) else a != b,
    "in":       lambda a, b: a in b,
    "not_in":   lambda a, b: a not in b,
    "contains": lambda a, b: str(b).lower() in str(a).lower(),
}


@dataclass
class Condition:
    field: str
    op: str
    value: Any

    def evaluate(self, flow: dict) -> bool:
        raw = flow.get(self.field)
        if raw is None:
            return False
        try:
            fn = OPS.get(self.op)
            if fn is None:
                logger.warning(f"Unknown operator '{self.op}' in condition")
                return False
            return fn(raw, self.value)
        except (TypeError, ValueError):
            return False


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    enabled: bool
    tags: List[str]
    conditions: List[Condition] = field(default_factory=list)

    def matches(self, flow: dict) -> bool:
        """Returns True if ALL conditions match (logical AND)."""
        if not self.enabled or not self.conditions:
            return False
        return all(c.evaluate(flow) for c in self.conditions)

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "name":        self.name,
            "description": self.description,
            "severity":    self.severity,
            "enabled":     self.enabled,
            "tags":        self.tags,
            "conditions":  len(self.conditions),
        }


def load_rules(rules_path: str = "signatures/rules.yaml") -> List[Rule]:
    """
    Parse a rules YAML file and return a list of compiled Rule objects.
    Invalid rules are skipped with a warning.
    """
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML required: pip install pyyaml")

    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    raw_rules = data.get("rules", [])
    compiled: List[Rule] = []

    for raw in raw_rules:
        try:
            conditions = [
                Condition(
                    field=c["field"],
                    op=c["op"],
                    value=c["value"],
                )
                for c in raw.get("conditions", [])
            ]
            rule = Rule(
                id          = raw["id"],
                name        = raw["name"],
                description = raw.get("description", ""),
                severity    = raw.get("severity", "medium"),
                enabled     = raw.get("enabled", True),
                tags        = raw.get("tags", []),
                conditions  = conditions,
            )
            compiled.append(rule)
        except KeyError as e:
            logger.warning(f"Skipping malformed rule (missing key {e}): {raw.get('id', '?')}")

    enabled = sum(1 for r in compiled if r.enabled)
    logger.info(
        f"Loaded {len(compiled)} signature rules "
        f"({enabled} enabled, {len(compiled)-enabled} disabled) "
        f"from {path}"
    )
    return compiled
