"""
Unit Tests — signatures/ Step 7
Tests loader, Condition evaluation, Rule matching, SignatureChecker,
and hot-reload behaviour.
"""

import sys
import time
import tempfile
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from signatures.loader import Condition, Rule, load_rules
from signatures.checker import SignatureChecker


# ── Condition evaluation ──────────────────────────────────────────────────────

class TestCondition:
    def test_gt_true(self):
        c = Condition(field="syn_flag_count", op="gt", value=50)
        assert c.evaluate({"syn_flag_count": 100}) is True

    def test_gt_false(self):
        c = Condition(field="syn_flag_count", op="gt", value=50)
        assert c.evaluate({"syn_flag_count": 10}) is False

    def test_lt(self):
        c = Condition(field="duration", op="lt", value=0.5)
        assert c.evaluate({"duration": 0.1}) is True
        assert c.evaluate({"duration": 1.0}) is False

    def test_eq_numeric(self):
        c = Condition(field="protocol_type", op="eq", value=17)
        assert c.evaluate({"protocol_type": 17}) is True
        assert c.evaluate({"protocol_type": 6})  is False

    def test_eq_string(self):
        c = Condition(field="label", op="eq", value="ATTACK")
        assert c.evaluate({"label": "ATTACK"}) is True
        assert c.evaluate({"label": "BENIGN"}) is False

    def test_in_list(self):
        c = Condition(field="_dst_port", op="in", value=[80, 443, 8080])
        assert c.evaluate({"_dst_port": 443}) is True
        assert c.evaluate({"_dst_port": 22})  is False

    def test_not_in(self):
        c = Condition(field="_dst_port", op="not_in", value=[22, 80])
        assert c.evaluate({"_dst_port": 443}) is True
        assert c.evaluate({"_dst_port": 22})  is False

    def test_gte(self):
        c = Condition(field="packet_count", op="gte", value=5)
        assert c.evaluate({"packet_count": 5}) is True
        assert c.evaluate({"packet_count": 4}) is False

    def test_lte(self):
        c = Condition(field="packet_count", op="lte", value=3)
        assert c.evaluate({"packet_count": 3}) is True
        assert c.evaluate({"packet_count": 4}) is False

    def test_missing_field_returns_false(self):
        c = Condition(field="nonexistent", op="gt", value=0)
        assert c.evaluate({}) is False

    def test_type_error_returns_false(self):
        c = Condition(field="label", op="gt", value=10)
        assert c.evaluate({"label": "ATTACK"}) is False


# ── Rule matching ─────────────────────────────────────────────────────────────

def make_rule(conditions, enabled=True, severity="high"):
    return Rule(
        id="TEST_001", name="Test rule", description="desc",
        severity=severity, enabled=enabled, tags=["test"],
        conditions=conditions,
    )


class TestRule:
    def test_all_conditions_must_match(self):
        rule = make_rule([
            Condition("syn_flag_count", "gt",  50),
            Condition("ack_flag_count", "lt", 5),
        ])
        assert rule.matches({"syn_flag_count": 100, "ack_flag_count": 1}) is True
        assert rule.matches({"syn_flag_count": 100, "ack_flag_count": 10}) is False
        assert rule.matches({"syn_flag_count": 10,  "ack_flag_count": 1})  is False

    def test_disabled_rule_never_matches(self):
        rule = make_rule(
            [Condition("syn_flag_count", "gt", 0)],
            enabled=False,
        )
        assert rule.matches({"syn_flag_count": 1000}) is False

    def test_empty_conditions_never_match(self):
        rule = make_rule(conditions=[])
        assert rule.matches({"anything": 1}) is False

    def test_to_dict(self):
        rule = make_rule([Condition("x", "gt", 1)])
        d = rule.to_dict()
        assert d["id"]         == "TEST_001"
        assert d["enabled"]    is True
        assert d["conditions"] == 1


# ── YAML loader ───────────────────────────────────────────────────────────────

MINIMAL_YAML = textwrap.dedent("""\
    version: "1.0"
    rules:
      - id: R001
        name: High SYN
        description: SYN flood test
        severity: high
        enabled: true
        tags: [dos]
        conditions:
          - field: syn_flag_count
            op: gt
            value: 50

      - id: R002
        name: Disabled rule
        description: Should not fire
        severity: low
        enabled: false
        tags: [test]
        conditions:
          - field: packet_count
            op: gt
            value: 0
""")


class TestLoader:
    def _write_yaml(self, content: str) -> Path:
        tmp = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
        tmp.write(content)
        tmp.flush()
        return Path(tmp.name)

    def test_loads_rules(self):
        path = self._write_yaml(MINIMAL_YAML)
        rules = load_rules(str(path))
        assert len(rules) == 2

    def test_enabled_flags(self):
        path = self._write_yaml(MINIMAL_YAML)
        rules = load_rules(str(path))
        assert rules[0].enabled is True
        assert rules[1].enabled is False

    def test_conditions_compiled(self):
        path = self._write_yaml(MINIMAL_YAML)
        rules = load_rules(str(path))
        assert len(rules[0].conditions) == 1

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_rules("/nonexistent/rules.yaml")

    def test_malformed_rule_skipped(self):
        bad_yaml = textwrap.dedent("""\
            version: "1.0"
            rules:
              - id: GOOD_001
                name: Good rule
                severity: medium
                enabled: true
                tags: []
                conditions:
                  - field: packet_count
                    op: gt
                    value: 0
              - this_is_missing_id_and_name: true
        """)
        path = self._write_yaml(bad_yaml)
        rules = load_rules(str(path))
        assert len(rules) == 1
        assert rules[0].id == "GOOD_001"


# ── SignatureChecker ──────────────────────────────────────────────────────────

class TestSignatureChecker:
    def _write_yaml(self, content: str) -> Path:
        tmp = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
        tmp.write(content)
        tmp.flush()
        return Path(tmp.name)

    def test_check_returns_match(self):
        path = self._write_yaml(MINIMAL_YAML)
        checker = SignatureChecker(rules_path=str(path))
        result = checker.check({"syn_flag_count": 100})
        assert result is not None
        assert "SYN" in result

    def test_check_returns_none_for_benign(self):
        path = self._write_yaml(MINIMAL_YAML)
        checker = SignatureChecker(rules_path=str(path))
        assert checker.check({"syn_flag_count": 1}) is None

    def test_check_all_returns_list(self):
        path = self._write_yaml(MINIMAL_YAML)
        checker = SignatureChecker(rules_path=str(path))
        results = checker.check_all({"syn_flag_count": 100})
        assert isinstance(results, list)
        assert len(results) == 1

    def test_check_with_metadata(self):
        path = self._write_yaml(MINIMAL_YAML)
        checker = SignatureChecker(rules_path=str(path))
        metas = checker.check_with_metadata({"syn_flag_count": 100})
        assert len(metas) == 1
        assert metas[0]["rule_id"] == "R001"
        assert metas[0]["severity"] == "high"
        assert "dos" in metas[0]["tags"]

    def test_rule_count(self):
        path = self._write_yaml(MINIMAL_YAML)
        checker = SignatureChecker(rules_path=str(path))
        assert checker.rule_count == 2
        assert checker.enabled_count == 1

    def test_reload_picks_up_changes(self):
        path = self._write_yaml(MINIMAL_YAML)
        checker = SignatureChecker(rules_path=str(path))
        assert checker.rule_count == 2

        # Write a new version with three rules
        new_yaml = MINIMAL_YAML + textwrap.dedent("""\
              - id: R003
                name: Extra rule
                severity: medium
                enabled: true
                tags: [test]
                conditions:
                  - field: rst_flag_count
                    op: gt
                    value: 10
        """)
        path.write_text(new_yaml)
        checker.reload()
        assert checker.rule_count == 3

    def test_hot_reload_via_watcher(self):
        path = self._write_yaml(MINIMAL_YAML)
        checker = SignatureChecker(rules_path=str(path), watch=True, watch_interval=1)
        assert checker.rule_count == 2

        time.sleep(0.5)
        new_yaml = MINIMAL_YAML + textwrap.dedent("""\
              - id: R004
                name: Watcher test rule
                severity: low
                enabled: true
                tags: [test]
                conditions:
                  - field: fin_flag_count
                    op: gt
                    value: 5
        """)
        path.write_text(new_yaml)
        time.sleep(2.0)   # let watcher detect and reload
        checker.stop_watching()
        assert checker.rule_count == 3

    def test_rules_summary(self):
        path = self._write_yaml(MINIMAL_YAML)
        checker = SignatureChecker(rules_path=str(path))
        summary = checker.rules_summary
        assert len(summary) == 2
        assert summary[0]["id"] == "R001"


# ── Integration: real rules.yaml ─────────────────────────────────────────────

class TestRealRulesYaml:
    """Smoke tests against the actual rules.yaml in the project."""

    REAL_RULES = Path("signatures/rules.yaml")

    def test_loads_without_error(self):
        if not self.REAL_RULES.exists():
            pytest.skip("signatures/rules.yaml not found")
        rules = load_rules(str(self.REAL_RULES))
        assert len(rules) > 0

    def test_syn_flood_fires(self):
        if not self.REAL_RULES.exists():
            pytest.skip("signatures/rules.yaml not found")
        checker = SignatureChecker(rules_path=str(self.REAL_RULES))
        flow = {"syn_flag_count": 100, "ack_flag_count": 0}
        assert checker.check(flow) is not None

    def test_smb_port_fires(self):
        if not self.REAL_RULES.exists():
            pytest.skip("signatures/rules.yaml not found")
        checker = SignatureChecker(rules_path=str(self.REAL_RULES))
        assert checker.check({"_dst_port": 445}) is not None

    def test_benign_flow_does_not_fire(self):
        if not self.REAL_RULES.exists():
            pytest.skip("signatures/rules.yaml not found")
        checker = SignatureChecker(rules_path=str(self.REAL_RULES))
        flow = {
            "syn_flag_count": 1, "ack_flag_count": 5,
            "rst_flag_count": 0, "fin_flag_count": 1,
            "psh_flag_count": 2, "packet_count": 20,
            "duration": 2.5,    "src_bytes": 4000,
            "flow_bytes_per_sec": 1600,
            "flow_packets_per_sec": 8,
            "avg_packet_len": 200,
            "protocol_type": 6, "_dst_port": 443,
        }
        assert checker.check(flow) is None
