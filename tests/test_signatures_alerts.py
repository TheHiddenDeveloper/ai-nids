"""
Unit Tests — SignatureChecker & AlertEngine
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from signatures.checker import SignatureChecker
from ai_engine.alert_engine import classify_severity, process_results


class TestSignatureChecker:
    def setup_method(self):
        self.checker = SignatureChecker()

    def test_syn_flood_detected(self):
        flow = {"syn_flag_count": 100, "ack_flag_count": 1}
        result = self.checker.check(flow)
        assert result is not None
        assert "SYN flood" in result

    def test_port_scan_detected(self):
        flow = {"rst_flag_count": 50, "syn_flag_count": 0, "ack_flag_count": 0}
        result = self.checker.check(flow)
        assert result is not None
        assert "Port scan" in result

    def test_bad_port_detected(self):
        flow = {"_dst_port": 445}
        result = self.checker.check(flow)
        assert result is not None
        assert "port" in result.lower()

    def test_benign_flow_passes(self):
        flow = {
            "syn_flag_count": 1, "ack_flag_count": 5,
            "rst_flag_count": 0, "fin_flag_count": 1,
            "packet_count": 20, "duration": 5.0,
            "flow_bytes_per_sec": 500,
            "_dst_port": 443,
        }
        assert self.checker.check(flow) is None

    def test_check_all_returns_list(self):
        flow = {"syn_flag_count": 100, "ack_flag_count": 0, "_dst_port": 445}
        matches = self.checker.check_all(flow)
        assert isinstance(matches, list)
        assert len(matches) >= 2

    def test_fin_scan_detected(self):
        flow = {"fin_flag_count": 10, "syn_flag_count": 0, "ack_flag_count": 0}
        result = self.checker.check(flow)
        assert result is not None

    def test_high_volume_detected(self):
        flow = {"flow_bytes_per_sec": 50_000_000}
        result = self.checker.check(flow)
        assert result is not None


class TestAlertEngine:
    def test_high_severity(self):
        assert classify_severity(0.95) == "high"

    def test_medium_severity(self):
        assert classify_severity(0.85) == "medium"

    def test_low_severity(self):
        assert classify_severity(0.70) == "low"

    def test_below_threshold_returns_none(self):
        assert classify_severity(0.50) is None
        assert classify_severity(0.64) is None

    def test_process_filters_benign(self):
        results = [
            {"score": 0.1, "label": "BENIGN"},
            {"score": 0.2, "label": "BENIGN"},
        ]
        alerts = process_results(results)
        assert len(alerts) == 0

    def test_process_returns_high_score(self):
        results = [{"score": 0.95, "label": "ATTACK"}]
        alerts = process_results(results)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "high"

    def test_signature_escalates_to_high(self):
        checker = SignatureChecker()
        results = [{"score": 0.30, "label": "BENIGN", "syn_flag_count": 200, "ack_flag_count": 0}]
        alerts = process_results(results, signature_checker=checker)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "high"
        assert "signature_match" in alerts[0]

    def test_mixed_batch(self):
        results = [
            {"score": 0.05, "label": "BENIGN"},
            {"score": 0.95, "label": "ATTACK"},
            {"score": 0.72, "label": "ATTACK"},
            {"score": 0.10, "label": "BENIGN"},
        ]
        alerts = process_results(results)
        assert len(alerts) == 2
