"""
===============================================================================
TEST: COMPREHENSIVE RULES & ATTACK TYPES — Every Rule, Every Tag, Edge Cases
===============================================================================
Purpose:
  End-to-end coverage for every YAML signature rule, every attack category
  tag, alert engine integration with signatures, and edge cases.

  - TestAllRules:       each of the 18 rules individually (trigger + non-trigger)
  - TestAttackCategories: all 7 tag groups (dos, flood, scan, c2, exfil,
                          bruteforce, suspicious)
  - TestAlertEngineIntegration: signature override, multiple matches,
                                metadata enrichment
  - TestEdgeCases:      empty flows, partial fields, boundary thresholds,
                        multi-rule overlap
  - TestRealRulesYamlSmoke: structural integrity of rules.yaml itself

Run:
  pytest tests/test_rules_comprehensive.py -v  --no-header -rP
===============================================================================
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from signatures.checker import SignatureChecker
from ai_engine.alert_engine import process_results, reload_severity_thresholds


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_checker() -> SignatureChecker:
    """Return a SignatureChecker loaded with the real rules.yaml."""
    return SignatureChecker()


# ── Test All Rules — Each Rule Individually ────────────────────────────────────
#   For every rule we verify:
#     1. A flow that satisfies all conditions triggers the rule
#     2. The returned metadata has the correct rule_id, severity, tags
#     3. Changing at least one condition so it no longer matches → no trigger
#   Disabled rules are tested to NEVER fire even with a fully matching flow.

class TestAllRules:
    def setup_method(self):
        self.checker = _make_checker()

    # ── SYN_FLOOD_001 ──────────────────────────────────────────────────────────

    def test_syn_flood_001_triggers(self):
        flow = {"syn_flag_count": 100, "ack_flag_count": 0, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "SYN_FLOOD_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "SYN_FLOOD_001")
        assert meta["severity"] == "high"
        assert "dos" in meta["tags"]
        assert "flood" in meta["tags"]

    def test_syn_flood_001_ack_too_high(self):
        flow = {"syn_flag_count": 100, "ack_flag_count": 10, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "SYN_FLOOD_001" for m in metas)

    def test_syn_flood_001_wrong_direction(self):
        flow = {"syn_flag_count": 100, "ack_flag_count": 0, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "SYN_FLOOD_001" for m in metas)

    # ── HIGH_VOLUME_001 ────────────────────────────────────────────────────────

    def test_high_volume_001_triggers(self):
        flow = {"flow_bytes_per_sec": 50_000_000}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "HIGH_VOLUME_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "HIGH_VOLUME_001")
        assert meta["severity"] == "high"

    def test_high_volume_001_below_threshold(self):
        flow = {"flow_bytes_per_sec": 1_000_000}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "HIGH_VOLUME_001" for m in metas)

    # ── UDP_FLOOD_001 ──────────────────────────────────────────────────────────

    def test_udp_flood_001_triggers(self):
        flow = {"flow_packets_per_sec": 1000, "avg_packet_len": 50}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "UDP_FLOOD_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "UDP_FLOOD_001")
        assert meta["severity"] == "high"
        assert "dos" in meta["tags"]

    def test_udp_flood_001_low_packet_rate(self):
        flow = {"flow_packets_per_sec": 200, "avg_packet_len": 50}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "UDP_FLOOD_001" for m in metas)

    def test_udp_flood_001_large_avg_packet(self):
        flow = {"flow_packets_per_sec": 1000, "avg_packet_len": 200}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "UDP_FLOOD_001" for m in metas)

    # ── PORT_SCAN_MASS_001 ─────────────────────────────────────────────────────

    def test_port_scan_mass_001_triggers(self):
        flow = {"rst_flag_count": 50, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "PORT_SCAN_MASS_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "PORT_SCAN_MASS_001")
        assert meta["severity"] == "high"
        assert "scan" in meta["tags"]

    def test_port_scan_mass_001_few_rsts(self):
        flow = {"rst_flag_count": 5, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "PORT_SCAN_MASS_001" for m in metas)

    def test_port_scan_mass_001_outbound(self):
        flow = {"rst_flag_count": 50, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "PORT_SCAN_MASS_001" for m in metas)

    # ── FIN_SCAN_001 ───────────────────────────────────────────────────────────

    def test_fin_scan_001_triggers(self):
        flow = {"fin_flag_count": 10, "syn_flag_count": 0, "ack_flag_count": 0, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "FIN_SCAN_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "FIN_SCAN_001")
        assert meta["severity"] == "medium"
        assert "scan" in meta["tags"]

    def test_fin_scan_001_with_syn(self):
        flow = {"fin_flag_count": 10, "syn_flag_count": 1, "ack_flag_count": 0, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "FIN_SCAN_001" for m in metas)

    def test_fin_scan_001_few_fins(self):
        flow = {"fin_flag_count": 2, "syn_flag_count": 0, "ack_flag_count": 0, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "FIN_SCAN_001" for m in metas)

    # ── NULL_SCAN_001 ──────────────────────────────────────────────────────────

    def test_null_scan_001_triggers(self):
        flow = {
            "syn_flag_count": 0, "ack_flag_count": 0, "fin_flag_count": 0,
            "rst_flag_count": 0, "psh_flag_count": 0,
            "packet_count": 10, "direction": "inbound",
        }
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "NULL_SCAN_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "NULL_SCAN_001")
        assert meta["severity"] == "medium"
        assert "scan" in meta["tags"]

    def test_null_scan_001_has_flag(self):
        flow = {
            "syn_flag_count": 1, "ack_flag_count": 0, "fin_flag_count": 0,
            "rst_flag_count": 0, "psh_flag_count": 0,
            "packet_count": 10, "direction": "inbound",
        }
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "NULL_SCAN_001" for m in metas)

    def test_null_scan_001_too_few_packets(self):
        flow = {
            "syn_flag_count": 0, "ack_flag_count": 0, "fin_flag_count": 0,
            "rst_flag_count": 0, "psh_flag_count": 0,
            "packet_count": 3, "direction": "inbound",
        }
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "NULL_SCAN_001" for m in metas)

    # ── C2_BEACON_001 ──────────────────────────────────────────────────────────

    def test_c2_beacon_001_triggers(self):
        flow = {"packet_count": 3, "duration": 0.1, "direction": "outbound", "_dst_port": 9999}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "C2_BEACON_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "C2_BEACON_001")
        assert meta["severity"] == "high"
        assert "c2" in meta["tags"]

    def test_c2_beacon_001_too_many_packets(self):
        flow = {"packet_count": 10, "duration": 0.1, "direction": "outbound", "_dst_port": 9999}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "C2_BEACON_001" for m in metas)

    def test_c2_beacon_001_long_duration(self):
        flow = {"packet_count": 3, "duration": 2.0, "direction": "outbound", "_dst_port": 9999}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "C2_BEACON_001" for m in metas)

    def test_c2_beacon_001_bypass_port(self):
        flow = {"packet_count": 3, "duration": 0.1, "direction": "outbound", "_dst_port": 443}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "C2_BEACON_001" for m in metas)

    def test_c2_beacon_001_all_bypass_ports(self):
        for port in [53, 80, 443, 123]:
            flow = {"packet_count": 3, "duration": 0.1, "direction": "outbound", "_dst_port": port}
            metas = self.checker.check_with_metadata(flow)
            assert not any(m["rule_id"] == "C2_BEACON_001" for m in metas), \
                f"C2_BEACON_001 should not match bypass port {port}"

    # ── C2_BEACON_002 ──────────────────────────────────────────────────────────

    def test_c2_beacon_002_triggers(self):
        flow = {"duration": 500, "src_bytes": 500, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "C2_BEACON_002" in ids
        meta = next(m for m in metas if m["rule_id"] == "C2_BEACON_002")
        assert meta["severity"] == "medium"
        assert "c2" in meta["tags"]

    def test_c2_beacon_002_short_duration(self):
        flow = {"duration": 100, "src_bytes": 500, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "C2_BEACON_002" for m in metas)

    def test_c2_beacon_002_too_many_bytes(self):
        flow = {"duration": 500, "src_bytes": 50000, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "C2_BEACON_002" for m in metas)

    # ── BAD_PORT_TELNET ────────────────────────────────────────────────────────

    def test_bad_port_telnet_triggers(self):
        flow = {"_dst_port": 23, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_TELNET" in ids
        meta = next(m for m in metas if m["rule_id"] == "BAD_PORT_TELNET")
        assert meta["severity"] == "medium"
        assert "suspicious" in meta["tags"]

    def test_bad_port_telnet_wrong_port(self):
        flow = {"_dst_port": 22, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BAD_PORT_TELNET" for m in metas)

    def test_bad_port_telnet_outbound(self):
        flow = {"_dst_port": 23, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BAD_PORT_TELNET" for m in metas)

    # ── BAD_PORT_SMB ───────────────────────────────────────────────────────────

    def test_bad_port_smb_triggers(self):
        flow = {"_dst_port": 445, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_SMB" in ids
        meta = next(m for m in metas if m["rule_id"] == "BAD_PORT_SMB")
        assert meta["severity"] == "high"
        assert "suspicious" in meta["tags"]

    def test_bad_port_smb_outbound(self):
        flow = {"_dst_port": 445, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BAD_PORT_SMB" for m in metas)

    # ── BAD_PORT_RDP ───────────────────────────────────────────────────────────

    def test_bad_port_rdp_triggers(self):
        flow = {"_dst_port": 3389, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_RDP" in ids
        meta = next(m for m in metas if m["rule_id"] == "BAD_PORT_RDP")
        assert meta["severity"] == "medium"
        assert "suspicious" in meta["tags"]
        assert "bruteforce" in meta["tags"]

    # ── BAD_PORT_VNC ───────────────────────────────────────────────────────────

    def test_bad_port_vnc_triggers(self):
        flow = {"_dst_port": 5900}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_VNC" in ids
        meta = next(m for m in metas if m["rule_id"] == "BAD_PORT_VNC")
        assert meta["severity"] == "low"

    def test_bad_port_vnc_other_port(self):
        flow = {"_dst_port": 5901}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BAD_PORT_VNC" for m in metas)

    # ── BAD_PORT_IRC ───────────────────────────────────────────────────────────

    def test_bad_port_irc_triggers(self):
        flow = {"_dst_port": 6667}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_IRC" in ids
        meta = next(m for m in metas if m["rule_id"] == "BAD_PORT_IRC")
        assert meta["severity"] == "high"
        assert "c2" in meta["tags"]
        assert "suspicious" in meta["tags"]

    # ── BAD_PORT_METERPRETER ───────────────────────────────────────────────────

    def test_bad_port_meterpreter_triggers(self):
        flow = {"_dst_port": 4444}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_METERPRETER" in ids
        meta = next(m for m in metas if m["rule_id"] == "BAD_PORT_METERPRETER")
        assert meta["severity"] == "high"
        assert "c2" in meta["tags"]
        assert "suspicious" in meta["tags"]

    # ── BAD_PORT_BACKCONNECT ───────────────────────────────────────────────────

    def test_bad_port_backconnect_31337_triggers(self):
        flow = {"_dst_port": 31337}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_BACKCONNECT" in ids

    def test_bad_port_backconnect_12345_triggers(self):
        flow = {"_dst_port": 12345}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_BACKCONNECT" in ids

    def test_bad_port_backconnect_other_port(self):
        flow = {"_dst_port": 4444}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BAD_PORT_BACKCONNECT" for m in metas)

    # ── BRUTEFORCE_SSH_001 ─────────────────────────────────────────────────────

    def test_bruteforce_ssh_001_triggers(self):
        flow = {"_dst_port": 22, "syn_flag_count": 30, "duration": 10, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BRUTEFORCE_SSH_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "BRUTEFORCE_SSH_001")
        assert meta["severity"] == "high"
        assert "bruteforce" in meta["tags"]

    def test_bruteforce_ssh_001_low_syn_count(self):
        flow = {"_dst_port": 22, "syn_flag_count": 10, "duration": 10, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BRUTEFORCE_SSH_001" for m in metas)

    def test_bruteforce_ssh_001_long_duration(self):
        flow = {"_dst_port": 22, "syn_flag_count": 30, "duration": 60, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BRUTEFORCE_SSH_001" for m in metas)

    def test_bruteforce_ssh_001_wrong_direction(self):
        flow = {"_dst_port": 22, "syn_flag_count": 30, "duration": 10, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BRUTEFORCE_SSH_001" for m in metas)

    # ── BRUTEFORCE_FTP_001 ─────────────────────────────────────────────────────

    def test_bruteforce_ftp_001_triggers(self):
        flow = {"_dst_port": 21, "syn_flag_count": 20}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "BRUTEFORCE_FTP_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "BRUTEFORCE_FTP_001")
        assert meta["severity"] == "medium"
        assert "bruteforce" in meta["tags"]

    def test_bruteforce_ftp_001_low_syn(self):
        flow = {"_dst_port": 21, "syn_flag_count": 5}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "BRUTEFORCE_FTP_001" for m in metas)

    # ── EXFIL_LARGE_UPLOAD_001 ─────────────────────────────────────────────────

    def test_exfil_large_upload_001_triggers(self):
        flow = {"src_bytes": 10_000_000, "flow_bytes_per_sec": 1_000_000, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        ids = [m["rule_id"] for m in metas]
        assert "EXFIL_LARGE_UPLOAD_001" in ids
        meta = next(m for m in metas if m["rule_id"] == "EXFIL_LARGE_UPLOAD_001")
        assert meta["severity"] == "medium"
        assert "exfil" in meta["tags"]

    def test_exfil_large_upload_001_low_bytes(self):
        flow = {"src_bytes": 100_000, "flow_bytes_per_sec": 1_000_000, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "EXFIL_LARGE_UPLOAD_001" for m in metas)

    def test_exfil_large_upload_001_low_rate(self):
        flow = {"src_bytes": 10_000_000, "flow_bytes_per_sec": 100_000, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "EXFIL_LARGE_UPLOAD_001" for m in metas)

    # ── ICMP_FLOOD_001 (disabled) ──────────────────────────────────────────────

    def test_icmp_flood_001_disabled(self):
        flow = {"flow_packets_per_sec": 500, "avg_packet_len": 50}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "ICMP_FLOOD_001" for m in metas), \
            "ICMP_FLOOD_001 is disabled — must never match"

    # ── DNS_EXFIL_001 (disabled) ───────────────────────────────────────────────

    def test_dns_exfil_001_disabled(self):
        flow = {"dst_port": 53, "flow_packets_per_sec": 500}
        metas = self.checker.check_with_metadata(flow)
        assert not any(m["rule_id"] == "DNS_EXFIL_001" for m in metas), \
            "DNS_EXFIL_001 is disabled — must never match"


# ── Test Attack Categories — Grouped by Tag ────────────────────────────────────
#   Verify that for each attack tag at least one rule can be triggered.

class TestAttackCategories:
    def setup_method(self):
        self.checker = _make_checker()

    def test_dos_tag(self):
        flow = {"syn_flag_count": 100, "ack_flag_count": 0, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        dos_rules = [m for m in metas if "dos" in m["tags"]]
        assert len(dos_rules) >= 1

    def test_flood_tag(self):
        flow = {"syn_flag_count": 100, "ack_flag_count": 0, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        flood_rules = [m for m in metas if "flood" in m["tags"]]
        assert len(flood_rules) >= 1

    def test_scan_tag(self):
        flow = {"fin_flag_count": 10, "syn_flag_count": 0, "ack_flag_count": 0, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        scan_rules = [m for m in metas if "scan" in m["tags"]]
        assert len(scan_rules) >= 1

    def test_c2_tag(self):
        flow = {"packet_count": 3, "duration": 0.1, "direction": "outbound", "_dst_port": 9999}
        metas = self.checker.check_with_metadata(flow)
        c2_rules = [m for m in metas if "c2" in m["tags"]]
        assert len(c2_rules) >= 1

    def test_exfil_tag(self):
        flow = {"src_bytes": 10_000_000, "flow_bytes_per_sec": 1_000_000, "direction": "outbound"}
        metas = self.checker.check_with_metadata(flow)
        exfil_rules = [m for m in metas if "exfil" in m["tags"]]
        assert len(exfil_rules) >= 1

    def test_bruteforce_tag(self):
        flow = {"_dst_port": 22, "syn_flag_count": 30, "duration": 10, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        bf_rules = [m for m in metas if "bruteforce" in m["tags"]]
        assert len(bf_rules) >= 1

    def test_suspicious_tag(self):
        flow = {"_dst_port": 445, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        susp_rules = [m for m in metas if "suspicious" in m["tags"]]
        assert len(susp_rules) >= 1


# ── Alert Engine Integration ───────────────────────────────────────────────────
#   Test how the alert engine merges signature results with ML inference output.

class TestAlertEngineIntegration:
    def setup_method(self):
        reload_severity_thresholds()
        self.checker = _make_checker()

    def test_signature_overrides_ml_score(self):
        """
        A flow below the ML threshold but matching a signature rule
        should still produce an alert with the rule's severity.
        """
        results = [{"score": 0.30, "label": "BENIGN", "syn_flag_count": 200, "ack_flag_count": 0, "direction": "inbound"}]
        alerts = process_results(results, signature_checker=self.checker)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "high"
        assert "signature_match" in alerts[0]
        assert alerts[0]["label"] == "ATTACK"

    def test_multiple_signatures_in_alert(self):
        """
        A flow matching multiple rules should have all matches
        serialized into signature_match.
        """
        flow = {"_dst_port": 23, "direction": "inbound", "rst_flag_count": 50}
        results = [{"score": 0.10, "label": "BENIGN", **flow}]
        alerts = process_results(results, signature_checker=self.checker)
        assert len(alerts) == 1
        import json
        sigs = json.loads(alerts[0]["signature_match"])
        rule_ids = [s["rule_id"] for s in sigs]
        assert "BAD_PORT_TELNET" in rule_ids
        assert "PORT_SCAN_MASS_001" in rule_ids

    def test_signature_enriches_alert_metadata(self):
        """Alert dict should contain signature_match with rule_id, severity, tags."""
        results = [{"score": 0.30, "label": "BENIGN", "syn_flag_count": 200, "ack_flag_count": 0, "direction": "inbound"}]
        alerts = process_results(results, signature_checker=self.checker)
        import json
        sigs = json.loads(alerts[0]["signature_match"])
        entry = next(s for s in sigs if s["rule_id"] == "SYN_FLOOD_001")
        assert entry["severity"] == "high"
        assert "dos" in entry["tags"]
        assert "name" in entry
        assert "description" in entry

    def test_ml_only_below_threshold_no_signature(self):
        """Flow below ML threshold with no signature match produces no alert."""
        results = [{"score": 0.30, "label": "BENIGN", "dst_port": 443}]
        alerts = process_results(results, signature_checker=self.checker)
        assert len(alerts) == 0

    def test_ml_high_score_without_signature(self):
        """High ML score alone should produce an alert even without signature."""
        results = [{"score": 0.95, "label": "ATTACK"}]
        alerts = process_results(results, signature_checker=self.checker)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "high"
        assert "signature_match" not in alerts[0]


# ── Edge Cases ─────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def setup_method(self):
        self.checker = _make_checker()

    def test_empty_flow_dict(self):
        """An empty dict should not crash — should match nothing."""
        metas = self.checker.check_with_metadata({})
        assert metas == []

    def test_partial_fields_no_crash(self):
        """A flow with only some expected fields should not raise."""
        flow = {"dst_port": 80}
        metas = self.checker.check_with_metadata(flow)
        assert isinstance(metas, list)

    def test_boundary_conditions_exact_thresholds(self):
        """
        gt 50 means value must be strictly > 50.
        gte 5 means value must be >= 5.
        lt 0.5 means value must be strictly < 0.5.
        """
        flow = {"syn_flag_count": 51, "ack_flag_count": 4, "direction": "inbound"}
        metas = self.checker.check_with_metadata(flow)
        assert any(m["rule_id"] == "SYN_FLOOD_001" for m in metas)

        flow_eq = {"syn_flag_count": 50, "ack_flag_count": 4, "direction": "inbound"}
        metas_eq = self.checker.check_with_metadata(flow_eq)
        assert not any(m["rule_id"] == "SYN_FLOOD_001" for m in metas_eq), \
            "syn_flag_count == 50 should NOT trigger gt 50"

    def test_multiple_rules_match_same_flow(self):
        """A flow to port 23 with high RST count should match TELNET + PORT_SCAN."""
        flow = {"_dst_port": 23, "direction": "inbound", "rst_flag_count": 50}
        metas = self.checker.check_with_metadata(flow)
        rule_ids = [m["rule_id"] for m in metas]
        assert "BAD_PORT_TELNET" in rule_ids
        assert "PORT_SCAN_MASS_001" in rule_ids
        assert len(rule_ids) >= 2

    def test_disabled_rules_never_match(self):
        """Both disabled rules must never match, period."""
        flow_icmp = {"flow_packets_per_sec": 500, "avg_packet_len": 50}
        flow_dns = {"dst_port": 53, "flow_packets_per_sec": 500}
        metas_icmp = self.checker.check_with_metadata(flow_icmp)
        metas_dns = self.checker.check_with_metadata(flow_dns)
        assert not any(m["rule_id"] == "ICMP_FLOOD_001" for m in metas_icmp)
        assert not any(m["rule_id"] == "DNS_EXFIL_001" for m in metas_dns)


# ── Structural Integrity of rules.yaml ─────────────────────────────────────────

class TestRealRulesYamlSmoke:
    def setup_method(self):
        self.checker = _make_checker()

    def test_loads_all_expected_rules(self):
        rules = self.checker.rules_summary
        assert len(rules) == 25, f"Expected 25 rules, got {len(rules)}"

    def test_all_rule_ids_are_unique(self):
        rules = self.checker.rules_summary
        ids = [r["id"] for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_expected_enabled_count(self):
        enabled = sum(1 for r in self.checker.rules_summary if r["enabled"])
        disabled = self.checker.rule_count - enabled
        assert enabled == 23, f"Expected 23 enabled rules, got {enabled}"
        assert disabled == 2, f"Expected 2 disabled rules, got {disabled}"

    def test_known_attack_flow_hits_expected_rules(self):
        """
        A multi-indicator flow should trigger multiple rules simultaneously:
        high SYN count (>50) + SMB port (445) + low ACK.
        """
        flow = {
            "_dst_port": 445,
            "syn_flag_count": 60,
            "ack_flag_count": 1,
            "direction": "inbound",
            "duration": 5,
        }
        metas = self.checker.check_with_metadata(flow)
        rule_ids = [m["rule_id"] for m in metas]
        assert "SYN_FLOOD_001" in rule_ids
        assert "BAD_PORT_SMB" in rule_ids
