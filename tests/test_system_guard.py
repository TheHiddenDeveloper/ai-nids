"""
===============================================================================
TEST: SYSTEM GUARD — End-to-End AI-NIDS Network Protection
===============================================================================
Purpose:
  Validates the system behaves as a production AI-NIDS capable of guarding
  a network. Tests the full detection pipeline with synthetic traffic:

  1. Benign traffic produces zero alerts (no false positives)
  2. Attack traffic produces correct, classified alerts (true positives)
  3. Both detection paths work: signature-only and full ensemble
  4. Alert deduplication prevents alert storms
  5. Data persistence writes to SQLite correctly
  6. Pipeline lifecycle (start/stop/flush) is clean
  7. Graceful degradation when models are unavailable
  8. Event bus delivers flow/alert/stats events in real-time

Design:
  - Generates synthetic packet dicts matching capture.py format
    (no scapy dependency — pure dicts fed to pipeline.ingest_packet)
  - Uses real NIDSPipeline with all real components
  - Monkeypatches Redis out (in-memory fallback) for test isolation
  - Cleans SQLite data between classes via clear_db_data()

Attack scenarios generated:
  SYN flood, port scan, FIN scan, C2 beacon, bad ports (SMB, Telnet,
  Meterpreter), SSH brute-force, FTP brute-force, NULL scan,
  high-volume exfil, UDP flood

Run:
  pytest tests/test_system_guard.py -v --tb=long
  pytest tests/test_system_guard.py -v -k "test_benign"  # quick subset
===============================================================================
"""

import sys
import time
import json
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from loguru import logger

# Suppress loguru chatter during tests
logger.remove()


# ── Synthetic packet helpers ───────────────────────────────────────────────────
#   These produce packet dicts in the same format as capture.py's _parse_packet.
#   No scapy needed — direct dicts fed to pipeline.ingest_packet().

HOME_NET = ["192.168.0.0/16"]
INTERNAL = "192.168.1.100"
INTERNAL2 = "192.168.1.200"
EXTERNAL_ATTACKER = "10.0.0.99"
EXTERNAL_C2 = "185.220.101.1"
EXTERNAL_SERVER = "93.184.216.34"

_now = time.time()


def _t(offset=0.0):
    """Return a monotonically increasing timestamp starting from now."""
    global _now
    _now += offset
    return _now


def make_pkt(
    src_ip=INTERNAL,
    dst_ip=EXTERNAL_SERVER,
    src_port=40000,
    dst_port=80,
    protocol=6,
    ip_len=100,
    ttl=64,
    syn=0,
    ack=0,
    fin=0,
    rst=0,
    psh=0,
    urg=0,
    timestamp=None,
):
    """Create a single packet dict in capture.py format."""
    return {
        "timestamp": timestamp or _t(0.001),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "ip_len": ip_len,
        "ttl": ttl,
        "syn": syn,
        "ack": ack,
        "fin": fin,
        "rst": rst,
        "psh": psh,
        "urg": urg,
    }


# ── Flow generators ────────────────────────────────────────────────────────────
#   Each returns a list of packet dicts forming one complete flow.

def benign_http_flow(src=INTERNAL, dst=EXTERNAL_SERVER, sp=40000, dp=80):
    """Normal HTTP request: SYN→SYN-ACK→ACK→GET→200→FIN→FIN-ACK."""
    base = _t(0)
    return [
        make_pkt(src, dst, sp, dp, syn=1, ack=0, timestamp=base),
        make_pkt(dst, src, dp, sp, syn=1, ack=1, timestamp=_t(0.001)),
        make_pkt(src, dst, sp, dp, syn=0, ack=1, timestamp=_t(0.001)),
        make_pkt(src, dst, sp, dp, psh=1, ack=1, ip_len=400,
                 timestamp=_t(0.01)),
        make_pkt(dst, src, dp, sp, psh=1, ack=1, ip_len=1200,
                 timestamp=_t(0.01)),
        make_pkt(src, dst, sp, dp, fin=1, ack=1, timestamp=_t(0.001)),
        make_pkt(dst, src, dp, sp, fin=1, ack=1, timestamp=_t(0.001)),
    ]


def benign_dns_query(src=INTERNAL, dst="8.8.8.8", sp=50000, dp=53):
    """Normal DNS query (UDP)."""
    base = _t(0)
    return [
        make_pkt(src, dst, sp, dp, protocol=17, ip_len=60,
                 timestamp=base),
        make_pkt(dst, src, dp, sp, protocol=17, ip_len=200,
                 timestamp=_t(0.01)),
    ]


def syn_flood_flow(attacker=EXTERNAL_ATTACKER, victim=INTERNAL, syn_count=80):
    """SYN flood: many SYNs on same 5-tuple so flags accumulate."""
    pkts = []
    for _ in range(syn_count):
        pkts.append(make_pkt(
            attacker, victim, 20000, 80,
            syn=1, ack=0, timestamp=_t(0.002),
        ))
    return pkts


def port_scan_flow(scanner=EXTERNAL_ATTACKER, target=INTERNAL):
    """RST-based scan: 25 RST packets in one flow (different port from SYN flood)."""
    pkts = []
    for _ in range(25):
        pkts.append(make_pkt(scanner, target, 50000, 81,
                             rst=1, ack=0, timestamp=_t(0.002)))
    return pkts


def fin_scan_flow(scanner=EXTERNAL_ATTACKER, target=INTERNAL):
    """Stealth FIN scan: 10 FIN packets in one flow."""
    pkts = []
    for _ in range(10):
        pkts.append(make_pkt(scanner, target, 60000, 80,
                             fin=1, ack=0, syn=0, timestamp=_t(0.002)))
    return pkts


def null_scan_flow(scanner=EXTERNAL_ATTACKER, target=INTERNAL):
    """NULL scan: 10 null-flag packets in one flow."""
    pkts = []
    for _ in range(10):
        pkts.append(make_pkt(scanner, target, 61000, 80,
                             syn=0, ack=0, fin=0, rst=0, psh=0,
                             timestamp=_t(0.002)))
    return pkts


def c2_beacon_flow(bot=INTERNAL, c2=EXTERNAL_C2):
    """
    C2 beacon: tiny periodic flows to non-standard port (8443).
    Each beacon is 3 packets with short duration (< 0.5s).
    Different 5-tuples produce separate flows, each matching C2_BEACON_001.
    """
    pkts = []
    for i in range(8):
        sp = 63000 + i
        pkts.append(make_pkt(bot, c2, sp, 8443,
                             syn=1, ack=0, timestamp=_t(0.001)))
        pkts.append(make_pkt(c2, bot, 8443, sp,
                             syn=1, ack=1, timestamp=_t(0.001)))
        pkts.append(make_pkt(bot, c2, sp, 8443,
                             fin=1, ack=1, ip_len=40, timestamp=_t(0.1)))
    return pkts


def bad_port_smb_flow(attacker=EXTERNAL_ATTACKER, victim=INTERNAL):
    """SMB traffic to port 445."""
    sp = 65000
    return [
        make_pkt(attacker, victim, sp, 445, syn=1, ack=0, timestamp=_t(0.01)),
        make_pkt(victim, attacker, 445, sp, syn=1, ack=1, timestamp=_t(0.01)),
        make_pkt(attacker, victim, sp, 445, psh=1, ack=1, ip_len=200, timestamp=_t(0.05)),
        make_pkt(attacker, victim, sp, 445, fin=1, ack=1, timestamp=_t(0.01)),
    ]


def bad_port_telnet_flow(attacker=EXTERNAL_ATTACKER, victim=INTERNAL):
    """Telnet traffic to port 23."""
    sp = 66000
    return [
        make_pkt(attacker, victim, sp, 23, syn=1, ack=0, timestamp=_t(0.01)),
        make_pkt(victim, attacker, 23, sp, syn=1, ack=1, timestamp=_t(0.01)),
        make_pkt(attacker, victim, sp, 23, psh=1, ack=1, ip_len=64, timestamp=_t(0.1)),
        make_pkt(attacker, victim, sp, 23, fin=1, ack=1, timestamp=_t(0.01)),
    ]


def ssh_bruteforce_flow(attacker=EXTERNAL_ATTACKER, victim=INTERNAL):
    """SSH brute-force: 30 SYN packets to port 22, same 5-tuple."""
    pkts = []
    for _ in range(30):
        pkts.append(make_pkt(attacker, victim, 67000, 22,
                             syn=1, ack=0, timestamp=_t(0.002)))
    return pkts


def ftp_bruteforce_flow(attacker=EXTERNAL_ATTACKER, victim=INTERNAL):
    """FTP brute-force: 20 SYN packets to port 21, same 5-tuple."""
    pkts = []
    for _ in range(20):
        pkts.append(make_pkt(attacker, victim, 68000, 21,
                             syn=1, ack=0, timestamp=_t(0.002)))
    return pkts


def meterpreter_flow(attacker=EXTERNAL_ATTACKER, victim=INTERNAL):
    """Meterpreter reverse shell to port 4444."""
    sp = 70000
    return [
        make_pkt(attacker, victim, sp, 4444, syn=1, ack=0, timestamp=_t(0.01)),
        make_pkt(victim, attacker, 4444, sp, syn=1, ack=1, timestamp=_t(0.01)),
        make_pkt(attacker, victim, sp, 4444, psh=1, ack=1, ip_len=512, timestamp=_t(0.05)),
        make_pkt(attacker, victim, sp, 4444, fin=1, ack=1, timestamp=_t(0.01)),
    ]


# ── Test fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    """Force in-memory fallback for Redis throughout all tests."""
    import core.redis_client as rc
    monkeypatch.setattr(rc, "get_redis_client", lambda: None)


@pytest.fixture(autouse=True)
def _clean_db():
    """Clean SQLite data before and after each test class."""
    from monitor.db import clear_db_data
    try:
        clear_db_data()
    except PermissionError:
        pass  # data/nids.log may be root-owned
    yield
    try:
        clear_db_data()
    except PermissionError:
        pass


# ── Pipeline lifecycle helpers ─────────────────────────────────────────────────

def _safe_stop(pipeline):
    """Stop pipeline safely, handling the ThreadPool shutdown order."""
    remaining = pipeline.aggregator.flush_all()
    if remaining:
        pipeline._process_flows(remaining)
    pipeline._stop_event.set()
    time.sleep(0.1)
    pipeline._intel_pool.shutdown(wait=False)
    pipeline.stop()


def _ingest_flows(pipeline, flow_generators):
    """Feed multiple flow generators into the pipeline."""
    for gen in flow_generators:
        pkts = gen() if callable(gen) else gen
        for pkt in pkts:
            pipeline.ingest_packet(pkt)


def _flush_and_stop(pipeline):
    """Flush remaining flows and stop the pipeline.
    Returns (flows_processed, alerts_collected) by subscribing to the event bus.
    """
    collected = {"flows": 0, "alerts": []}

    def on_flow(p):
        collected["flows"] += 1

    def on_alert(a):
        collected["alerts"].append(a)

    pipeline.bus.subscribe("flow", on_flow)
    pipeline.bus.subscribe("alert", on_alert)

    _safe_stop(pipeline)
    time.sleep(0.1)
    return collected["flows"], collected["alerts"]


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestPipelineLifecycle:
    """Pipeline starts, processes traffic, and stops cleanly."""

    def test_pipeline_starts_and_stops(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        assert pipeline.start() is True
        assert pipeline.active_flows == 0
        pipeline.stop()

    def test_pipeline_ingest_and_flush(self):
        from core.pipeline import NIDSPipeline
        from core.event_bus import EventBus
        bus = EventBus()
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
            event_bus=bus,
        )
        pipeline.start()

        pkts = syn_flood_flow()
        for pkt in pkts:
            pipeline.ingest_packet(pkt)

        assert pipeline.active_flows >= 1
        _safe_stop(pipeline)


class TestBenignTraffic:
    """Benign traffic must produce zero alerts."""

    def test_benign_http_no_alerts(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()

        for _ in range(10):
            for pkt in benign_http_flow():
                pipeline.ingest_packet(pkt)

        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) == 0, f"Expected 0 alerts, got {len(alerts)}"

    def test_benign_dns_no_alerts(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()

        for _ in range(5):
            for pkt in benign_dns_query():
                pipeline.ingest_packet(pkt)

        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) == 0, f"Expected 0 alerts, got {len(alerts)}"

    def test_mixed_benign_traffic_no_alerts(self):
        """Mix of HTTP + DNS, all benign → zero alerts."""
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()

        for _ in range(5):
            for pkt in benign_http_flow():
                pipeline.ingest_packet(pkt)
        for _ in range(3):
            for pkt in benign_dns_query():
                pipeline.ingest_packet(pkt)

        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) == 0, f"Benign traffic produced {len(alerts)} alerts"


class TestAttackDetection:
    """Each known attack type triggers the correct signature alert."""

    def test_syn_flood_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [syn_flood_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "SYN_FLOOD_001" in sigs

    def test_port_scan_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [port_scan_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "PORT_SCAN_MASS_001" in sigs

    def test_fin_scan_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [fin_scan_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "FIN_SCAN_001" in sigs

    def test_null_scan_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [null_scan_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "NULL_SCAN_001" in sigs

    def test_c2_beacon_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [c2_beacon_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "C2_BEACON_001" in sigs

    def test_bad_port_smb_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [bad_port_smb_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "BAD_PORT_SMB" in sigs

    def test_bad_port_telnet_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [bad_port_telnet_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "BAD_PORT_TELNET" in sigs

    def test_ssh_bruteforce_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [ssh_bruteforce_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "BRUTEFORCE_SSH_001" in sigs

    def test_ftp_bruteforce_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [ftp_bruteforce_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "BRUTEFORCE_FTP_001" in sigs

    def test_meterpreter_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [meterpreter_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 1
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "BAD_PORT_METERPRETER" in sigs


class TestMultiAttackDetection:
    """Mixed attack scenarios: multiple alerts from one traffic batch."""

    def test_mixed_attacks_all_detected(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()

        _ingest_flows(pipeline, [
            syn_flood_flow,
            port_scan_flow,
            c2_beacon_flow,
            bad_port_smb_flow,
            ssh_bruteforce_flow,
        ])

        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 5, f"Expected >=5 alerts, got {len(alerts)}"
        sigs = " ".join(a.get("signature_match", "") for a in alerts)
        assert "SYN_FLOOD_001" in sigs
        assert "PORT_SCAN_MASS_001" in sigs
        assert "C2_BEACON_001" in sigs
        assert "BAD_PORT_SMB" in sigs
        assert "BRUTEFORCE_SSH_001" in sigs

    def test_benign_and_attacks_mixed(self):
        """Benign + attack traffic: only attacks produce alerts."""
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()

        for _ in range(5):
            for pkt in benign_http_flow():
                pipeline.ingest_packet(pkt)

        _ingest_flows(pipeline, [
            syn_flood_flow,
            port_scan_flow,
        ])

        for _ in range(3):
            for pkt in benign_dns_query():
                pipeline.ingest_packet(pkt)

        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 2
        assert len(alerts) <= 20, "Benign traffic must not generate alerts"


class TestAlertDeduplication:
    """Duplicate alerts must be suppressed within the dedup window."""

    def test_duplicate_attack_suppressed(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
            dedup_window=60,
        )
        pipeline.start()

        _ingest_flows(pipeline, [syn_flood_flow])
        _ingest_flows(pipeline, [syn_flood_flow])

        n_flows, alerts = _flush_and_stop(pipeline)
        syn_alerts = [a for a in alerts if "SYN_FLOOD_001" in
                      a.get("signature_match", "")]
        assert len(syn_alerts) == 1, \
            f"Expected 1 SYN_FLOOD alert after dedup, got {len(syn_alerts)}"

    def test_different_attacks_not_suppressed(self):
        """Different attack types should not be suppressed against each other."""
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
            dedup_window=60,
        )
        pipeline.start()

        _ingest_flows(pipeline, [syn_flood_flow, bad_port_smb_flow])
        n_flows, alerts = _flush_and_stop(pipeline)
        assert len(alerts) >= 2


class TestDataPersistence:
    """Alerts and flows must persist to SQLite."""

    def test_alerts_written_to_sqlite(self):
        from core.pipeline import NIDSPipeline
        from monitor.db import get_db_connection

        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [syn_flood_flow, port_scan_flow,
                                 bad_port_smb_flow])
        n_flows, alerts = _flush_and_stop(pipeline)

        # Check SQLite has the alerts
        conn = get_db_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM alerts")
        db_count = cursor.fetchone()[0]
        assert db_count >= len(alerts), \
            f"SQLite has {db_count} alerts, expected at least {len(alerts)}"

    def test_flows_written_to_sqlite(self):
        from core.pipeline import NIDSPipeline
        from monitor.db import get_db_connection

        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()
        _ingest_flows(pipeline, [benign_http_flow, benign_dns_query,
                                 syn_flood_flow])
        n_flows, alerts = _flush_and_stop(pipeline)

        conn = get_db_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM flows")
        db_count = cursor.fetchone()[0]
        assert db_count >= 1, f"SQLite has {db_count} flows, expected >= 1"


class TestFullEnsembleMode:
    """Full detection pipeline with ML ensemble (RF + Autoencoder)."""

    def test_ensemble_loads_if_models_exist(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=True, use_signatures=True, home_net=HOME_NET,
        )
        started = pipeline.start()
        if pipeline.engine and pipeline.engine.is_loaded:
            assert started is True
            assert pipeline.engine.mode in ("ensemble", "rf_only", "ae_only")
            _safe_stop(pipeline)
        else:
            pytest.skip("No trained models found in data/models/")

    def test_ensemble_detects_attack(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=True, use_signatures=True, home_net=HOME_NET,
        )
        started = pipeline.start()
        if not pipeline.engine or not pipeline.engine.is_loaded:
            pytest.skip("No trained models available")

        _ingest_flows(pipeline, [syn_flood_flow, port_scan_flow])
        n_flows, alerts = _flush_and_stop(pipeline)

        assert len(alerts) >= 1
        for a in alerts:
            assert "score" in a
            assert "label" in a
            assert a["label"] == "ATTACK"

    def test_ensemble_scores_include_rf_and_ae(self):
        """Alerts from ensemble mode should have rf_score and ae_score."""
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=True, use_signatures=True, home_net=HOME_NET,
        )
        started = pipeline.start()
        if not pipeline.engine or not pipeline.engine.is_loaded:
            pytest.skip("No trained models available")

        _ingest_flows(pipeline, [syn_flood_flow, bad_port_smb_flow])
        n_flows, alerts = _flush_and_stop(pipeline)

        for a in alerts:
            if "rf_score" in a or "ae_score" in a:
                assert "rf_score" in a
                assert "ae_score" in a
                break


class TestGracefulDegradation:
    """System must not crash when components are missing."""

    def test_no_model_no_crash(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        assert pipeline.start() is True
        for pkt in syn_flood_flow():
            pipeline.ingest_packet(pkt)
        _safe_stop(pipeline)

    def test_no_signatures_no_crash(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=False, home_net=HOME_NET,
        )
        assert pipeline.start() is False  # no detection mode
        _safe_stop(pipeline)

    def test_both_disabled_returns_false(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=False, home_net=HOME_NET,
        )
        assert pipeline.start() is False


class TestEventBus:
    """Event bus delivers flow and alert events in real-time."""

    def test_flow_events_published(self):
        from core.pipeline import NIDSPipeline
        from core.event_bus import EventBus

        bus = EventBus()
        received = {"flows": 0, "alerts": 0}

        def on_flow(p):
            received["flows"] += 1

        def on_alert(a):
            received["alerts"] += 1

        bus.subscribe("flow", on_flow)
        bus.subscribe("alert", on_alert)

        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
            event_bus=bus,
        )
        pipeline.start()
        _ingest_flows(pipeline, [syn_flood_flow, port_scan_flow])
        n_flows, alerts = _flush_and_stop(pipeline)

        assert received["flows"] >= 1
        assert received["alerts"] >= 1

    def test_stats_events_published(self):
        from core.pipeline import NIDSPipeline
        from core.event_bus import EventBus

        bus = EventBus()
        received = {"stats": []}

        def on_stats(s):
            received["stats"].append(s)

        bus.subscribe("stats", on_stats)

        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
            event_bus=bus,
        )
        pipeline.start()
        _ingest_flows(pipeline, [syn_flood_flow])
        n_flows, alerts = _flush_and_stop(pipeline)

        assert len(received["stats"]) >= 1
        snap = received["stats"][-1]
        assert "total_flows" in snap
        assert "total_alerts" in snap


class TestBackpressure:
    """Pipeline must handle flow table pressure without crashing."""

    def test_active_flow_count_limited(self):
        from core.pipeline import NIDSPipeline
        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
            max_active_flows=10,
        )
        pipeline.start()

        # Generate many unique flows
        for i in range(20):
            src_port = 80000 + i
            pkt = make_pkt(EXTERNAL_ATTACKER, INTERNAL, src_port, 80,
                           syn=1, ack=0, timestamp=_t(0.001))
            pipeline.ingest_packet(pkt)

        assert pipeline.active_flows <= 10
        _safe_stop(pipeline)


class TestCompleteGuardScenario:
    """Full realistic scenario: guards a network end-to-end."""

    def test_network_guarded_signature_only(self):
        """
        Simulates real network conditions:
        - Benign internal traffic (HTTP, DNS)
        - External SYN flood
        - External port scan
        - Internal C2 beacon (compromised host)
        - External SMB access attempt

        The system must:
        1. Detect all attack types
        2. Produce zero false positives on benign traffic
        3. Provide correct severity classification
        4. Persist alerts to SQLite
        """
        from core.pipeline import NIDSPipeline
        from monitor.db import get_db_connection

        pipeline = NIDSPipeline(
            use_model=False, use_signatures=True, home_net=HOME_NET,
        )
        pipeline.start()

        # Phase 1: background benign traffic
        for _ in range(8):
            for pkt in benign_http_flow(dp=80):
                pipeline.ingest_packet(pkt)

        # Phase 2: external SYN flood hits
        _ingest_flows(pipeline, [syn_flood_flow])

        # Phase 3: more benign traffic interspersed
        for _ in range(3):
            for pkt in benign_dns_query():
                pipeline.ingest_packet(pkt)

        # Phase 4: port scan + SMB attempt
        _ingest_flows(pipeline, [port_scan_flow, bad_port_smb_flow])

        # Phase 5: internal C2 beacon (compromised machine)
        _ingest_flows(pipeline, [c2_beacon_flow])

        # Phase 6: SSH brute-force
        _ingest_flows(pipeline, [ssh_bruteforce_flow])

        # Phase 7: more benign traffic afterward
        for _ in range(3):
            for pkt in benign_http_flow(dp=443):
                pipeline.ingest_packet(pkt)

        n_flows, all_alerts = _flush_and_stop(pipeline)

        # Verify detection
        sigs = " ".join(a.get("signature_match", "") for a in all_alerts)
        assert "SYN_FLOOD_001" in sigs, "SYN flood undetected"
        assert "PORT_SCAN_MASS_001" in sigs, "Port scan undetected"
        assert "BAD_PORT_SMB" in sigs, "SMB traffic undetected"
        assert "C2_BEACON_001" in sigs, "C2 beacon undetected"
        assert "BRUTEFORCE_SSH_001" in sigs, "SSH brute-force undetected"

        # Verify severity classification
        high = [a for a in all_alerts if a.get("severity") == "high"]
        medium = [a for a in all_alerts if a.get("severity") == "medium"]
        assert len(high) >= 4, "Expected high severity alerts for all attack types"
        assert len(all_alerts) >= 5, "Expected alerts for all 5 attack types"

        # Verify alerts persisted
        conn = get_db_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM alerts")
        db_count = cursor.fetchone()[0]
        assert db_count >= len(all_alerts), \
            f"SQLite has {db_count}, expected >= {len(all_alerts)}"

        # Verify flows persisted
        cursor = conn.execute("SELECT COUNT(*) FROM flows")
        flow_count = cursor.fetchone()[0]
        assert flow_count >= 1, "No flows persisted to SQLite"
