"""
Unit Tests — core/ components
Tests EventBus, AlertDeduplicator, StatsTracker
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.event_bus import EventBus
from core.deduplicator import AlertDeduplicator
from core.stats_tracker import StatsTracker


def make_alert(src="1.2.3.4", dst="5.6.7.8", port=80, label="ATTACK", score=0.9, sev="high"):
    return {
        "_src_ip": src, "_dst_ip": dst, "_dst_port": port,
        "label": label, "score": score, "severity": sev,
    }


# ── EventBus ──────────────────────────────────────────────────────────────────

class TestEventBus:
    def test_subscribe_and_publish(self):
        bus = EventBus()
        received = []
        bus.subscribe("alert", lambda p: received.append(p))
        bus.publish("alert", {"score": 0.9})
        assert len(received) == 1
        assert received[0]["score"] == 0.9

    def test_multiple_subscribers(self):
        bus = EventBus()
        log1, log2 = [], []
        bus.subscribe("flow", lambda p: log1.append(p))
        bus.subscribe("flow", lambda p: log2.append(p))
        bus.publish("flow", {"x": 1})
        assert len(log1) == 1
        assert len(log2) == 1

    def test_unknown_topic_dropped(self):
        bus = EventBus()
        bus.publish("nonexistent_topic", {"x": 1})  # should not raise

    def test_handler_exception_does_not_crash_bus(self):
        bus = EventBus()
        good = []
        bus.subscribe("alert", lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
        bus.subscribe("alert", lambda p: good.append(p))
        bus.publish("alert", {"score": 0.9})
        assert len(good) == 1

    def test_subscriber_count(self):
        bus = EventBus()
        assert bus.subscriber_count("alert") == 0
        bus.subscribe("alert", lambda p: None)
        assert bus.subscriber_count("alert") == 1


# ── AlertDeduplicator ─────────────────────────────────────────────────────────

class TestAlertDeduplicator:
    def test_first_alert_fires(self):
        dedup = AlertDeduplicator(suppress_window_secs=60)
        assert dedup.should_fire(make_alert()) is True

    def test_duplicate_within_window_suppressed(self):
        dedup = AlertDeduplicator(suppress_window_secs=60)
        alert = make_alert()
        assert dedup.should_fire(alert) is True
        assert dedup.should_fire(alert) is False

    def test_different_src_not_suppressed(self):
        dedup = AlertDeduplicator(suppress_window_secs=60)
        assert dedup.should_fire(make_alert(src="1.1.1.1")) is True
        assert dedup.should_fire(make_alert(src="2.2.2.2")) is True

    def test_different_dst_port_not_suppressed(self):
        dedup = AlertDeduplicator(suppress_window_secs=60)
        assert dedup.should_fire(make_alert(port=80))  is True
        assert dedup.should_fire(make_alert(port=443)) is True

    def test_suppression_count_increments(self):
        dedup = AlertDeduplicator(suppress_window_secs=60)
        a = make_alert()
        dedup.should_fire(a)
        dedup.should_fire(a)
        dedup.should_fire(a)
        note = dedup.suppression_note(a)
        assert note is not None
        assert "2" in note

    def test_eviction_removes_old_keys(self):
        dedup = AlertDeduplicator(suppress_window_secs=1)
        dedup.should_fire(make_alert())
        assert dedup.active_keys == 1
        time.sleep(2.1)
        evicted = dedup.evict_expired()
        assert evicted == 1
        assert dedup.active_keys == 0

    def test_after_window_expires_refires(self):
        dedup = AlertDeduplicator(suppress_window_secs=1)
        a = make_alert()
        assert dedup.should_fire(a) is True
        time.sleep(1.1)
        assert dedup.should_fire(a) is True


# ── StatsTracker ──────────────────────────────────────────────────────────────

class TestStatsTracker:
    def test_initial_snapshot_zeroed(self):
        st = StatsTracker()
        snap = st.snapshot()
        assert snap["total_flows"]   == 0
        assert snap["total_alerts"]  == 0
        assert snap["total_packets"] == 0

    def test_record_packet(self):
        st = StatsTracker()
        st.record_packet()
        st.record_packet()
        assert st.snapshot()["total_packets"] == 2

    def test_record_flow(self):
        st = StatsTracker()
        st.record_flow({"protocol_type": 6})
        st.record_flow({"protocol_type": 17})
        snap = st.snapshot()
        assert snap["total_flows"] == 2
        assert snap["protocol_counts"][6]  == 1
        assert snap["protocol_counts"][17] == 1

    def test_record_alert_updates_distributions(self):
        st = StatsTracker()
        st.record_alert(make_alert(src="10.0.0.1", sev="high", score=0.95))
        st.record_alert(make_alert(src="10.0.0.1", sev="medium", score=0.82))
        snap = st.snapshot()
        assert snap["total_alerts"] == 2
        assert snap["severity_counts"]["high"]   == 1
        assert snap["severity_counts"]["medium"] == 1
        assert snap["top_src_ips"][0][0] == "10.0.0.1"
        assert snap["top_src_ips"][0][1] == 2

    def test_attack_rate_calculation(self):
        st = StatsTracker()
        for _ in range(90):
            st.record_flow({"protocol_type": 6})
        for _ in range(10):
            st.record_alert(make_alert())
        snap = st.snapshot()
        assert abs(snap["attack_rate_pct"] - 11.11) < 1.0

    def test_score_mean(self):
        st = StatsTracker()
        for s in [0.5, 0.6, 0.7, 0.8, 0.9]:
            st.record_alert({**make_alert(), "score": s})
        snap = st.snapshot()
        assert abs(snap["score_mean"] - 0.7) < 0.01

    def test_rolling_window_prunes_old_events(self):
        st = StatsTracker(window_secs=1)
        st.record_flow({"protocol_type": 6})
        time.sleep(1.1)
        snap = st.snapshot()
        assert snap["flows_in_window"] == 0
        assert snap["total_flows"] == 1  # cumulative never resets
