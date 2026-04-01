"""
Unit Tests — FlowAggregator
"""

import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from monitor.flow_aggregator import FlowAggregator, Flow


def make_pkt(
    src="1.2.3.4", dst="5.6.7.8",
    src_port=12345, dst_port=80,
    proto=6, length=100,
    syn=1, ack=0, fin=0, rst=0, psh=0,
):
    return {
        "timestamp": time.time(),
        "src_ip": src, "dst_ip": dst,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": proto, "ip_len": length,
        "syn": syn, "ack": ack, "fin": fin, "rst": rst, "psh": psh, "urg": 0,
    }


class TestFlowCreation:
    def test_single_packet_creates_flow(self):
        agg = FlowAggregator(flow_timeout=60)
        agg.ingest(make_pkt())
        assert agg.active_flow_count == 1

    def test_two_distinct_flows(self):
        agg = FlowAggregator(flow_timeout=60)
        agg.ingest(make_pkt(src="1.1.1.1", dst="2.2.2.2", dst_port=80))
        agg.ingest(make_pkt(src="3.3.3.3", dst="4.4.4.4", dst_port=443))
        assert agg.active_flow_count == 2

    def test_bidirectional_keying(self):
        """Forward and reverse packets belong to same flow."""
        agg = FlowAggregator(flow_timeout=60)
        agg.ingest(make_pkt(src="1.1.1.1", dst="2.2.2.2", src_port=54321, dst_port=80))
        agg.ingest(make_pkt(src="2.2.2.2", dst="1.1.1.1", src_port=80, dst_port=54321))
        assert agg.active_flow_count == 1


class TestFlushAndFeatures:
    def test_flush_returns_features(self):
        agg = FlowAggregator(flow_timeout=60)
        for _ in range(5):
            agg.ingest(make_pkt())
        completed = agg.flush_all()
        assert len(completed) == 1
        assert completed[0]["packet_count"] == 5

    def test_flush_clears_flows(self):
        agg = FlowAggregator(flow_timeout=60)
        agg.ingest(make_pkt())
        agg.flush_all()
        assert agg.active_flow_count == 0

    def test_single_packet_flow_not_returned(self):
        """Flows with < 2 packets produce no features."""
        agg = FlowAggregator(flow_timeout=60)
        agg.ingest(make_pkt())
        completed = agg.flush_all()
        assert len(completed) == 0


class TestFeatureValues:
    def _build_flow_features(self, n=4):
        agg = FlowAggregator(flow_timeout=60)
        for i in range(n):
            agg.ingest(make_pkt(length=100 + i * 10, syn=1, ack=i))
        return agg.flush_all()[0]

    def test_packet_count(self):
        f = self._build_flow_features(n=4)
        assert f["packet_count"] == 4

    def test_syn_flag_count(self):
        f = self._build_flow_features(n=4)
        assert f["syn_flag_count"] == 4

    def test_avg_packet_len_positive(self):
        f = self._build_flow_features(n=4)
        assert f["avg_packet_len"] > 0

    def test_flow_rate_positive(self):
        f = self._build_flow_features(n=4)
        assert f["flow_bytes_per_sec"] > 0
        assert f["flow_packets_per_sec"] > 0

    def test_metadata_present(self):
        f = self._build_flow_features(n=4)
        assert "_src_ip" in f
        assert "_dst_ip" in f
        assert "_timestamp" in f
