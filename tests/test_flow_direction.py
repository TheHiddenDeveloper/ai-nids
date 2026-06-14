"""
Unit Tests — Flow direction correction & IAT re-orientation bug regression.
"""

import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from monitor.flow_aggregator import FlowAggregator


def _pkt(
    src="1.2.3.4", dst="5.6.7.8",
    src_port=12345, dst_port=80,
    proto=6, length=100,
    syn=0, ack=0, fin=0, rst=0, psh=0,
    ts=None,
):
    return {
        "timestamp": ts or time.time(),
        "src_ip": src, "dst_ip": dst,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": proto, "ip_len": length,
        "syn": syn, "ack": ack, "fin": fin, "rst": rst, "psh": psh, "urg": 0,
    }


class TestDirectionCorrection:
    def test_direction_correction(self):
        agg = FlowAggregator()

        # Response packet seen FIRST
        agg.ingest(_pkt(
            src="192.168.1.10", dst="8.8.8.8",
            src_port=443, dst_port=54321,
            ack=1, length=100, ts=1000.0,
        ))

        # SYN packet seen SECOND (triggers re-orientation)
        agg.ingest(_pkt(
            src="8.8.8.8", dst="192.168.1.10",
            src_port=54321, dst_port=443,
            syn=1, length=60, ts=1000.1,
        ))

        flows = agg.flush_all()
        assert len(flows) == 1
        f = flows[0]

        assert f["_src_ip"] == "8.8.8.8"
        assert f["_dst_ip"] == "192.168.1.10"
        assert f["src_bytes"] == 60
        assert f["dst_bytes"] == 100
        assert f["fwd_packet_count"] == 1
        assert f["bwd_packet_count"] == 1

    def test_iat_reset_on_reorientation(self):
        """
        Regression test: IAT accumulators must reset when flow direction
        is re-oriented. Values collected with wrong-direction packets
        would produce corrupted statistics.
        """
        agg = FlowAggregator()

        # 3 packets in wrong direction (response first)
        agg.ingest(_pkt(
            src="192.168.1.10", dst="8.8.8.8",
            src_port=443, dst_port=54321,
            ack=1, ts=1000.0,
        ))
        agg.ingest(_pkt(
            src="192.168.1.10", dst="8.8.8.8",
            src_port=443, dst_port=54321,
            ack=1, ts=1000.05,
        ))
        agg.ingest(_pkt(
            src="192.168.1.10", dst="8.8.8.8",
            src_port=443, dst_port=54321,
            ack=1, ts=1000.09,
        ))

        # SYN packet triggers re-orientation
        agg.ingest(_pkt(
            src="8.8.8.8", dst="192.168.1.10",
            src_port=54321, dst_port=443,
            syn=1, ts=1000.1,
        ))

        # 3 post-reorientation packets with known IAT
        agg.ingest(_pkt(
            src="8.8.8.8", dst="192.168.1.10",
            src_port=54321, dst_port=443,
            ack=1, ts=1000.2,
        ))
        agg.ingest(_pkt(
            src="8.8.8.8", dst="192.168.1.10",
            src_port=54321, dst_port=443,
            ack=1, ts=1000.3,
        ))
        agg.ingest(_pkt(
            src="8.8.8.8", dst="192.168.1.10",
            src_port=54321, dst_port=443,
            ack=1, ts=1000.6,
        ))

        flows = agg.flush_all()
        assert len(flows) == 1
        f = flows[0]

        # 7 total packets (3 wrong-dir + 1 re-orient + 3 post-reorient)
        assert f["packet_count"] == 7

        # IAT should reflect only the 3 post-reorientation gaps:
        #   re-orient (ts=1000.1) → ack (ts=1000.2): 0.1s
        #   ack (ts=1000.2) → ack (ts=1000.3):        0.1s
        #   ack (ts=1000.3) → ack (ts=1000.6):        0.3s
        # Sum = 0.5 (not polluted by pre-reorient IAT values)
        # _iat_count = 3, flow_iat_mean = 0.5 / 3 ≈ 0.1667
        assert f["flow_iat_mean"] == pytest.approx(0.5 / 3, rel=0.01)
        assert f["flow_iat_max"] == pytest.approx(0.3, rel=0.01)
        assert f["flow_iat_min"] == pytest.approx(0.1, rel=0.01)


if __name__ == "__main__":
    pytest.main([__file__])
