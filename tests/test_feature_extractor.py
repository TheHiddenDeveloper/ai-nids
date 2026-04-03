"""
Unit Tests — FeatureExtractor
"""

import sys
import time
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from monitor.feature_extractor import FeatureExtractor, FEATURE_COLS


def make_flow(
    dst_port=80, duration=1.5, packet_count=10,
    src_bytes=1500, dst_bytes=800,
    avg_packet_len=150.0, std_packet_len=20.0,
    flow_bytes_per_sec=1000.0, flow_packets_per_sec=6.6,
    fwd_packet_len_max=300.0, bwd_packet_len_max=200.0,
    fin_flag_count=1, syn_flag_count=1,
    rst_flag_count=0, psh_flag_count=2, ack_flag_count=8,
    src_ip="1.2.3.4", dst_ip="5.6.7.8",
    src_port=54321,
):
    return {
        "dst_port": dst_port,
        "duration": duration,
        "packet_count": packet_count,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "avg_packet_len": avg_packet_len,
        "std_packet_len": std_packet_len,
        "flow_bytes_per_sec": flow_bytes_per_sec,
        "flow_packets_per_sec": flow_packets_per_sec,
        "fwd_packet_len_max": fwd_packet_len_max,
        "bwd_packet_len_max": bwd_packet_len_max,
        "fin_flag_count": fin_flag_count,
        "syn_flag_count": syn_flag_count,
        "rst_flag_count": rst_flag_count,
        "psh_flag_count": psh_flag_count,
        "ack_flag_count": ack_flag_count,
        "_src_ip": src_ip,
        "_dst_ip": dst_ip,
        "_src_port": src_port,
        "_dst_port": dst_port,
        "_timestamp": time.time(),
    }


class TestFeatureExtractor:
    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_returns_none_for_empty(self):
        assert self.extractor.transform([]) is None

    def test_returns_dataframe(self):
        df = self.extractor.transform([make_flow()])
        assert df is not None
        assert len(df) == 1

    def test_all_feature_cols_present(self):
        df = self.extractor.transform([make_flow()])
        for col in FEATURE_COLS:
            assert col in df.columns, f"Missing column: {col}"

    def test_metadata_preserved(self):
        df = self.extractor.transform([make_flow(src_ip="9.9.9.9")])
        assert df["_src_ip"].iloc[0] == "9.9.9.9"

    def test_handles_inf_values(self):
        flow = make_flow(flow_bytes_per_sec=float("inf"))
        df = self.extractor.transform([flow])
        assert df["flow_bytes_per_sec"].iloc[0] == 0.0

    def test_handles_nan_values(self):
        flow = make_flow(avg_packet_len=float("nan"))
        df = self.extractor.transform([flow])
        assert df["avg_packet_len"].iloc[0] == 0.0

    def test_clips_extreme_rates(self):
        flow = make_flow(flow_bytes_per_sec=1e12)
        df = self.extractor.transform([flow])
        assert df["flow_bytes_per_sec"].iloc[0] <= 1e9

    def test_to_numpy_shape(self):
        flows = [make_flow() for _ in range(5)]
        df = self.extractor.transform(flows)
        arr = self.extractor.to_numpy(df)
        assert arr.shape == (5, len(FEATURE_COLS))
        assert arr.dtype == np.float32

    def test_missing_feature_filled_with_zero(self):
        flow = make_flow()
        del flow["rst_flag_count"]
        df = self.extractor.transform([flow])
        assert "rst_flag_count" in df.columns
        assert df["rst_flag_count"].iloc[0] == 0

    def test_batch_transform(self):
        flows = [make_flow(packet_count=i + 2) for i in range(10)]
        df = self.extractor.transform(flows)
        assert len(df) == 10
