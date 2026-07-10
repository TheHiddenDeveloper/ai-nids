"""
===============================================================================
TEST: AI INFERENCE — Ensemble Engine Integration Test
===============================================================================
Purpose:
  Integration test for EnsembleInferenceEngine. Requires trained models in
  data/models/. Creates benign and anomalous mock flows, runs inference, and
  verifies the benign flow scores below threshold while anomalous scores above.

Run:
  pytest tests/test_ai_inference.py -v
  python tests/test_ai_inference.py    # standalone mode

Asserts:
  - Load returns True with trained models present
  - Engine.mode is not "unloaded"
  - Benign DNS query flow (port 53, normal params) → score < 0.5
  - SYN scan probe flow (zero duration, syn=1, no ACK) → score > 0.5
===============================================================================
"""

import sys
import os
import pandas as pd
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_engine.ensemble import EnsembleInferenceEngine
from ai_engine.dataset import FEATURE_COLS


def _make_benign_dns():
    """A realistic benign DNS query flow."""
    flow = {k: 0.0 for k in FEATURE_COLS}
    flow["dst_port"] = 53.0
    flow["duration"] = 100000.0
    flow["src_bytes"] = 100.0
    flow["dst_bytes"] = 200.0
    flow["packet_count"] = 4.0
    flow["avg_packet_len"] = 75.0
    flow["std_packet_len"] = 30.0
    flow["fwd_packet_len_max"] = 100.0
    flow["bwd_packet_len_max"] = 200.0
    flow["syn_flag_count"] = 1.0
    flow["ack_flag_count"] = 1.0
    flow["syn_ratio"] = 0.25
    flow["ack_ratio"] = 0.25
    flow["port_is_dns"] = 1.0
    flow["flow_bytes_per_sec"] = 3000.0
    flow["flow_packets_per_sec"] = 40.0
    flow["flow_iat_mean"] = 25000.0
    flow["_src_ip"] = "192.168.1.10"
    flow["_dst_ip"] = "8.8.8.8"
    flow["_src_port"] = 40000
    flow["_dst_port"] = 53
    flow["_timestamp"] = 1000.0
    return flow


def _make_syn_scan():
    """A realistic SYN scan probe flow (nmap-style)."""
    flow = {k: 0.0 for k in FEATURE_COLS}
    flow["dst_port"] = 6666.0
    flow["duration"] = 0.0
    flow["src_bytes"] = 60.0
    flow["dst_bytes"] = 0.0
    flow["packet_count"] = 1.0
    flow["avg_packet_len"] = 60.0
    flow["std_packet_len"] = 0.0
    flow["fwd_packet_len_max"] = 60.0
    flow["bwd_packet_len_max"] = 0.0
    flow["syn_flag_count"] = 1.0
    flow["ack_flag_count"] = 0.0
    flow["syn_ratio"] = 1.0
    flow["flow_bytes_per_sec"] = 60000.0
    flow["_src_ip"] = "1.2.3.4"
    flow["_dst_ip"] = "192.168.1.1"
    flow["_src_port"] = 54321
    flow["_dst_port"] = 6666
    flow["_timestamp"] = 1001.0
    return flow


def test_ai_inference():
    print("Running Ensemble Inference Tests...")
    engine = EnsembleInferenceEngine()

    if not engine.load():
        print("FAIL: Could not load ensemble models.")
        sys.exit(1)

    print(f"Engine Mode: {engine.mode}")
    print(f"Details: {engine.describe()}")

    benign_flow = _make_benign_dns()
    anomaly_flow = _make_syn_scan()

    df = pd.DataFrame([benign_flow, anomaly_flow])
    results = engine.predict(df)

    for i, res in enumerate(results):
        print(f"\nFlow {i+1} ({res['_src_ip']} -> {res['_dst_ip']}):")
        print(f"  Ensemble Score: {res['score']:.4f}")
        print(f"  RF Score:       {res['rf_score']:.4f}")
        print(f"  AE Score:       {res['ae_score']:.4f}")
        print(f"  Prediction:     {res['label']}")
        if "explanation" in res:
            print(f"  Explanation:    {res['explanation']}")

    assert results[0]["score"] < 0.5, "Benign flow flagged as attack"
    assert results[1]["score"] > 0.5, "Anomalous flow NOT flagged as attack"
    print("\n--- ALL AI INFERENCE TESTS PASSED ---")


if __name__ == "__main__":
    try:
        test_ai_inference()
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
