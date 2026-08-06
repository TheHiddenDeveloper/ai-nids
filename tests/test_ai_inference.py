"""
===============================================================================
TEST: AI INFERENCE — Ensemble Engine Integration Test
===============================================================================
Purpose:
  Integration test for EnsembleInferenceEngine. Requires trained models in
  data/models/. Creates benign + attack mock flows and verifies the ensemble
  correctly distinguishes attacks from benign traffic.

Run:
  pytest tests/test_ai_inference.py -v
  python tests/test_ai_inference.py    # standalone mode

Asserts:
  - Load returns True with trained models present
  - Engine.mode is not "unloaded"
  - Benign DNS query flow (port 53, normal params) → score < 0.5
  - DDoS attack flow (high volume, SYN flood) → score > 0.5
  - SYN scan flow (single probe) → ensemble rank above benign
  - AE anomaly score for SYN scan > AE score for benign (AE sees novel patterns)
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
    flow["duration"] = 0.1
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
    flow["flow_bytes_per_sec"] = 3000.0
    flow["flow_packets_per_sec"] = 40.0
    flow["flow_iat_mean"] = 0.025
    flow["port_is_dns"] = 1.0
    flow["_src_ip"] = "192.168.1.10"
    flow["_dst_ip"] = "8.8.8.8"
    flow["_src_port"] = 40000
    flow["_dst_port"] = 53
    flow["_timestamp"] = 1000.0
    return flow


def _make_ddos_attack_cicids():
    """An HTTP-based DDoS flow matching real CICIDS2017 attack distributions.

    Actual CICIDS2017 DDoS/Web attack flows are HTTP POST floods: few packets
    (~10), large backward bytes (server responses), long duration, ~0 SYN ratio.
    Values sampled from real holdout rows the RF flags with p(attack)≈0.995.
    """
    flow = {k: 0.0 for k in FEATURE_COLS}
    flow["dst_port"] = 80.0
    flow["duration"] = 0.4686
    flow["src_bytes"] = 328.0
    flow["dst_bytes"] = 11595.0
    flow["packet_count"] = 12.0
    flow["avg_packet_len"] = 917.6154
    flow["std_packet_len"] = 1813.715
    flow["fwd_packet_len_max"] = 316.0
    flow["bwd_packet_len_max"] = 5792.0
    flow["fin_flag_count"] = 1.0
    flow["ack_flag_count"] = 1.0
    flow["fin_ratio"] = 0.083333
    flow["flow_bytes_per_sec"] = 120.8174
    flow["flow_packets_per_sec"] = 0.121598
    flow["flow_iat_mean"] = 8.971466
    flow["flow_iat_std"] = 29.7
    flow["flow_iat_max"] = 98.7
    flow["flow_iat_min"] = 0.000006
    flow["port_is_web"] = 1.0
    flow["_src_ip"] = "10.0.0.50"
    flow["_dst_ip"] = "192.168.1.1"
    flow["_src_port"] = 40001
    flow["_dst_port"] = 80
    flow["_timestamp"] = 1002.0
    return flow


def _make_syn_scan():
    """A stealthy SYN scan probe (single SYN, no response).

    Values mirror monitor/flow_aggregator.to_features() for a single-packet
    flow (duration clamps to 1e-6). FV4 probe flags (is_syn_probe etc.) are
    set via the shared compute_probe_features helper so they match what
    production feature extraction produces.
    """
    from core.features import compute_probe_features
    flow = {k: 0.0 for k in FEATURE_COLS}
    flow["dst_port"] = 6666.0
    flow["duration"] = 1e-6
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
    flow["ack_ratio"] = 0.0
    flow["flow_bytes_per_sec"] = 60.0 / 1e-6
    flow["flow_packets_per_sec"] = 1.0 / 1e-6
    flow.update(compute_probe_features(flow))
    flow["_src_ip"] = "1.2.3.4"
    flow["_dst_ip"] = "192.168.1.1"
    flow["_src_port"] = 54321
    flow["_dst_port"] = 6666
    flow["_timestamp"] = 1001.0
    return flow


def _make_syn_flood():
    """A raw TCP SYN flood against a live host (each SYN gets a SYN-ACK).

    CICIDS2017's DDoS class is HTTP-POST-flood shaped, so raw SYN floods
    (high SYN ratio, small packets, high packet rate) are a blind spot the
    FV5 flood features must close. Values mirror flow_aggregator.to_features()
    for a 100-SYN flood with replies.
    """
    from core.features import compute_flood_features
    n = 100
    flow = {k: 0.0 for k in FEATURE_COLS}
    flow["dst_port"] = 80.0
    flow["duration"] = 1.0
    flow["src_bytes"] = float(n * 54)
    flow["dst_bytes"] = float(n * 60)
    flow["packet_count"] = float(2 * n)
    flow["fwd_packet_count"] = float(n)
    flow["bwd_packet_count"] = float(n)
    flow["avg_packet_len"] = 57.0
    flow["std_packet_len"] = 3.0
    flow["fwd_packet_len_max"] = 54.0
    flow["bwd_packet_len_max"] = 60.0
    flow["syn_flag_count"] = float(n)
    flow["ack_flag_count"] = float(n)
    flow["syn_ratio"] = float(n) / float(2 * n)
    flow["ack_ratio"] = float(n) / float(2 * n)
    flow["flow_bytes_per_sec"] = float(n * (54 + 60)) / 1.0
    flow["flow_packets_per_sec"] = float(2 * n) / 1.0
    flow["flow_iat_mean"] = 0.001
    flow["flow_iat_std"] = 0.0005
    flow["flow_iat_max"] = 0.005
    flow["flow_iat_min"] = 0.0002
    flow.update(compute_flood_features(flow))
    flow["_src_ip"] = "10.0.0.77"
    flow["_dst_ip"] = "192.168.1.1"
    flow["_src_port"] = 40002
    flow["_dst_port"] = 80
    flow["_timestamp"] = 1003.0
    return flow


def test_ai_inference():
    print("Running Ensemble Inference Tests...")
    engine = EnsembleInferenceEngine()

    if not engine.load():
        print("FAIL: Could not load ensemble models.")
        sys.exit(1)

    print(f"Engine Mode: {engine.mode}")
    print(f"Details: {engine.describe()}")

    benign = _make_benign_dns()
    ddos = _make_ddos_attack_cicids()
    syn_scan = _make_syn_scan()
    syn_flood = _make_syn_flood()

    df = pd.DataFrame([benign, ddos, syn_scan, syn_flood])
    results = engine.predict(df)

    for i, res in enumerate(results):
        labels = ["Benign DNS", "DDoS Flood", "SYN Scan", "SYN Flood"]
        print(f"\n{labels[i]} ({res['_src_ip']} → {res['_dst_ip']}):")
        print(f"  Ensemble: {res['score']:.4f}  RF: {res['rf_score']:.4f}  AE: {res['ae_score']:.4f}  → {res['label']}")
        if "explanation" in res:
            print(f"  Driven by: {res['explanation']['driver']}")
            top = res['explanation']['features'][0]
            print(f"  Top feature: {top['name']} ({top['score']:.4f})")

    assert results[0]["score"] < 0.5, "Benign flow flagged as attack"
    assert results[1]["score"] > 0.5, "DDoS attack NOT flagged (score {results[1]['score']:.3f})"
    assert results[2]["ae_score"] > results[0]["ae_score"], \
        "SYN scan AE score not above benign baseline"
    assert results[2]["score"] > 0.5, \
        "SYN scan probe NOT flagged as attack (score {results[2]['score']:.3f})"
    assert results[2]["rf_score"] > 0.5, \
        "RF does not flag single-packet SYN probe (rf {results[2]['rf_score']:.3f})"
    assert results[3]["score"] > 0.85, \
        "Responded SYN flood NOT flagged with high confidence (score {results[3]['score']:.3f})"
    assert results[3]["rf_score"] > 0.8, \
        "RF does not flag raw SYN flood (rf {results[3]['rf_score']:.3f})"

    print("\n--- ALL AI INFERENCE TESTS PASSED ---")


if __name__ == "__main__":
    try:
        test_ai_inference()
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
