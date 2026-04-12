import sys
import os
import pandas as pd
import numpy as np
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_engine.ensemble import EnsembleInferenceEngine
from ai_engine.dataset import FEATURE_COLS

def test_ai_inference():
    print("Running Ensemble Inference Tests...")
    engine = EnsembleInferenceEngine()
    
    if not engine.load():
        print("FAIL: Could not load ensemble models.")
        sys.exit(1)
        
    print(f"Engine Mode: {engine.mode}")
    print(f"Details: {engine.describe()}")

    # 1. Create a "Benign" Mock Flow
    benign_flow = {k: 0.1 for k in FEATURE_COLS}
    benign_flow["dst_port"] = 443
    benign_flow["duration"] = 1.0
    benign_flow["packet_count"] = 5
    benign_flow["_src_ip"] = "192.168.1.10"
    benign_flow["_dst_ip"] = "8.8.8.8"
    
    # 2. Create an "Anomalous" Mock Flow (High bytes per sec, weird port)
    anomaly_flow = {k: 5.0 for k in FEATURE_COLS}
    anomaly_flow["dst_port"] = 6666
    anomaly_flow["duration"] = 0.001
    anomaly_flow["flow_bytes_per_sec"] = 1000000.0
    anomaly_flow["syn_flag_count"] = 10
    anomaly_flow["_src_ip"] = "1.2.3.4"
    anomaly_flow["_dst_ip"] = "192.168.1.1"

    df = pd.DataFrame([benign_flow, anomaly_flow])
    results = engine.predict(df)
    
    for i, res in enumerate(results):
        print(f"\nFlow {i+1} ({res['_src_ip']} -> {res['_dst_ip']}):")
        print(f"  Ensemble Score: {res['score']:.4f}")
        print(f"  RF Score:       {res['rf_score']:.4f}")
        print(f"  AE Score:       {res['ae_score']:.4f}")
        print(f"  Prediction:     {res['label']}")

    # Assertions
    assert results[0]["score"] < 0.5, "Benign flow flagged as attack"
    assert results[1]["score"] > 0.5, "Anomalous flow NOT flagged as attack"
    print("\n--- ALL AI INFERENCE TESTS PASSED ---")

if __name__ == "__main__":
    try:
        test_ai_inference()
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
