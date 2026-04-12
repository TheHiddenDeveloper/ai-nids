"""
AI Data Bootstrapper
--------------------
Generates a balanced seed dataset for training the NIDS models.
This provides a starting point for the AI when local data is low.
"""

import pandas as pd
import numpy as np
import random
from pathlib import Path
from loguru import logger

# Using the precise feature columns expected by our dataset loader
FEATURE_COLS = [
    "dst_port", "duration", "src_bytes", "dst_bytes",
    "packet_count", "avg_packet_len", "std_packet_len",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "fwd_packet_len_max", "bwd_packet_len_max",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count",
]

def generate_benign(n=8000):
    """Generates normal-looking traffic profiles."""
    data = []
    for _ in range(n):
        # Mostly 80, 443, or high ports
        p = random.choice([80, 443, 8080] + [random.randint(1024, 65535)]*3)
        duration = random.uniform(0.1, 5.0)
        pkt_count = random.randint(3, 20)
        src_bytes = pkt_count * random.randint(60, 1500)
        dst_bytes = pkt_count * random.randint(60, 5000)
        
        row = {
            "dst_port": p,
            "duration": duration,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "packet_count": pkt_count,
            "avg_packet_len": (src_bytes + dst_bytes) / (pkt_count * 2),
            "std_packet_len": random.uniform(10, 500),
            "flow_bytes_per_sec": (src_bytes + dst_bytes) / duration,
            "flow_packets_per_sec": pkt_count / duration,
            "fwd_packet_len_max": 1500,
            "bwd_packet_len_max": 1500,
            "flow_iat_mean": duration / pkt_count,
            "flow_iat_std": random.uniform(0.01, 0.1),
            "flow_iat_max": duration / 2,
            "flow_iat_min": 0.001,
            "fin_flag_count": random.choice([0, 1]),
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "psh_flag_count": random.randint(0, 5),
            "ack_flag_count": pkt_count,
            "label": "BENIGN"
        }
        data.append(row)
    return data

def generate_scan(n=1000):
    """Generates rapid port scanning profiles (SYN scans)."""
    data = []
    for _ in range(n):
        p = random.randint(1, 65535)
        duration = random.uniform(0.001, 0.05)
        pkt_count = 1  # Classic one-packet scan
        src_bytes = 40 # Standard SYN packet size
        dst_bytes = 0
        
        row = {
            "dst_port": p,
            "duration": duration,
            "src_bytes": src_bytes,
            "dst_bytes": 0,
            "packet_count": 1,
            "avg_packet_len": 40.0,
            "std_packet_len": 0,
            "flow_bytes_per_sec": src_bytes / duration,
            "flow_packets_per_sec": 1 / duration,
            "fwd_packet_len_max": 40,
            "bwd_packet_len_max": 0,
            "flow_iat_mean": 0,
            "flow_iat_std": 0,
            "flow_iat_max": 0,
            "flow_iat_min": 0,
            "fin_flag_count": 0,
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "psh_flag_count": 0,
            "ack_flag_count": 0,
            "label": "PortScan"
        }
        data.append(row)
    return data

def generate_brute_force(n=1000):
    """Generates login brute force attempts (SSH/RDP)."""
    data = []
    for _ in range(n):
        p = random.choice([22, 3389])
        duration = random.uniform(1.0, 10.0)
        pkt_count = random.randint(15, 50)
        src_bytes = pkt_count * 100 # uniform payload size
        dst_bytes = pkt_count * 80
        
        row = {
            "dst_port": p,
            "duration": duration,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "packet_count": pkt_count,
            "avg_packet_len": 90.0,
            "std_packet_len": 5.0,
            "flow_bytes_per_sec": (src_bytes + dst_bytes) / duration,
            "flow_packets_per_sec": pkt_count / duration,
            "fwd_packet_len_max": 120,
            "bwd_packet_len_max": 100,
            "flow_iat_mean": duration / pkt_count,
            "flow_iat_std": 0.001,
            "flow_iat_max": 0.5,
            "flow_iat_min": 0.01,
            "fin_flag_count": 0,
            "syn_flag_count": 1,
            "rst_flag_count": random.choice([0, 1]),
            "psh_flag_count": pkt_count // 2,
            "ack_flag_count": pkt_count // 2,
            "label": "BruteForce"
        }
        data.append(row)
    return data

if __name__ == "__main__":
    logger.info("Generating seed dataset for High-Precision AI training...")
    
    benign = generate_benign(8000)
    scan = generate_scan(1000)
    brute = generate_brute_force(1000)
    
    all_data = benign + scan + brute
    df = pd.DataFrame(all_data)
    
    # Shuffle
    df = df.sample(frac=1).reset_index(drop=True)
    
    out_path = Path("data/training_seed.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    
    logger.success(f"Generated {len(df):,} samples across 3 categories → {out_path}")
