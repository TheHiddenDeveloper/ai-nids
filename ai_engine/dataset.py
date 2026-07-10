"""
================================================================================
DATASET LOADER — CICIDS2017 Research Data
================================================================================
Purpose:
  Loads CICIDS2017 research CSV files from data/raw/cicids2017/, maps their
  columns to our internal FEATURE_COLS schema, computes derived features
  (FV2 port categories, FV3 flag ratios), cleans data, and splits into
  train/test sets.

  Dataset: https://www.unb.ca/cic/datasets/ids-2017.html
  Download: python scripts/fetch_cicids.py

Usage:
  df = load_cicids2017("data/raw/cicids2017")
  X_train, X_test, y_train, y_test, label_encoder = prepare_splits(df)

Key mappers:
  - CICIDS_COLUMN_MAP: maps CICIDS column names → internal FEATURE_COLS
  - FV2: dst_port → one-hot category flags (web, mail, admin, db, dns)
  - FV3: raw flag counts → syn_ratio, fin_ratio, etc. (normalized by packet_count)
  - Label: anything not "BENIGN" → is_attack=1 (broad classification)
================================================================================
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from loguru import logger

from core.features import FEATURE_COLS

# Mapping: CICIDS2017 column name → our internal feature name
# Note: MachineLearningCSV.zip does not include a 'Protocol' column —
# 'Destination Port' is used instead as the protocol proxy.
CICIDS_COLUMN_MAP = {
    "Destination Port": "dst_port",
    "Flow Duration": "duration",
    "Total Length of Fwd Packets": "src_bytes",
    "Total Length of Bwd Packets": "dst_bytes",
    "Total Fwd Packets": "fwd_count",  # Temporary for sum
    "Total Backward Packets": "bwd_count", # Temporary for sum
    "Packet Length Mean": "avg_packet_len",
    "Packet Length Std": "std_packet_len",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Fwd Packet Length Max": "fwd_packet_len_max",
    "Bwd Packet Length Max": "bwd_packet_len_max",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "FIN Flag Count": "fin_flag_count",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "Label": "label",
}


def load_cicids2017(data_dir: str = "data/raw/cicids2017") -> pd.DataFrame:
    """
    Load all CICIDS2017 CSV files from data_dir into a single DataFrame.
    Renames columns to our internal schema and cleans data.
    """
    data_path = Path(data_dir)
    csv_files = list(data_path.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}.\n"
            f"Run 'bash scripts/fetch_cicids.sh' or 'python scripts/fetch_cicids.py' first."
        )

    logger.info(f"Loading {len(csv_files)} research CSV file(s) from {data_dir}")
    dfs = []
    for f in csv_files:
        logger.info(f"  Reading {f.name}...")
        # Research data is often encoded in latin1
        df = pd.read_csv(f, low_memory=False, encoding="latin1")
        df.columns = df.columns.str.strip()
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Raw research dataset: {len(combined):,} rows")

    combined.rename(columns=CICIDS_COLUMN_MAP, inplace=True)

    # Calculate total packet count if directional counts exist
    if "fwd_count" in combined.columns and "bwd_count" in combined.columns:
        combined["packet_count"] = combined["fwd_count"] + combined["bwd_count"]

    # FV3 — compute flag ratios from raw CICIDS counts
    fv3_map = {"syn_flag_count": "syn_ratio", "fin_flag_count": "fin_ratio",
               "rst_flag_count": "rst_ratio", "ack_flag_count": "ack_ratio", "psh_flag_count": "psh_ratio"}
    for count_col, ratio_col in fv3_map.items():
        if count_col in combined.columns and "packet_count" in combined.columns:
            combined[ratio_col] = np.where(combined["packet_count"] > 0, combined[count_col] / combined["packet_count"], 0.0)

    # FV2 — port category one-hot encoding
    if "dst_port" in combined.columns:
        port = combined["dst_port"]
        combined["port_is_web"]   = port.isin({80, 443, 8080, 8443}).astype(float)
        combined["port_is_mail"]  = port.isin({25, 110, 143, 587, 993, 995}).astype(float)
        combined["port_is_admin"] = port.isin({22, 23, 21, 3389, 5900}).astype(float)
        combined["port_is_db"]    = port.isin({3306, 5432, 27017, 6379}).astype(float)
        combined["port_is_dns"]   = (port == 53).astype(float)

    needed = FEATURE_COLS + ["label"]
    available = [c for c in needed if c in combined.columns]
    combined = combined[available].copy()

    # Clean data (NaN/Inf)
    combined.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(combined)
    combined.dropna(inplace=True)
    after = len(combined)
    dropped = before - after
    if dropped:
        logger.warning(f"Dropped {dropped:,} rows with NaN/Inf values ({dropped/before*100:.1f}%)")

    combined["label"] = combined["label"].str.strip()
    # Broad classification: anything not 'BENIGN' is an attack
    combined["is_attack"] = (combined["label"].str.upper() != "BENIGN").astype(int)

    logger.info(f"Clean research dataset: {len(combined):,} rows")
    logger.info(f"Attack samples: {combined['is_attack'].sum():,}")

    return combined


def prepare_splits(df: pd.DataFrame, test_size: float = 0.2, random_state: int = 42):
    """
    Split dataset into train/test sets.
    Returns X_train, X_test, y_train, y_test, and a fitted LabelEncoder.
    """
    le = LabelEncoder()
    le.fit(df["label"])

    y_binary = df["is_attack"].values
    X = df[FEATURE_COLS].values.astype(np.float32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binary,
        test_size=test_size,
        random_state=random_state,
        stratify=y_binary,
    )

    logger.info(f"Train: {len(X_train):,} | Test: {len(X_test):,}")
    return X_train, X_test, y_train, y_test, le
