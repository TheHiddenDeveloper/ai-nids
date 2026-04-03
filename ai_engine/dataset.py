"""
Dataset Loader — CICIDS2017
----------------------------
Loads the CICIDS2017 dataset, maps its columns to our internal feature
schema, and splits into train/test sets.

Download: https://www.unb.ca/cic/datasets/ids-2017.html
Place CSV files in: data/raw/cicids2017/
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from loguru import logger

# Mapping: CICIDS2017 column name → our internal feature name
# Note: MachineLearningCSV.zip does not include a 'Protocol' column —
# 'Destination Port' is used instead as the protocol proxy.
CICIDS_COLUMN_MAP = {
    "Destination Port": "dst_port",
    "Flow Duration": "duration",
    "Total Length of Fwd Packets": "src_bytes",
    "Total Length of Bwd Packets": "dst_bytes",
    "Total Fwd Packets": "packet_count",
    "Fwd Packet Length Mean": "avg_packet_len",
    "Fwd Packet Length Std": "std_packet_len",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Fwd Packet Length Max": "fwd_packet_len_max",
    "Bwd Packet Length Max": "bwd_packet_len_max",
    "FIN Flag Count": "fin_flag_count",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "Label": "label",
}

FEATURE_COLS = [
    "dst_port", "duration", "src_bytes", "dst_bytes",
    "packet_count", "avg_packet_len", "std_packet_len",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "fwd_packet_len_max", "bwd_packet_len_max",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count",
]


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
            f"Download CICIDS2017 from https://www.unb.ca/cic/datasets/ids-2017.html\n"
            f"and place the CSV files in {data_dir}/"
        )

    logger.info(f"Loading {len(csv_files)} CSV file(s) from {data_dir}")
    dfs = []
    for f in csv_files:
        logger.info(f"  Reading {f.name}...")
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Raw dataset: {len(combined):,} rows, {len(combined.columns)} columns")

    combined.rename(columns=CICIDS_COLUMN_MAP, inplace=True)

    needed = FEATURE_COLS + ["label"]
    available = [c for c in needed if c in combined.columns]
    combined = combined[available].copy()

    combined.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined.dropna(inplace=True)

    combined["label"] = combined["label"].str.strip()
    combined["is_attack"] = (combined["label"].str.upper() != "BENIGN").astype(int)

    logger.info(f"Clean dataset: {len(combined):,} rows")
    logger.info(f"Label distribution:\n{combined['label'].value_counts().to_string()}")

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
