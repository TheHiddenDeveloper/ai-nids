"""
================================================================================
DATASET LOADER — Multi-Dataset Research Data
================================================================================
Purpose:
  Loads CICIDS2017 and/or CICIoT2023 research CSV files, maps their columns
  to our internal FEATURE_COLS schema, computes derived features (FV2 port
  categories, FV3 flag ratios), cleans data, and returns combined DataFrames.

  Datasets:
    CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
    CICIoT2023: https://www.unb.ca/cic/datasets/iotdataset-2023.html

Usage:
  df = load_cicids2017("data/raw/cicids2017")
  df = load_ciciot2023("data/raw/ciciot2023")
  df = load_all_datasets(["cicids2017", "ciciot2023"])

Key mappers:
  - CICIDS_COLUMN_MAP: maps CICIDS2017 column names → internal FEATURE_COLS
  - CICIOT_COLUMN_MAP: maps CICIoT2023 column names → internal FEATURE_COLS
  - FV2: dst_port → one-hot category flags (web, mail, admin, db, dns)
  - FV3: raw flag counts → syn_ratio, fin_ratio, etc. (normalized by packet_count)
  - Label: anything not 'BENIGN'/'BenignTraffic' → is_attack=1 (broad classification)
================================================================================
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from loguru import logger

from core.features import FEATURE_COLS, compute_probe_features_vec, compute_flood_features_vec

# ── CICIDS2017 column mapping ────────────────────────────────────────────────
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

# ── CICIoT2023 column mapping ────────────────────────────────────────────────
# CICIoT2023 uses different names for similar features. Some features must be
# derived (packet_count from fwd+bwd counts, rates from totals/duration).
# Port categories are derived from protocol-type columns (HTTP, DNS, etc.)
# since CICIoT2023 has no explicit dst_port column.
CICIOT_COLUMN_MAP = {
    "flow_duration":      "duration",
    "Tot size":           "src_bytes",        # Total forward bytes (closest match)
    "Tot sum":            "dst_bytes",        # Total backward bytes (closest match)
    "ack_count":          "fwd_count",        # Forward packet count (temporary)
    "syn_count":          "bwd_count",        # Backward packet count (temporary)
    "AVG":                "avg_packet_len",
    "Std":                "std_packet_len",
    "Rate":               "flow_bytes_per_sec",
    "Number":             "flow_packets_per_sec",
    "Max":                "fwd_packet_len_max",
    "Min":                "bwd_packet_len_max",
    "IAT":                "flow_iat_mean",
    "fin_flag_number":    "fin_flag_count",
    "syn_flag_number":    "syn_flag_count",
    "rst_flag_number":    "rst_flag_count",
    "psh_flag_number":    "psh_flag_count",
    "ack_flag_number":    "ack_flag_count",
    "Label":              "label",
}


def _add_fv2_fv3(df: pd.DataFrame) -> pd.DataFrame:
    """Add FV3 (flag ratios) and FV2 (port categories) to a DataFrame."""
    # FV3 — flag ratios from raw counts
    fv3_map = {
        "syn_flag_count": "syn_ratio", "fin_flag_count": "fin_ratio",
        "rst_flag_count": "rst_ratio", "ack_flag_count": "ack_ratio",
        "psh_flag_count": "psh_ratio",
    }
    for count_col, ratio_col in fv3_map.items():
        if count_col in df.columns and "packet_count" in df.columns:
            df[ratio_col] = np.where(
                df["packet_count"] > 0, df[count_col] / df["packet_count"], 0.0
            )

    # FV2 — port category one-hot from dst_port
    if "dst_port" in df.columns:
        port = df["dst_port"]
        df["port_is_web"]   = port.isin({80, 443, 8080, 8443}).astype(float)
        df["port_is_mail"]  = port.isin({25, 110, 143, 587, 993, 995}).astype(float)
        df["port_is_admin"] = port.isin({22, 23, 21, 3389, 5900}).astype(float)
        df["port_is_db"]    = port.isin({3306, 5432, 27017, 6379}).astype(float)
        df["port_is_dns"]   = (port == 53).astype(float)

    return df


def _add_fv2_from_protocols(df: pd.DataFrame) -> pd.DataFrame:
    """
    FV2 for datasets without dst_port (e.g. CICIoT2023).
    Uses protocol-type columns (HTTP, DNS, Telnet, etc.) as proxies.
    """
    if "dst_port" not in df.columns:
        http_val = df.get("HTTP", 0).astype(float)
        https_val = df.get("HTTPS", 0).astype(float)
        telnet_val = df.get("Telnet", 0).astype(float)
        ssh_val = df.get("SSH", 0).astype(float)
        df["port_is_web"]   = np.clip(http_val + https_val, 0, 1)
        df["port_is_mail"]  = df.get("SMTP", 0).astype(float)
        df["port_is_admin"] = np.clip(telnet_val + ssh_val, 0, 1)
        df["port_is_db"]    = 0.0  # No DB protocol indicator in CICIoT2023
        df["port_is_dns"]   = df.get("DNS", 0).astype(float)
    return df


def _clean(df: pd.DataFrame, source_name: str) -> pd.DataFrame:
    """Common cleaning: NaN/Inf zero-fill, label normalisation.

    Matches production feature_extractor behaviour (replaces NaN/Inf with 0.0
    rather than dropping rows) so the model trains on the same input
    distribution it receives at inference time.
    """
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    nan_cols = df.columns[df.isna().any()].tolist()
    if nan_cols:
        df[nan_cols] = df[nan_cols].fillna(0.0)
        logger.info(f"[{source_name}] Zero-filled NaN values in {len(nan_cols)} columns ({before:,} rows kept)")

    df["label"] = df["label"].str.strip()
    # Broad binary classification
    benign_labels = {"benign", "benigntraffic"}
    df["is_attack"] = (~df["label"].str.lower().isin(benign_labels)).astype(int)

    logger.info(f"[{source_name}] Clean dataset: {len(df):,} rows "
                f"(attack={df['is_attack'].sum():,}, benign={(df['is_attack']==0).sum():,})")
    return df


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

    logger.info(f"Loading {len(csv_files)} CICIDS2017 CSV file(s) from {data_dir}")
    dfs = []
    for f in csv_files:
        logger.info(f"  Reading {f.name}...")
        df = pd.read_csv(f, low_memory=False, encoding="latin1")
        df.columns = df.columns.str.strip()
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Raw CICIDS2017 dataset: {len(combined):,} rows")

    combined.rename(columns=CICIDS_COLUMN_MAP, inplace=True)

    # CICIDS2017 stores time-based features in MICROSECONDS, but production
    # (monitor/flow_aggregator.py) computes them in SECONDS from time.time().
    # Convert here so training matches the inference-time input distribution.
    # Flow Bytes/s and Flow Packets/s are already per-second in both.
    for col in ("duration", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min"):
        if col in combined.columns:
            combined[col] = pd.to_numeric(combined[col], errors="coerce") / 1e6

    # Calculate total packet count if directional counts exist
    if "fwd_count" in combined.columns and "bwd_count" in combined.columns:
        combined["packet_count"] = combined["fwd_count"] + combined["bwd_count"]

    # FV2 + FV3
    combined = _add_fv2_fv3(combined)

    # FV4 — probe/scan indicators (shared logic with production)
    for feat, val in compute_probe_features_vec(combined).items():
        combined[feat] = val

    # FV5 — flood/DoS indicators (shared logic with production)
    for feat, val in compute_flood_features_vec(combined).items():
        combined[feat] = val

    needed = FEATURE_COLS + ["label"]
    available = [c for c in needed if c in combined.columns]
    combined = combined[available].copy()

    return _clean(combined, "CICIDS2017")


def load_ciciot2023(data_dir: str = "data/raw/ciciot2023") -> pd.DataFrame:
    """
    Load CICIoT2023 CSV files from data_dir into a single DataFrame.
    Maps CICIoT2023-specific columns to our internal FEATURE_COLS schema.

    Handles both directory layouts:
      - Flat: data/raw/ciciot2023/*.csv
      - Kaggle split: data/raw/ciciot2023/{train,validation,test}/*.csv

    CICIoT2023 uses different column names and has no dst_port column.
    Port categories (FV2) are derived from protocol-type columns instead.
    """
    data_path = Path(data_dir)

    # Find CSVs in both flat layout and subdirectories
    csv_files = list(data_path.glob("*.csv"))
    for sub in ("train", "validation", "test"):
        csv_files.extend((data_path / sub).glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}.\n"
            f"Run 'python scripts/fetch_ciciot2023.py' or download from Kaggle."
        )

    logger.info(f"Loading {len(csv_files)} CICIoT2023 CSV file(s) from {data_dir}")
    dfs = []
    for f in csv_files:
        logger.info(f"  Reading {f.name}...")
        df = pd.read_csv(f, low_memory=False, encoding="latin1")
        df.columns = df.columns.str.strip()
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Raw CICIoT2023 dataset: {len(combined):,} rows")

    combined.rename(columns=CICIOT_COLUMN_MAP, inplace=True)

    # Calculate packet_count from directional counts
    if "fwd_count" in combined.columns and "bwd_count" in combined.columns:
        combined["packet_count"] = combined["fwd_count"] + combined["bwd_count"]
    elif "Number" in combined.columns:
        combined["packet_count"] = combined["Number"]

    # Derive std_packet_len if missing (CICIoT2023 has 'Std' but not always)
    if "std_packet_len" not in combined.columns and "Covariance" in combined.columns:
        combined["std_packet_len"] = np.sqrt(combined["Covariance"].clip(lower=0))

    # FV3 — flag ratios from raw counts
    fv3_map = {
        "syn_flag_count": "syn_ratio", "fin_flag_count": "fin_ratio",
        "rst_flag_count": "rst_ratio", "ack_flag_count": "ack_ratio",
        "psh_flag_count": "psh_ratio",
    }
    for count_col, ratio_col in fv3_map.items():
        if count_col in combined.columns and "packet_count" in combined.columns:
            combined[ratio_col] = np.where(
                combined["packet_count"] > 0, combined[count_col] / combined["packet_count"], 0.0
            )

    # FV2 — protocol-based (no dst_port in CICIoT2023)
    combined = _add_fv2_from_protocols(combined)

    # FV4 — probe/scan indicators (shared logic with production)
    for feat, val in compute_probe_features_vec(combined).items():
        combined[feat] = val

    # FV5 — flood/DoS indicators (shared logic with production)
    for feat, val in compute_flood_features_vec(combined).items():
        combined[feat] = val

    # Fill remaining missing features with safe defaults
    # CICIoT2023 has no dst_port, flow_iat_std, flow_iat_max, flow_iat_min
    _defaults = {
        "dst_port": 0.0,
        "flow_iat_std": 0.0,
        "flow_iat_max": 0.0,
        "flow_iat_min": 0.0,
    }
    for col, default in _defaults.items():
        if col not in combined.columns:
            combined[col] = default

    needed = FEATURE_COLS + ["label"]
    available = [c for c in needed if c in combined.columns]
    missing = [c for c in FEATURE_COLS if c not in combined.columns]
    if missing:
        logger.warning(f"CICIoT2023 missing {len(missing)} features (filling with 0): {missing}")
        for col in missing:
            combined[col] = 0.0

    combined = combined[needed].copy()
    return _clean(combined, "CICIoT2023")


def load_all_datasets(datasets: list = None, data_dirs: dict = None) -> pd.DataFrame:
    """
    Load and combine multiple research datasets.

    Args:
        datasets: list of dataset names to load. Options: "cicids2017", "ciciot2023".
                  Default: ["cicids2017"] (backward compatible).
        data_dirs: optional dict mapping dataset name → directory path.
                   Default: uses standard data/raw/{name} paths.

    Returns:
        Combined DataFrame with all FEATURE_COLS + label + is_attack.
    """
    if datasets is None:
        datasets = ["cicids2017"]
    if data_dirs is None:
        data_dirs = {}

    loaders = {
        "cicids2017": ("data/raw/cicids2017", load_cicids2017),
        "ciciot2023": ("data/raw/ciciot2023", load_ciciot2023),
    }

    frames = []
    for name in datasets:
        if name not in loaders:
            logger.warning(f"Unknown dataset '{name}', skipping. Options: {list(loaders.keys())}")
            continue
        default_dir, loader_fn = loaders[name]
        data_dir = data_dirs.get(name, default_dir)
        try:
            df = loader_fn(data_dir)
            logger.info(f"[{name}] Loaded {len(df):,} samples")
            frames.append(df)
        except FileNotFoundError as e:
            logger.warning(f"[{name}] Skipped: {e}")
        except Exception as e:
            logger.error(f"[{name}] Failed to load: {e}")

    if not frames:
        raise RuntimeError("No datasets loaded. Check data directories and run fetch scripts.")

    if len(frames) == 1:
        return frames[0]

    combined = pd.concat(frames, ignore_index=True)
    logger.info(f"Combined dataset: {len(combined):,} rows from {len(frames)} source(s)")
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
