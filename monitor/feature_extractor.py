"""
Feature Extractor
-----------------
Transforms raw flow feature dicts into a clean pandas DataFrame
ready for ML inference or training data export.
"""

import pandas as pd
import numpy as np
from typing import List, Optional
from loguru import logger

from core.features import FEATURE_COLS, META_COLS


class FeatureExtractor:
    """
    Converts a list of flow feature dicts to a clean DataFrame.
    Handles missing values, type casting, and infinite values.
    """

    def __init__(self, clip_upper: float = 1e9):
        self.clip_upper = clip_upper

    def transform(self, flows: List[dict]) -> Optional[pd.DataFrame]:
        if not flows:
            return None

        n = len(flows)
        n_features = len(FEATURE_COLS)

        # OP4: pre-allocate numpy array instead of pd.DataFrame(list-of-dicts)
        arr = np.zeros((n, n_features), dtype=np.float32)
        meta_data = {col: np.empty(n, dtype=object) for col in META_COLS}

        for i, flow in enumerate(flows):
            for j, col in enumerate(FEATURE_COLS):
                val = flow.get(col)
                if val is not None:
                    try:
                        arr[i, j] = float(val)
                    except (ValueError, TypeError):
                        pass
            for col in META_COLS:
                meta_data[col][i] = flow.get(col)

        feature_df = pd.DataFrame(arr, columns=FEATURE_COLS)

        # FV3 — compute flag ratios from raw counts
        for feat, count_col in [("syn_ratio", "syn_flag_count"), ("fin_ratio", "fin_flag_count"),
                                ("rst_ratio", "rst_flag_count"), ("ack_ratio", "ack_flag_count"),
                                ("psh_ratio", "psh_flag_count")]:
            if count_col in FEATURE_COLS and "packet_count" in FEATURE_COLS:
                pc = feature_df["packet_count"].values
                cc = feature_df[count_col].values
                feature_df[feat] = np.where(pc > 0, cc / pc, 0.0)

        # FV2 — port category one-hot encoding
        if "dst_port" in FEATURE_COLS:
            port = feature_df["dst_port"].values
            feature_df["port_is_web"]   = np.isin(port, [80, 443, 8080, 8443]).astype(np.float32)
            feature_df["port_is_mail"]  = np.isin(port, [25, 110, 143, 587, 993, 995]).astype(np.float32)
            feature_df["port_is_admin"] = np.isin(port, [22, 23, 21, 3389, 5900]).astype(np.float32)
            feature_df["port_is_db"]    = np.isin(port, [3306, 5432, 27017, 6379]).astype(np.float32)
            feature_df["port_is_dns"]   = (port == 53).astype(np.float32)

        # OP4: force contiguous copy so .values is writable
        feature_df = feature_df[FEATURE_COLS].copy()
        values = feature_df.values

        inf_mask = np.isinf(values)
        if inf_mask.any():
            n_inf = int(inf_mask.sum())
            logger.warning(f"Replaced {n_inf} Inf value(s) with 0 — check flow aggregation")
        values[inf_mask] = 0.0

        nan_mask = np.isnan(values)
        nan_count = int(nan_mask.sum())
        if nan_count:
            logger.warning(f"Replaced {nan_count} NaN value(s) with 0 — check feature extraction")
        values[nan_mask] = 0.0

        # Mark malformed rows (had inf or nan — E2)
        had_issues = inf_mask.any(axis=1) | nan_mask.any(axis=1)
        feature_df["_is_malformed"] = had_issues

        # Clip extreme outliers (E3: configurable via clip_upper)
        for col in ["flow_bytes_per_sec", "flow_packets_per_sec"]:
            if col in feature_df.columns:
                feature_df[col] = feature_df[col].clip(upper=self.clip_upper)

        # Re-attach metadata (skip _is_malformed — already computed)
        for col in META_COLS:
            if col == "_is_malformed":
                continue
            if col in meta_data:
                feature_df[col] = meta_data[col]

        logger.debug(f"Extracted features for {len(feature_df)} flows")
        return feature_df
