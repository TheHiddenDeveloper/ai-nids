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

        df = pd.DataFrame(flows)

        meta = df[[c for c in META_COLS if c in df.columns]].copy()
        feature_df = df[[c for c in FEATURE_COLS if c in df.columns]].copy()

        # Fill any missing feature columns with 0
        for col in FEATURE_COLS:
            if col not in feature_df.columns:
                feature_df[col] = 0

        # FV3 — compute flag ratios from raw counts
        for feat, count_col in [("syn_ratio", "syn_flag_count"), ("fin_ratio", "fin_flag_count"),
                                ("rst_ratio", "rst_flag_count"), ("ack_ratio", "ack_flag_count"),
                                ("psh_ratio", "psh_flag_count")]:
            if count_col in feature_df.columns and "packet_count" in feature_df.columns:
                feature_df[feat] = np.where(
                    feature_df["packet_count"] > 0,
                    feature_df[count_col] / feature_df["packet_count"],
                    0.0
                )

        # FV2 — port category one-hot encoding
        if "dst_port" in feature_df.columns:
            port = feature_df["dst_port"]
            feature_df["port_is_web"]   = port.isin({80, 443, 8080, 8443}).astype(float)
            feature_df["port_is_mail"]  = port.isin({25, 110, 143, 587, 993, 995}).astype(float)
            feature_df["port_is_admin"] = port.isin({22, 23, 21, 3389, 5900}).astype(float)
            feature_df["port_is_db"]    = port.isin({3306, 5432, 27017, 6379}).astype(float)
            feature_df["port_is_dns"]   = (port == 53).astype(float)

        feature_df = feature_df[FEATURE_COLS]

        # Replace inf / -inf, then NaN — warn if data quality is poor
        inf_mask = np.isinf(feature_df.values)
        if inf_mask.any():
            n_inf = int(inf_mask.sum())
            logger.warning(f"Replaced {n_inf} Inf value(s) with 0 — check flow aggregation")
        feature_df.replace([np.inf, -np.inf], 0, inplace=True)
        nan_mask = feature_df.isna().values
        nan_count = int(nan_mask.sum())
        if nan_count:
            logger.warning(f"Replaced {nan_count} NaN value(s) with 0 — check feature extraction")
        feature_df.fillna(0, inplace=True)

        # Mark malformed rows (had inf or nan — E2)
        had_issues = inf_mask.any(axis=1) | nan_mask.any(axis=1)
        feature_df["_is_malformed"] = had_issues

        # Clip extreme outliers (E3: configurable via clip_upper)
        for col in ["flow_bytes_per_sec", "flow_packets_per_sec"]:
            if col in feature_df.columns:
                feature_df[col] = feature_df[col].clip(upper=self.clip_upper)

        # Re-attach metadata
        for col in META_COLS:
            if col in meta.columns:
                feature_df[col] = meta[col].values

        logger.debug(f"Extracted features for {len(feature_df)} flows")
        return feature_df
