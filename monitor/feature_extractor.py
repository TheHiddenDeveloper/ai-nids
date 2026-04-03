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

# Must match ai_engine/dataset.py FEATURE_COLS exactly
FEATURE_COLS = [
    "dst_port", "duration", "src_bytes", "dst_bytes",
    "packet_count", "avg_packet_len", "std_packet_len",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "fwd_packet_len_max", "bwd_packet_len_max",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count",
]

META_COLS = ["_src_ip", "_dst_ip", "_src_port", "_dst_port", "_timestamp"]


class FeatureExtractor:
    """
    Converts a list of flow feature dicts to a clean DataFrame.
    Handles missing values, type casting, and infinite values.
    """

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

        feature_df = feature_df[FEATURE_COLS]

        # Replace inf / -inf, then NaN
        feature_df.replace([np.inf, -np.inf], 0, inplace=True)
        feature_df.fillna(0, inplace=True)

        # Clip extreme outliers from malformed packets
        for col in ["flow_bytes_per_sec", "flow_packets_per_sec"]:
            if col in feature_df.columns:
                feature_df[col] = feature_df[col].clip(upper=1e9)

        # Re-attach metadata
        for col in META_COLS:
            if col in meta.columns:
                feature_df[col] = meta[col].values

        logger.debug(f"Extracted features for {len(feature_df)} flows")
        return feature_df

    def to_numpy(self, df: pd.DataFrame) -> np.ndarray:
        """Return only ML-ready numeric columns as numpy array."""
        return df[FEATURE_COLS].to_numpy(dtype=np.float32)
