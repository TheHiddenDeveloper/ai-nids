"""
===============================================================================
FEATURE EXTRACTOR — Flow Dict → Clean DataFrame
===============================================================================
Purpose:
Transforms a list of raw flow feature dicts (from FlowAggregator) into a
clean, NaN/Inf-free pandas DataFrame ready for ML inference or training.

Usage:
extractor = FeatureExtractor()
df = extractor.transform(flows) # returns DataFrame or None

Processing steps:
1. OP4: pre-allocate numpy array instead of pd.DataFrame(list-of-dicts)
— faster and memory-efficient for high throughput
2. FV3: compute flag ratios (syn_ratio, fin_ratio, etc.) from raw counts
3. FV2: port category one-hot encoding (port_is_web, port_is_mail, etc.)
4. Replace Inf/NaN with 0.0; mark malformed rows (_is_malformed flag)
5. Re-attach metadata columns (_src_ip, _dst_ip, etc.) from META_COLS

Note: No artificial outlier clipping is applied. StandardScaler fitted at
training time handles out-of-range values; clipping would introduce a
train/production distribution shift for high-bandwidth flows.
===============================================================================
"""

import pandas as pd
import numpy as np
from typing import List, Optional
from loguru import logger

from core.features import FEATURE_COLS, META_COLS, compute_probe_features, compute_flood_features


class FeatureExtractor:
    """Converts a list of flow feature dicts to a clean DataFrame.
    Handles missing values, type casting, and infinite values.
    """

    def __init__(self):
        pass

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
            feature_df["port_is_web"] = np.isin(port, [80, 443, 8080, 8443]).astype(np.float32)
            feature_df["port_is_mail"] = np.isin(port, [25, 110, 143, 587, 993, 995]).astype(np.float32)
            feature_df["port_is_admin"] = np.isin(port, [22, 23, 21, 3389, 5900]).astype(np.float32)
            feature_df["port_is_db"] = np.isin(port, [3306, 5432, 27017, 6379]).astype(np.float32)
            feature_df["port_is_dns"] = (port == 53).astype(np.float32)

        # FV4 — probe/scan indicators (shared logic with training)
        for i, flow in enumerate(flows):
            probe = compute_probe_features(flow)
            for feat, val in probe.items():
                if feat in FEATURE_COLS:
                    feature_df.at[i, feat] = float(val)

        # FV5 — flood/DoS indicators (shared logic with training)
        for i, flow in enumerate(flows):
            flood = compute_flood_features(flow)
            for feat, val in flood.items():
                if feat in FEATURE_COLS:
                    feature_df.at[i, feat] = float(val)

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

        # Re-attach metadata (skip _is_malformed — already computed)
        for col in META_COLS:
            if col == "_is_malformed":
                continue
            if col in meta_data:
                feature_df[col] = meta_data[col]

        logger.debug(f"Extracted features for {len(feature_df)} flows")
        return feature_df
