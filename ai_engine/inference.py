"""
Inference Engine
----------------
Loads trained model + scaler and scores live flow feature vectors.
Returns a probability score [0,1] and predicted label per flow.
"""

import joblib
import numpy as np
from pathlib import Path
from typing import List
from loguru import logger

from monitor.feature_extractor import FEATURE_COLS


class InferenceEngine:
    """
    Wraps a trained sklearn model for real-time flow scoring.

    Usage:
        engine = InferenceEngine()
        engine.load()
        results = engine.predict(feature_df)
    """

    def __init__(
        self,
        model_path: str = "data/models/nids_model.joblib",
        scaler_path: str = "data/models/scaler.joblib",
    ):
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)
        self.model = None
        self.scaler = None
        self._loaded = False

    def load(self) -> bool:
        if not self.model_path.exists():
            logger.error(
                f"Model not found: {self.model_path}\n"
                f"Train first with: python scripts/train.py --model rf"
            )
            return False
        if not self.scaler_path.exists():
            logger.error(f"Scaler not found: {self.scaler_path}")
            return False

        self.model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.scaler_path)
        self._loaded = True
        logger.info(f"Model loaded from {self.model_path}")
        return True

    def predict(self, feature_df) -> List[dict]:
        """
        Score a DataFrame of flow features.
        Returns list of result dicts with 'score', 'label', and flow metadata.
        """
        if not self._loaded:
            raise RuntimeError("Call load() before predict()")

        X = feature_df[FEATURE_COLS].to_numpy(dtype=np.float32)
        X_scaled = self.scaler.transform(X)

        proba = self.model.predict_proba(X_scaled)[:, 1]  # P(attack)

        results = []
        for i, score in enumerate(proba):
            row = feature_df.iloc[i]
            results.append({
                "score": float(score),
                "label": "ATTACK" if score >= 0.5 else "BENIGN",
                "_src_ip": row.get("_src_ip"),
                "_dst_ip": row.get("_dst_ip"),
                "_src_port": row.get("_src_port"),
                "_dst_port": row.get("_dst_port"),
                "_timestamp": row.get("_timestamp"),
            })

        return results

    @property
    def is_loaded(self) -> bool:
        return self._loaded
