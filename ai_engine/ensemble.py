"""
Ensemble Inference Engine
-------------------------
Combines Random Forest (supervised) and Autoencoder (unsupervised)
into a single weighted attack probability score.

RF catches known attack patterns from CICIDS2017 training data.
Autoencoder catches zero-days — anything that reconstructs poorly
from the benign-traffic baseline.

Final score = (rf_weight * rf_score) + (ae_weight * ae_score)

Both scores are in [0, 1]. The ensemble is more robust than either
model alone:
  - RF alone: high accuracy on known attacks, blind to novel ones
  - AE alone: catches anomalies but high false positive rate
  - Ensemble: RF anchors known patterns, AE adds zero-day coverage
"""

import hashlib
import joblib
import numpy as np
from pathlib import Path
from typing import List, Optional
from loguru import logger

from core.features import FEATURE_COLS, HUMAN_FEATURE_NAMES


class EnsembleInferenceEngine:
    """
    Weighted ensemble of RF classifier + Autoencoder anomaly detector.

    Usage:
        engine = EnsembleInferenceEngine()
        engine.load()
        results = engine.predict(feature_df)
    """

    def __init__(
        self,
        model_dir:  str   = "data/models",
        rf_weight:  float = None,
        ae_weight:  float = None,
    ):
        self.model_dir  = Path(model_dir)
        self.rf_weight  = rf_weight
        self.ae_weight  = ae_weight

        # RF components
        self._rf     = None
        self._scaler = None

        # Autoencoder components
        self._ae           = None
        self._ae_scaler    = None
        self._ae_threshold = None

        self._rf_loaded = False
        self._ae_loaded = False

        # Load config defaults (weights, threshold) if not explicitly provided
        self._load_config()

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_config(self):
        """Read model weights and threshold from config.yaml, fall back to defaults."""
        try:
            import yaml
            with open("config.yaml") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}

        model_cfg = cfg.get("model", {})
        if self.rf_weight is None:
            self.rf_weight = model_cfg.get("rf_weight", 0.50)
        if self.ae_weight is None:
            self.ae_weight = model_cfg.get("ae_weight", 0.50)
        self._threshold = model_cfg.get("anomaly_threshold", 0.5)

    # ── Loading ───────────────────────────────────────────────────────────────

    def _check_feature_hash(self) -> bool:
        """Verify feature metadata matches current FEATURE_COLS. Backward-compat."""
        meta_path = self.model_dir / "feature_metadata.joblib"
        if not meta_path.exists():
            logger.warning(
                "No feature metadata found (pre-hash model). "
                "If FEATURE_COLS changed, re-train to avoid silent drift."
            )
            return True
        try:
            meta = joblib.load(meta_path)
            expected = hashlib.md5(":".join(FEATURE_COLS).encode()).hexdigest()
            stored = meta.get("feature_hash")
            if stored != expected:
                logger.error(
                    f"Feature hash mismatch! Expected {expected[:12]}..., "
                    f"model has {stored[:12]}...\n"
                    f"FEATURE_COLS changed since training. Re-train or revert FEATURE_COLS."
                )
                return False
            logger.info(f"Feature hash verified ({expected[:12]}...)")
            return True
        except Exception as e:
            logger.warning(f"Feature hash check failed: {e}")
            return True

    def load(self) -> bool:
        """Load available models. Works with RF only if AE not trained yet."""
        if not self._check_feature_hash():
            return False
        self._rf_loaded = self._load_rf()
        self._ae_loaded = self._load_ae()

        if not self._rf_loaded and not self._ae_loaded:
            logger.error("No models found. Train first: python scripts/train.py --model both")
            return False

        if self._rf_loaded and self._ae_loaded:
            logger.info(
                f"Ensemble loaded | RF weight={self.rf_weight} "
                f"AE weight={self.ae_weight}"
            )
        elif self._rf_loaded:
            logger.info("Ensemble loaded | RF only (no autoencoder found — train with --model both)")
        else:
            logger.info("Ensemble loaded | Autoencoder only")

        return True

    def _load_rf(self) -> bool:
        model_path  = self.model_dir / "nids_model.joblib"
        scaler_path = self.model_dir / "scaler.joblib"
        if not model_path.exists() or not scaler_path.exists():
            return False
        try:
            self._rf     = joblib.load(model_path)
            self._scaler = joblib.load(scaler_path)
            logger.info(f"RF loaded from {model_path}")
            return True
        except Exception as e:
            logger.error(f"RF load failed: {e}")
            return False

    def _load_ae(self) -> bool:
        ae_path    = self.model_dir / "autoencoder.keras"
        sc_path    = self.model_dir / "ae_scaler.joblib"
        th_path    = self.model_dir / "ae_threshold.joblib"
        if not all(p.exists() for p in [ae_path, sc_path, th_path]):
            return False
        try:
            import tensorflow as tf
            self._ae           = tf.keras.models.load_model(str(ae_path))
            self._ae_scaler    = joblib.load(sc_path)
            self._ae_threshold = float(joblib.load(th_path))
            logger.info(f"Autoencoder loaded from {ae_path} (threshold={self._ae_threshold:.6f})")
            return True
        except Exception as e:
            logger.warning(f"Autoencoder load failed (not critical): {e}")
            return False

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _rf_score(self, X: np.ndarray) -> np.ndarray:
        """Return P(attack) from RF, shape (n,)."""
        X_s = self._scaler.transform(X)
        return self._rf.predict_proba(X_s)[:, 1]

    def _ae_score(self, X: np.ndarray) -> np.ndarray:
        """
        Return normalised anomaly score from AE, shape (n,).
        Score = min(mse / (threshold * 3), 1.0) so it maps to [0, 1]
        with threshold being ~0.33 on the scale.
        """
        X_s = self._ae_scaler.transform(X)
        reconstructions = self._ae.predict(X_s, verbose=0)
        mse = np.mean(np.power(X_s - reconstructions, 2), axis=1)
        # Normalise: threshold maps to ~0.33, 3× threshold maps to 1.0
        normalised = np.clip(mse / (self._ae_threshold * 3.0), 0.0, 1.0)
        return normalised

    def _batch_explain(self, X: np.ndarray, rf_scores: np.ndarray, ae_scores: np.ndarray, ensemble_scores: np.ndarray) -> dict:
        """
        Precompute explanations for all anomalous flows in batch.
        Returns {row_index: {driver, features}} for flows with ens >= 0.5.
        """
        anomalous = np.where(ensemble_scores >= 0.5)[0]
        if len(anomalous) == 0:
            return {}

        explanations = {}

        ae_driven = [i for i in anomalous if ae_scores[i] > rf_scores[i]]
        rf_driven = [i for i in anomalous if rf_scores[i] >= ae_scores[i]]

        if ae_driven and self._ae is not None and self._ae_scaler is not None:
            ae_idx = np.array(ae_driven)
            try:
                X_ae_scaled = self._ae_scaler.transform(X[ae_idx])
                reconstructions = self._ae.predict(X_ae_scaled, verbose=0)
                recon_errors = np.power(X_ae_scaled - reconstructions, 2)

                for j, original_idx in enumerate(ae_driven):
                    errors = recon_errors[j]
                    top_indices = np.argsort(errors)[::-1][:3]
                    explanations[original_idx] = {
                        "driver": "Unsupervised Autoencoder",
                        "features": [
                            {
                                "name": HUMAN_FEATURE_NAMES.get(FEATURE_COLS[idx], FEATURE_COLS[idx]),
                                "score": float(errors[idx]),
                            }
                            for idx in top_indices
                        ],
                    }
            except Exception as e:
                logger.error(f"Batch AE explanation failed: {e}")

        if rf_driven and self._scaler is not None:
            rf_idx = np.array(rf_driven)
            try:
                X_rf_scaled = self._scaler.transform(X[rf_idx])

                for j, original_idx in enumerate(rf_driven):
                    scores = np.abs(X_rf_scaled[j])
                    top_indices = np.argsort(scores)[::-1][:3]
                    explanations[original_idx] = {
                        "driver": "Supervised Random Forest",
                        "features": [
                            {
                                "name": HUMAN_FEATURE_NAMES.get(FEATURE_COLS[idx], FEATURE_COLS[idx]),
                                "score": float(scores[idx]),
                            }
                            for idx in top_indices
                        ],
                    }
            except Exception as e:
                logger.error(f"Batch RF explanation failed: {e}")

        return explanations

    def _validate_input(self, X: np.ndarray) -> None:
        """Check input quality before scoring. Warns but does not block."""
        n_features = len(FEATURE_COLS)
        if X.shape[1] != n_features:
            logger.error(
                f"Feature count mismatch: expected {n_features}, got {X.shape[1]}. "
                f"Check FEATURE_COLS vs feature_extractor."
            )
        nan_count = int(np.isnan(X).sum())
        if nan_count:
            logger.warning(
                f"Input contains {nan_count} NaN value(s) — predictions will be degraded. "
                f"Check flow aggregation and feature extraction."
            )

    def predict(self, feature_df) -> List[dict]:
        """
        Score a DataFrame of flow features.
        Returns list of result dicts with ensemble score, component scores,
        label, and flow metadata.
        """
        if not self._rf_loaded and not self._ae_loaded:
            raise RuntimeError("Call load() before predict()")

        X = feature_df[FEATURE_COLS].to_numpy(dtype=np.float32)
        self._validate_input(X)

        rf_scores = self._rf_score(X)  if self._rf_loaded else np.zeros(len(X))
        ae_scores = self._ae_score(X) if self._ae_loaded else np.zeros(len(X))

        if self._rf_loaded and self._ae_loaded:
            rf_w, ae_w = self.rf_weight, self.ae_weight
        elif self._rf_loaded:
            rf_w, ae_w = 1.0, 0.0
        else:
            rf_w, ae_w = 0.0, 1.0

        ensemble_scores = np.clip(rf_w * rf_scores + ae_w * ae_scores, 0.0, 1.0)

        explanations = self._batch_explain(X, rf_scores, ae_scores, ensemble_scores)

        threshold = self._threshold

        results = []
        for i, (ens, rf, ae) in enumerate(zip(ensemble_scores, rf_scores, ae_scores)):
            row = feature_df.iloc[i]
            # Confidence: 0 at threshold (max uncertainty), 1 at extremes
            max_dist = max(threshold, 1.0 - threshold)
            confidence = min(abs(ens - threshold) / max_dist, 1.0) if max_dist > 0 else 1.0
            res = {
                "score":    float(ens),
                "rf_score": float(rf),
                "ae_score": float(ae),
                "label":    "ATTACK" if ens >= threshold else "BENIGN",
                "_src_ip":    row.get("_src_ip"),
                "_dst_ip":    row.get("_dst_ip"),
                "_src_port":  row.get("_src_port"),
                "_dst_port":  row.get("_dst_port"),
                "_timestamp": row.get("_timestamp"),
                "confidence": round(confidence, 4),
            }
            if i in explanations:
                res["explanation"] = explanations[i]
            results.append(res)

        return results

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_loaded(self) -> bool:
        return self._rf_loaded or self._ae_loaded

    @property
    def mode(self) -> str:
        if self._rf_loaded and self._ae_loaded:
            return "ensemble"
        if self._rf_loaded:
            return "rf_only"
        if self._ae_loaded:
            return "ae_only"
        return "unloaded"

    def describe(self) -> dict:
        return {
            "mode":              self.mode,
            "rf_loaded":         self._rf_loaded,
            "ae_loaded":         self._ae_loaded,
            "rf_weight":         self.rf_weight,
            "ae_weight":         self.ae_weight,
            "ae_threshold":      self._ae_threshold,
            "classify_threshold": self._threshold,
        }
