"""
================================================================================
ENSEMBLE INFERENCE ENGINE — RF + Autoencoder Fusion
================================================================================
Purpose:
  Combines Random Forest (supervised, known attack patterns) and Autoencoder
  (unsupervised, anomaly detection on benign baseline) into a single weighted
  attack probability score.

  Final score = rf_weight * rf_score + ae_weight * ae_score

  Default weights from config.yaml: rf=0.65, ae=0.35

Usage:
  engine = EnsembleInferenceEngine(model_dir="data/models")
  engine.load()
  results = engine.predict(feature_df)

Design:
  - Config-driven weights loaded from config.yaml (can be overridden in ctor)
  - OP6: tries ONNX inference first (faster), falls back to joblib/keras
  - Feature hash verification: detects FEATURE_COLS drift between training
    and inference time, slices to the model's training-time feature set
  - M2: scales AE input once, passes to both _ae_score and _batch_explain
    to avoid double normalisation
  - M3: error explanation returned instead of silent failure on batch explain
  - M4: principled z-score normalisation for AE anomaly scores (not raw MSE)
  - Batch explain: for anomalous flows (ens >= 0.5), identifies which model
    drove the decision (RF or AE) and the top-3 contributing features
  - Confidence: distance from classification threshold (0=at threshold, 1=extreme)
================================================================================
"""

import hashlib
import joblib
import numpy as np
from pathlib import Path
from typing import List, Optional
from loguru import logger

from core.features import FEATURE_COLS, HUMAN_FEATURE_NAMES

HUMAN_FEATURE_NAMES = {
    "dst_port": "Destination Port",
    "duration": "Flow Duration",
    "src_bytes": "Sent Bytes",
    "dst_bytes": "Received Bytes",
    "packet_count": "Packet Count",
    "avg_packet_len": "Average Packet Length",
    "std_packet_len": "Packet Length Std Dev",
    "flow_bytes_per_sec": "Flow Bytes/Sec",
    "flow_packets_per_sec": "Flow Packets/Sec",
    "fwd_packet_len_max": "Max Forward Packet Length",
    "bwd_packet_len_max": "Max Backward Packet Length",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std Dev",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fin_flag_count": "FIN Flags",
    "syn_flag_count": "SYN Flags",
    "rst_flag_count": "RST Flags",
    "psh_flag_count": "PSH Flags",
    "ack_flag_count": "ACK Flags",
}


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

        # RF components (ONNX + joblib fallback — OP6)
        self._rf       = None
        self._rf_onnx  = None
        self._scaler   = None

        # Autoencoder components (ONNX + keras fallback — OP6)
        self._ae           = None
        self._ae_onnx      = None
        self._ae_scaler    = None
        self._ae_threshold = None
        self._ae_mse_mean  = 0.0
        self._ae_mse_std   = 1.0

        # Feature columns this model was trained on (backward compat)
        self._model_feature_cols: List[str] = list(FEATURE_COLS)

        self._rf_loaded = False
        self._ae_loaded = False

        # Load config defaults (weights, threshold) if not explicitly provided
        self._load_config()

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_config(self):
        """Read model weights and threshold from config.yaml, fall back to defaults."""
        try:
            import yaml
            cfg_path = Path("config.yaml")
            if not cfg_path.exists():
                cfg_path = Path(__file__).parent.parent / "config.yaml"
            with open(cfg_path) as f:
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
        """
        Verify feature metadata. Stores the training-time feature list for
        backward-compatible column slicing (FV2/FV3).
        """
        meta_path = self.model_dir / "feature_metadata.joblib"
        if not meta_path.exists():
            # Pre-hash model (trained before FV2/FV3). Reconstruct the
            # original 20-feature set by dropping new features.
            fv2v3 = {"syn_ratio", "fin_ratio", "rst_ratio", "ack_ratio", "psh_ratio",
                     "port_is_web", "port_is_mail", "port_is_admin", "port_is_db", "port_is_dns"}
            self._model_feature_cols = [c for c in FEATURE_COLS if c not in fv2v3]
            logger.warning(
                f"No feature metadata found (pre-hash model). "
                f"Using reconstructed {len(self._model_feature_cols)}-col set."
            )
            return True
        try:
            meta = joblib.load(meta_path)
            self._model_feature_cols = meta.get("feature_cols") or list(FEATURE_COLS)
            stored = meta.get("feature_hash")
            expected = hashlib.md5(":".join(FEATURE_COLS).encode()).hexdigest()
            if stored and stored != expected:
                logger.warning(
                    f"Feature hash mismatch: expected {expected[:12]}..., "
                    f"model has {stored[:12]}... "
                    f"Using model's training-time feature set ({len(self._model_feature_cols)} cols). "
                    f"Re-train to use all {len(FEATURE_COLS)} features."
                )
            else:
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
        model_path   = self.model_dir / "nids_model.joblib"
        onnx_path    = self.model_dir / "nids_model.onnx"
        scaler_path  = self.model_dir / "scaler.joblib"
        if not scaler_path.exists():
            return False
        try:
            self._scaler = joblib.load(scaler_path)
        except Exception as e:
            logger.error(f"RF scaler load failed: {e}")
            return False

        # OP6: try ONNX first, fall back to joblib
        if onnx_path.exists():
            try:
                import onnxruntime as ort
                self._rf_onnx = ort.InferenceSession(str(onnx_path))
                self._rf = None
                logger.info(f"RF loaded from ONNX → {onnx_path}")
                return True
            except Exception as e:
                logger.warning(f"ONNX RF load failed, trying joblib: {e}")
                self._rf_onnx = None

        if model_path.exists():
            try:
                self._rf = joblib.load(model_path)
                logger.info(f"RF loaded from {model_path}")
                return True
            except Exception as e:
                logger.error(f"RF joblib load failed: {e}")
                return False

        logger.warning("No RF model found (no joblib or ONNX)")
        return False

    def _load_ae(self) -> bool:
        ae_path    = self.model_dir / "autoencoder.keras"
        onnx_path  = self.model_dir / "autoencoder.onnx"
        sc_path    = self.model_dir / "ae_scaler.joblib"
        th_path    = self.model_dir / "ae_threshold.joblib"
        cal_path   = self.model_dir / "ae_calibration.joblib"
        if not all(p.exists() for p in [sc_path, th_path]):
            return False
        try:
            self._ae_scaler    = joblib.load(sc_path)
            self._ae_threshold = float(joblib.load(th_path))
        except Exception as e:
            logger.warning(f"AE scaler/threshold load failed: {e}")
            return False

        if cal_path.exists():
            cal = joblib.load(cal_path)
            self._ae_mse_mean = float(cal.get("mse_mean", 0.0))
            self._ae_mse_std  = float(cal.get("mse_std", 1.0))
            logger.info(f"AE calibration loaded (mse_mean={self._ae_mse_mean:.6f}, mse_std={self._ae_mse_std:.6f})")
        else:
            self._ae_mse_mean = 0.0
            self._ae_mse_std  = 1.0
            logger.warning("No AE calibration found — falling back to z-score defaults")

        # OP6: try ONNX first, fall back to keras
        if onnx_path.exists():
            try:
                import onnxruntime as ort
                self._ae_onnx = ort.InferenceSession(str(onnx_path))
                self._ae = None
                logger.info(f"Autoencoder loaded from ONNX → {onnx_path} (threshold={self._ae_threshold:.6f})")
                return True
            except Exception as e:
                logger.warning(f"ONNX AE load failed, trying keras: {e}")
                self._ae_onnx = None

        if ae_path.exists():
            try:
                import tensorflow as tf
                self._ae = tf.keras.models.load_model(str(ae_path))
                logger.info(f"Autoencoder loaded from {ae_path} (threshold={self._ae_threshold:.6f})")
                return True
            except Exception as e:
                logger.warning(f"Keras AE load failed: {e}")
                return False

        logger.warning("No AE model found (no ONNX or keras)")
        return False

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _rf_score(self, X: np.ndarray) -> np.ndarray:
        """Return P(attack) from RF, shape (n,). OP6: ONNX path if available."""
        X_s = self._scaler.transform(X).astype(np.float32)
        if self._rf_onnx is not None:
            input_name = self._rf_onnx.get_inputs()[0].name
            proba = self._rf_onnx.run(None, {input_name: X_s})[1]
            return proba[:, 1]
        return self._rf.predict_proba(X_s)[:, 1]

    def _ae_score(self, X: np.ndarray, X_scaled: np.ndarray = None) -> np.ndarray:
        """
        Return normalised anomaly score from AE, shape (n,).
        Uses threshold-relative scaling: score = mse / (threshold * 2.0).
        At threshold (p95 of benign MSE on calibration set): score = 0.5
        At 2x threshold: score = 1.0
        At mean (typical benign): score ≈ 0.13
        Clipped to [0, 1].
        M2: accepts optional pre-scaled array to avoid double transform.
        M6: ONNX inference path if available.
        """
        X_s = X_scaled if X_scaled is not None else (self._ae_scaler.transform(X) if self._ae_scaler is not None else X)
        X_s = X_s.astype(np.float32)
        if self._ae_onnx is not None:
            input_name = self._ae_onnx.get_inputs()[0].name
            reconstructions = self._ae_onnx.run(None, {input_name: X_s})[0]
        else:
            reconstructions = self._ae.predict(X_s, verbose=0)
        mse = np.mean(np.power(X_s - reconstructions, 2), axis=1)
        normalised = np.clip(mse / (self._ae_threshold * 2.0), 0.0, 1.0)
        return normalised

    def _batch_explain(self, X: np.ndarray, rf_scores: np.ndarray, ae_scores: np.ndarray,
                       ensemble_scores: np.ndarray, X_ae_scaled_full: np.ndarray = None) -> dict:
        """
        Precompute explanations for all anomalous flows in batch.
        Returns {row_index: {driver, features}} for flows with ens >= 0.5.
        M2: accepts optional pre-scaled AE array to avoid double normalisation.
        M3: returns error explanation instead of silent failure.
        """
        anomalous = np.where(ensemble_scores >= 0.5)[0]
        if len(anomalous) == 0:
            return {}

        explanations = {}

        ae_driven = [i for i in anomalous if ae_scores[i] > rf_scores[i]]
        rf_driven = [i for i in anomalous if rf_scores[i] >= ae_scores[i]]

        if ae_driven and (self._ae is not None or self._ae_onnx is not None) and self._ae_scaler is not None:
            ae_idx = np.array(ae_driven)
            try:
                X_ae = X_ae_scaled_full[ae_idx] if X_ae_scaled_full is not None else self._ae_scaler.transform(X[ae_idx])
                X_ae = X_ae.astype(np.float32)
                if self._ae_onnx is not None:
                    input_name = self._ae_onnx.get_inputs()[0].name
                    reconstructions = self._ae_onnx.run(None, {input_name: X_ae})[0]
                else:
                    reconstructions = self._ae.predict(X_ae, verbose=0)
                recon_errors = np.power(X_ae - reconstructions, 2)

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
                for idx in ae_driven:
                    explanations[idx] = {"error": f"AE explanation failed: {e}"}

        if rf_driven and self._scaler is not None:
            rf_idx = np.array(rf_driven)
            try:
                X_rf_scaled = self._scaler.transform(X[rf_idx])

                # Use actual RF feature importances when available (joblib path).
                # ONNX doesn't expose feature_importances_, fall back to scaled values.
                if self._rf is not None and hasattr(self._rf, "feature_importances_"):
                    importances = self._rf.feature_importances_
                else:
                    importances = None

                for j, original_idx in enumerate(rf_driven):
                    if importances is not None:
                        # Weighted by both importance and the sample's scaled value
                        scores = importances * np.abs(X_rf_scaled[j])
                    else:
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
                for idx in rf_driven:
                    explanations[idx] = {"error": f"RF explanation failed: {e}"}

        return explanations

    def _validate_input(self, X: np.ndarray) -> None:
        """Check input quality before scoring. Warns but does not block."""
        n_features = len(self._model_feature_cols)
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
        Backward-compat: uses _model_feature_cols for column slicing.
        """
        if not self._rf_loaded and not self._ae_loaded:
            raise RuntimeError("Call load() before predict()")

        use_cols = self._model_feature_cols
        missing = [c for c in use_cols if c not in feature_df.columns]
        if missing:
            for c in missing:
                feature_df[c] = 0.0
        try:
            X = feature_df[use_cols].to_numpy(dtype=np.float32)
        except KeyError as e:
            raise RuntimeError(
                f"Missing feature column(s): {e}. "
                "FEATURE_COLS changed since model training or feature extraction. "
                "Run feature hash check or re-train."
            ) from e
        self._validate_input(X)

        # M2: transform once, pass to both _ae_score and _batch_explain
        X_ae_scaled = self._ae_scaler.transform(X) if (self._ae_loaded and self._ae_scaler is not None) else None
        rf_scores = self._rf_score(X)  if self._rf_loaded else np.zeros(len(X))
        ae_scores = self._ae_score(X, X_scaled=X_ae_scaled) if self._ae_loaded else np.zeros(len(X))

        if self._rf_loaded and self._ae_loaded:
            rf_w, ae_w = self.rf_weight, self.ae_weight
        elif self._rf_loaded:
            rf_w, ae_w = 1.0, 0.0
        else:
            rf_w, ae_w = 0.0, 1.0

        ensemble_scores = np.clip(rf_w * rf_scores + ae_w * ae_scores, 0.0, 1.0)

        explanations = self._batch_explain(X, rf_scores, ae_scores, ensemble_scores, X_ae_scaled_full=X_ae_scaled)

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
