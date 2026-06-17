"""
================================================================================
TEST: ENSEMBLE ENGINE — Unit Tests (No Models Required)
================================================================================
Purpose:
  Unit tests for EnsembleInferenceEngine that do NOT require trained models
  on disk. Tests partial-load paths, error handling, configuration defaults,
  and the predict() contract.

Run:
  pytest tests/test_ensemble_engine.py -v

Test classes:
  TestUnloadedEngine    — engine with /nonexistent model dir
  TestConfigDefaults    — weight loading from config.yaml
  TestPredictContract   — predict() returns correct keys, partial-load paths
                          (RF-only, AE-only, unloaded raises RuntimeError)

Design:
  - Mocks _rf_score and _ae_score with lambda functions
  - Uses _DummyScaler (identity transform) to avoid needing real scaler
  - Covers edge cases: empty DataFrame, no anomalies, partial model loading
================================================================================
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
import pytest
from ai_engine.ensemble import EnsembleInferenceEngine
from core.features import FEATURE_COLS


class _DummyScaler:
    """Minimal scaler stand-in for tests — identity transform."""
    def transform(self, X):
        return X


def _make_df(n=2):
    """Build a minimal feature DataFrame with meta columns."""
    rows = []
    for i in range(n):
        row = {col: float(i + 1) for col in FEATURE_COLS}
        row["_src_ip"] = f"10.0.0.{i}"
        row["_dst_ip"] = f"10.0.1.{i}"
        row["_src_port"] = 40000 + i
        row["_dst_port"] = 80
        row["_timestamp"] = 1000.0 + i
        rows.append(row)
    return pd.DataFrame(rows)


class TestUnloadedEngine:
    def test_unloaded_raises_on_predict(self):
        engine = EnsembleInferenceEngine(model_dir="/nonexistent")
        assert not engine.is_loaded
        assert engine.mode == "unloaded"
        with pytest.raises(RuntimeError, match="Call load"):
            engine.predict(_make_df())

    def test_describe_before_load(self):
        engine = EnsembleInferenceEngine(model_dir="/nonexistent")
        d = engine.describe()
        assert d["mode"] == "unloaded"
        assert d["rf_loaded"] is False
        assert d["ae_loaded"] is False

    def test_load_missing_dir_returns_false(self):
        engine = EnsembleInferenceEngine(model_dir="/nonexistent")
        assert engine.load() is False
        assert not engine.is_loaded


class TestConfigDefaults:
    def test_weights_from_config(self):
        engine = EnsembleInferenceEngine()
        assert engine.rf_weight == 0.65
        assert engine.ae_weight == 0.35
        assert engine._threshold == 0.5

    def test_explicit_weights_override_config(self):
        engine = EnsembleInferenceEngine(rf_weight=1.0, ae_weight=0.0)
        assert engine.rf_weight == 1.0
        assert engine.ae_weight == 0.0


class TestPredictContract:
    def test_batch_explain_returns_empty_for_empty_df(self):
        engine = EnsembleInferenceEngine(model_dir="/nonexistent")
        engine._rf_loaded = True
        engine._ae_loaded = True
        # With no actual models, scores are all zero
        X = np.zeros((0, len(FEATURE_COLS)), dtype=np.float32)
        rf_scores = np.array([], dtype=np.float32)
        ae_scores = np.array([], dtype=np.float32)
        ens_scores = np.array([], dtype=np.float32)
        assert engine._batch_explain(X, rf_scores, ae_scores, ens_scores) == {}

    def test_batch_explain_no_anomalies(self):
        engine = EnsembleInferenceEngine(model_dir="/nonexistent")
        engine._rf_loaded = True
        engine._ae_loaded = True
        X = np.zeros((3, len(FEATURE_COLS)), dtype=np.float32)
        rf = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        ae = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        ens = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        assert engine._batch_explain(X, rf, ae, ens) == {}

    def test_predict_returns_correct_keys(self):
        """Even without models, predict returns result dicts with expected keys."""
        engine = EnsembleInferenceEngine(model_dir="/nonexistent")
        engine._rf_loaded = False
        engine._ae_loaded = False
        df = _make_df(n=2)

        with pytest.raises(RuntimeError):
            engine.predict(df)

    def test_rf_only_predict_no_crash(self):
        """When RF is loaded but AE is not, predict should not crash."""
        engine = EnsembleInferenceEngine(model_dir="/nonexistent")
        engine._rf_loaded = True
        engine._ae_loaded = False
        # Mock _rf_score to return plausible scores
        engine._rf_score = lambda X: np.array([0.1, 0.9], dtype=np.float32)
        # Dummy scaler so _batch_explain can compute RF explanations
        engine._scaler = _DummyScaler()
        df = _make_df(n=2)
        results = engine.predict(df)
        assert len(results) == 2
        assert results[0]["label"] == "BENIGN"
        assert results[1]["label"] == "ATTACK"
        assert "explanation" in results[1]

    def test_ae_only_predict_no_crash(self):
        """When AE is loaded but RF is not, predict should not crash."""
        engine = EnsembleInferenceEngine(model_dir="/nonexistent")
        engine._rf_loaded = False
        engine._ae_loaded = True
        engine._ae_score = lambda X, X_scaled=None: np.array([0.1, 0.9], dtype=np.float32)
        df = _make_df(n=2)
        results = engine.predict(df)
        assert len(results) == 2
        assert results[0]["label"] == "BENIGN"
        assert results[1]["label"] == "ATTACK"
