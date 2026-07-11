"""
================================================================================
EVALUATE — Model Performance Metrics (EV1)
================================================================================
Purpose:
  Loads the trained ensemble model (EnsembleInferenceEngine) and evaluates it
  against labeled CICIDS2017 data and optionally labeled live data from SQLite.

  Reports: accuracy, precision, recall, F1, AUC-ROC, confusion matrix, and
  per-class classification report.

Usage:
  python scripts/evaluate.py
  python scripts/evaluate.py --data-dir data/raw/cicids2017
  python scripts/evaluate.py --model-dir data/models --live-db data/nids.db

Design:
  - Uses EnsembleInferenceEngine.predict() for scoring (matches production path)
  - Fills missing FEATURE_COLS that the engine expects with 0.0
  - Per-class report via sklearn.metrics.classification_report
================================================================================
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import numpy as np
import pandas as pd
import joblib
from loguru import logger
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    classification_report, confusion_matrix,
    roc_auc_score,
)

from core.features import FEATURE_COLS
from ai_engine.dataset import load_cicids2017
from ai_engine.ensemble import EnsembleInferenceEngine


def evaluate_on_data(engine: EnsembleInferenceEngine, df: pd.DataFrame, name: str):
    """Run inference on a labeled DataFrame and print metrics."""
    logger.info(f"Evaluating on {name} ({len(df)} rows)")
    if "label" not in df.columns:
        logger.warning("No 'label' column — skipping evaluation")
        return

    df = df.copy()
    # Fill missing FEATURE_COLS that the engine expects
    use_cols = engine._model_feature_cols
    for c in use_cols:
        if c not in df.columns:
            df[c] = 0.0

    results = engine.predict(df)

    y_true_binary = (df["label"].str.upper() != "BENIGN").astype(int).values[:len(results)]
    y_pred = np.array([r["label"] == "ATTACK" for r in results], dtype=int)
    y_score = np.array([r.get("score", 0.0) for r in results])

    acc = accuracy_score(y_true_binary, y_pred)
    p, r, f1, _ = precision_recall_fscore_support(y_true_binary, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_true_binary, y_pred)

    logger.info(f"─── {name} ───")
    logger.info(f"  Accuracy:  {acc:.4f}")
    logger.info(f"  Precision: {float(p):.4f}")
    logger.info(f"  Recall:    {float(r):.4f}")
    logger.info(f"  F1-Score:  {float(f1):.4f}")
    try:
        auc = roc_auc_score(y_true_binary, y_score)
        logger.info(f"  AUC-ROC:   {auc:.4f}")
    except Exception:
        pass
    logger.info(f"  Confusion Matrix:\n{cm}")

    # Per-class breakdown
    if "label" in df.columns:
        labels = df["label"].values[:len(results)]
        logger.info("Per-class report:\n" +
                    classification_report(labels, ["ATTACK" if p else "BENIGN" for p in y_pred],
                                          zero_division=0))


def main():
    parser = argparse.ArgumentParser(description="EV1: Evaluate trained model")
    parser.add_argument("--model-dir", default="data/models")
    parser.add_argument("--data-dir", default="data/raw/cicids2017")
    parser.add_argument("--live-db", default="data/nids.db", help="Optional labeled live DB")
    args = parser.parse_args()

    engine = EnsembleInferenceEngine(model_dir=args.model_dir)
    if not engine.load():
        logger.error("Failed to load model — aborting.")
        sys.exit(1)

    # CICIDS2017 evaluation
    try:
        df_research = load_cicids2017(args.data_dir)
        evaluate_on_data(engine, df_research, "CICIDS2017")
    except Exception as e:
        logger.error(f"Failed to load CICIDS2017 data: {e}")

    # Live DB evaluation (if available and labeled)
    db_path = Path(args.live_db)
    if db_path.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            df_live = pd.read_sql_query(
                "SELECT raw_json, label FROM alerts WHERE label IS NOT NULL LIMIT 5000", conn
            )
            conn.close()
            if not df_live.empty:
                records = []
                for _, row in df_live.iterrows():
                    try:
                        rec = json.loads(row["raw_json"])
                        rec["label"] = row["label"]
                        records.append(rec)
                    except Exception:
                        continue
                if records:
                    df_live_feats = pd.DataFrame(records)
                    evaluate_on_data(engine, df_live_feats, "Live DB Alerts")
        except Exception as e:
            logger.warning(f"Live DB evaluation skipped: {e}")


if __name__ == "__main__":
    main()
