"""
Universal AI Trainer
--------------------
Unified command to train Random Forest and Deep Autoencoder models.
Combines seed data with live network traffic from SQLite.

Usage:
    python scripts/train.py --precision high
"""

import argparse
import pandas as pd
import numpy as np
import sqlite3
import json
import sys
import os
from pathlib import Path
from loguru import logger
from sklearn.model_selection import train_test_split

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_engine.trainer import train_random_forest, train_autoencoder
from ai_engine.dataset import FEATURE_COLS, load_cicids2017

def fetch_live_data(db_path="data/nids.db"):
    """Extracts labeled flows from the local database."""
    if not Path(db_path).exists():
        logger.warning(f"Database {db_path} not found. Skipping live data.")
        return pd.DataFrame()

    conn = sqlite3.connect(db_path)
    try:
        # Fetch flows and their potential alert labels
        query = """
        SELECT f.raw_json, a.label as alert_label
        FROM flows f
        LEFT JOIN alerts a ON 
            f.src_ip = a.src_ip AND 
            f.dst_ip = a.dst_ip AND 
            f.dst_port = a.dst_port AND
            ABS(f.timestamp - a.timestamp) < 5
        """
        df_raw = pd.read_sql_query(query, conn)
        
        live_features = []
        for _, row in df_raw.iterrows():
            try:
                raw_data = json.loads(row['raw_json'])
                # Re-calculate features using the same logic as our monitor
                # Assuming the raw_json contains the feature-ready fields
                feat = {k: raw_data.get(k, 0) for k in FEATURE_COLS}
                feat['label'] = row['alert_label'] if row['alert_label'] else "BENIGN"
                live_features.append(feat)
            except Exception:
                continue
        
        return pd.DataFrame(live_features)
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="AI-NIDS Model Trainer")
    parser.add_argument("--precision", type=str, default="high", choices=["standard", "high"])
    parser.add_argument("--epochs", type=int, default=100)
    args = parser.parse_args()

    # 1. Load Research Data (CICIDS2017)
    try:
        df_research = load_cicids2017()
        logger.info(f"Loaded {len(df_research):,} research samples (CICIDS2017).")
    except Exception as e:
        logger.error(f"Failed to load research data: {e}. Check scripts/fetch_cicids.py")
        return

    # 2. Load Live Data
    df_live = fetch_live_data()
    if not df_live.empty:
        logger.info(f"Loaded {len(df_live):,} live samples from DB.")
        df_combined = pd.concat([df_research, df_live], ignore_index=True)
    else:
        df_combined = df_research

    # 3. Preprocess
    df_combined["is_attack"] = (df_combined["label"].str.upper() != "BENIGN").astype(int)
    
    # Clean data (NaN/Inf)
    df_combined.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_combined.dropna(inplace=True)
    
    X = df_combined[FEATURE_COLS].values.astype(np.float32)
    y = df_combined["is_attack"].values
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Train Random Forest (Supervised)
    logger.info("+++ PHASE 1: Training Random Forest (Supervised) +++")
    rf_estimators = 500 if args.precision == "high" else 100
    train_random_forest(X_train, y_train, X_test, y_test, n_estimators=rf_estimators)

    # 5. Train Autoencoder (Unsupervised - Benign Only)
    logger.info("+++ PHASE 2: Training Semi-Supervised Autoencoder (Anomaly Detection) +++")
    X_benign = X_train[y_train == 0]
    train_autoencoder(X_benign, X_test, y_test, epochs=args.epochs)

    logger.success("--- HIGH-PRECISION MODELS TRAINED AND SAVED TO data/models/ ---")

if __name__ == "__main__":
    main()
