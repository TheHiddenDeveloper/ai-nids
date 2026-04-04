#!/usr/bin/env python3
import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from loguru import logger

sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_engine.dataset import FEATURE_COLS
from ai_engine.trainer import train_random_forest, train_autoencoder
from sklearn.model_selection import train_test_split

def load_custom_dataset(benign_csv: str, attack_csv: str):
    dfs = []
    for f in [benign_csv, attack_csv]:
        if Path(f).exists():
            logger.info(f"Found dataset: {f}")
            df = pd.read_csv(f)
            dfs.append(df)
        else:
            logger.warning(f"File {f} not found!")
            
    if not dfs:
        raise FileNotFoundError("Could not locate benign or attack dataset CSVs.")
        
    combined = pd.concat(dfs, ignore_index=True)
    combined.replace([np.inf, -np.inf], 0, inplace=True)
    combined.fillna(0, inplace=True)
    
    combined["is_attack"] = (combined["label"].str.upper() != "BENIGN").astype(int)
    logger.info(f"Combined dataset: {len(combined)} total samples")
    return combined
    
def main():
    p = argparse.ArgumentParser(description="Locally retraining AI NIDS models")
    p.add_argument("--benign", default="data/raw/benign.csv")
    p.add_argument("--attack", default="data/raw/attack.csv")
    args = p.parse_args()
    
    logger.info("Loading local JSONL / CSV datasets...")
    df = load_custom_dataset(args.benign, args.attack)
    
    # Check features alignment
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        logger.error(f"Dataset is missing required canonical features: {missing}")
        sys.exit(1)
        
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["is_attack"].values
    
    # Check if there's enough data for SMOTE (requires at least 1 attack and 1 benign, usually more)
    counts = np.bincount(y) if len(y) > 0 else []
    if len(counts) < 2 or counts[0] == 0 or counts[1] == 0:
        logger.error("Need BOTH benign and attack samples to train Random Forest classifiers!")
        
    if len(y) > 10:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        logger.info("⚙️ Commencing Local Random Forest Assembly...")
        train_random_forest(X_train, y_train, X_test, y_test)
        
        logger.info("⚙️ Commencing Local Benign-Only Autoencoder Assembly...")
        benign_mask = (y_train == 0)
        X_train_benign = X_train[benign_mask]
        
        if len(X_train_benign) > 0:
            train_autoencoder(X_train_benign, X_test, y_test)
        else:
            logger.warning("No benign traffic found! Skipping Autoencoder.")
    else:
        logger.error("Dataset vastly too small. Capture more network data.")

if __name__ == "__main__":
    main()
