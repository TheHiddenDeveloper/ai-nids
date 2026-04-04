#!/usr/bin/env python3
import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from loguru import logger

sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_engine.dataset import FEATURE_COLS, CICIDS_COLUMN_MAP
from ai_engine.trainer import train_random_forest, train_autoencoder
from sklearn.model_selection import train_test_split

def load_hybrid_datasets(data_dir: str, max_samples: int = None):
    p = Path(data_dir)
    csv_files = list(p.rglob("*.csv"))
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files located anywhere in {data_dir}")
        
    dfs = []
    logger.info(f"Targeting {len(csv_files)} CSV files for Hybrid Training...")
    
    for f in csv_files:
        try:
            logger.info(f"  Reading {f.name}...")
            df = pd.read_csv(f, low_memory=False)
            # Standardize raw whitespace
            df.columns = df.columns.str.strip()
            
            # THE TRANSLATOR: Auto-translate if this is a CIC-style formatted dataset
            df.rename(columns=CICIDS_COLUMN_MAP, inplace=True)
            
            if "label" in df.columns:
                df["label"] = df["label"].astype(str).str.strip()
            else:
                logger.warning(f"  [!] {f.name} has no valid 'label' column. Dropping.")
                continue
                
            dfs.append(df)
        except Exception as e:
            logger.warning(f"Could not safely load {f.name}: {e}")
            
    if not dfs:
        raise ValueError("No valid data loaded from the CSV files.")
        
    combined = pd.concat(dfs, ignore_index=True)
    
    if max_samples and len(combined) > max_samples:
        logger.info(f"Downsampling from {len(combined):,} to {max_samples:,} rows...")
        combined = combined.sample(n=max_samples, random_state=42)
        
    # Purge infinite math / bad rows cleanly before casting ML array
    combined.replace([np.inf, -np.inf], 0, inplace=True)
    combined.dropna(subset=["label"] + [c for c in FEATURE_COLS if c in combined.columns], inplace=True)
    
    combined["is_attack"] = (combined["label"].str.upper() != "BENIGN").astype(int)
    logger.info(f"Final Hybrid Dataset compiled: {len(combined):,} mathematical samples")
    return combined

def main():
    p = argparse.ArgumentParser(description="Hybrid Universal NIDS Trainer")
    p.add_argument("--data-dir", default="data/raw/", help="Directory containing all CSV chunks recursively")
    p.add_argument("--max-samples", type=int, default=500000, help="Downsample limit to prevent RAM crashes (default 500k, 0 to disable)")
    args = p.parse_args()
    
    max_count = args.max_samples if args.max_samples > 0 else None
    
    logger.info(f"Scanning target node: {args.data_dir} ...")
    df = load_hybrid_datasets(args.data_dir, max_samples=max_count)
    
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        logger.error(f"Hybrid Dataset is missing required canonical features: {missing}")
        logger.error("Make sure your dataset contains these columns, or adjust the dataset parser.")
        sys.exit(1)
        
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["is_attack"].values
    
    # Needs minimum variance 
    counts = np.bincount(y) if len(y) > 0 else []
    if len(counts) < 2 or counts[0] == 0 or counts[1] == 0:
        logger.error(f"Dataset lacks class balance! Count map: Benign={counts[0] if len(counts)>0 else 0}, Attack={counts[1] if len(counts)>1 else 0}")
        sys.exit(1)
        
    if len(y) > 50:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        logger.info("⚙️ Commencing Mega-Ensemble Random Forest Assembly...")
        train_random_forest(X_train, y_train, X_test, y_test)
        
        logger.info("⚙️ Commencing Mega-Ensemble Autoencoder Assembly...")
        benign_mask = (y_train == 0)
        X_train_benign = X_train[benign_mask]
        
        if len(X_train_benign) > 0:
            train_autoencoder(X_train_benign, X_test, y_test)
        else:
            logger.warning("No benign traffic logged. Skipping Autoencoder.")
    else:
        logger.error("Dataset vastly too small. Capture more network data.")

if __name__ == "__main__":
    main()
