"""
Model Trainer
-------------
Trains a Random Forest classifier and/or Autoencoder on CICIDS2017.
Saves trained models + scaler to data/models/.
"""

import joblib
import numpy as np
from pathlib import Path
from loguru import logger

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    n_estimators: int = 200,
    max_depth: int = 20,
    model_dir: str = "data/models",
) -> tuple:
    """
    Train a Random Forest binary classifier.
    Uses SMOTE to handle class imbalance (attacks << benign).
    Returns (model, scaler).
    """
    Path(model_dir).mkdir(parents=True, exist_ok=True)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    logger.info("Applying SMOTE to balance classes...")
    sm = SMOTE(random_state=42)
    X_res, y_res = sm.fit_resample(X_train_s, y_train)
    logger.info(f"After SMOTE: {len(X_res):,} samples")

    logger.info(f"Training Random Forest (n_estimators={n_estimators}, max_depth={max_depth})...")
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    rf.fit(X_res, y_res)

    y_pred = rf.predict(X_test_s)
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))
    logger.info(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

    model_path = Path(model_dir) / "nids_model.joblib"
    scaler_path = Path(model_dir) / "scaler.joblib"
    joblib.dump(rf, model_path)
    joblib.dump(scaler, scaler_path)
    logger.info(f"Saved model → {model_path}")
    logger.info(f"Saved scaler → {scaler_path}")

    return rf, scaler


def train_autoencoder(
    X_train_benign: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_dir: str = "data/models",
    epochs: int = 30,
    threshold_percentile: float = 95.0,
) -> tuple:
    """
    Train an Autoencoder on BENIGN traffic only.
    Flags anomalies when reconstruction error exceeds the threshold.
    Returns (autoencoder, threshold).
    """
    try:
        import tensorflow as tf
        from tensorflow import keras
    except ImportError:
        logger.error("tensorflow not installed: pip install tensorflow")
        return None, None

    Path(model_dir).mkdir(parents=True, exist_ok=True)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train_benign)
    X_test_s = scaler.transform(X_test)

    n_features = X_train_s.shape[1]

    inputs = keras.Input(shape=(n_features,))
    x = keras.layers.Dense(32, activation="relu")(inputs)
    x = keras.layers.Dense(16, activation="relu")(x)
    x = keras.layers.Dense(8, activation="relu")(x)
    x = keras.layers.Dense(16, activation="relu")(x)
    x = keras.layers.Dense(32, activation="relu")(x)
    outputs = keras.layers.Dense(n_features, activation="linear")(x)

    autoencoder = keras.Model(inputs, outputs)
    autoencoder.compile(optimizer="adam", loss="mse")

    logger.info("Training Autoencoder on benign traffic only...")
    autoencoder.fit(
        X_train_s, X_train_s,
        epochs=epochs,
        batch_size=256,
        validation_split=0.1,
        verbose=1,
    )

    reconstructions = autoencoder.predict(X_test_s)
    mse = np.mean(np.power(X_test_s - reconstructions, 2), axis=1)
    threshold = float(np.percentile(mse, threshold_percentile))
    logger.info(f"Anomaly threshold (p{threshold_percentile}): {threshold:.6f}")

    y_pred = (mse > threshold).astype(int)
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))

    ae_path = Path(model_dir) / "autoencoder.keras"
    autoencoder.save(ae_path)
    joblib.dump(scaler, Path(model_dir) / "ae_scaler.joblib")
    joblib.dump(threshold, Path(model_dir) / "ae_threshold.joblib")
    logger.info(f"Saved autoencoder → {ae_path}")

    return autoencoder, threshold
