"""Loads the trained model once and exposes predict_flow() for the API."""
import os
from functools import lru_cache

from joblib import load

from .train import engineer_features, FEATURES, MODEL_PATH
import pandas as pd


@lru_cache(maxsize=1)
def _load_bundle():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"No trained model found at {MODEL_PATH}. Run: python -m app.ml.train"
        )
    return load(MODEL_PATH)


def predict_flow(flow: dict) -> tuple[str, float]:
    """flow needs: source_port, dest_port, protocol, packet_count, total_bytes, duration
    Returns (predicted_label, confidence_score)."""
    bundle = _load_bundle()
    model, scaler, le = bundle["model"], bundle["scaler"], bundle["label_encoder"]

    df = pd.DataFrame([flow])
    df = engineer_features(df)
    X = df[FEATURES]
    X_scaled = scaler.transform(X)

    proba = model.predict_proba(X_scaled)[0]
    pred_idx = proba.argmax()
    label = le.inverse_transform([pred_idx])[0]
    confidence = float(proba[pred_idx])

    return label, confidence


def model_is_ready() -> bool:
    return os.path.exists(MODEL_PATH)
