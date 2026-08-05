"""
Trains a RandomForest classifier for the IDS.

By default this generates a synthetic-but-realistic flow dataset (since
CICIDS2017 is a multi-GB download not available in every environment) so the
whole project works out of the box. To use real data instead:

    1. Download CICIDS2017 CSVs (https://www.unb.ca/cic/datasets/ids-2017.html)
    2. Put them in backend/dataset/
    3. Run: python -m app.ml.train --csv dataset/your_file.csv

Either way this produces backend/app/ml/model.joblib, which app/ml/predict.py
loads at request time.
"""
import argparse
import os

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

FEATURES = [
    "source_port",
    "dest_port",
    "protocol_num",
    "packet_count",
    "total_bytes",
    "duration",
    "bytes_per_packet",
    "packets_per_second",
]

LABELS = ["normal", "dos", "ddos", "port_scan", "brute_force"]

MODEL_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(MODEL_DIR, "model.joblib")


def generate_synthetic_dataset(n_per_class: int = 1200, seed: int = 42) -> pd.DataFrame:
    """Generate labeled flow records with distributions loosely modeled on
    known traffic patterns (normal browsing vs DoS floods vs port scans etc)."""
    rng = np.random.default_rng(seed)
    rows = []

    def add(label, n, **dists):
        for _ in range(n):
            row = {}
            for k, v in dists.items():
                val = v()
                row[k] = max(0, val) if isinstance(val, (int, float, np.integer, np.floating)) else val
            row["label"] = label
            rows.append(row)

    # Normal traffic: moderate size, varied ports, moderate duration
    add(
        "normal", n_per_class,
        source_port=lambda: rng.integers(1024, 65535),
        dest_port=lambda: rng.choice([80, 443, 22, 53, 8080]),
        protocol=lambda: rng.choice(["TCP", "UDP"]),
        packet_count=lambda: rng.integers(5, 60),
        total_bytes=lambda: rng.normal(8000, 3000),
        duration=lambda: rng.normal(2.0, 1.0),
    )

    # DoS: high packet rate, short duration, single target port, small packets
    add(
        "dos", n_per_class,
        source_port=lambda: rng.integers(1024, 65535),
        dest_port=lambda: rng.choice([80, 443]),
        protocol=lambda: "TCP",
        packet_count=lambda: rng.integers(500, 5000),
        total_bytes=lambda: rng.normal(60000, 15000),
        duration=lambda: rng.normal(0.5, 0.2),
    )

    # DDoS: like DoS but even higher volume, very short duration
    add(
        "ddos", n_per_class,
        source_port=lambda: rng.integers(1, 65535),
        dest_port=lambda: rng.choice([80, 443, 53]),
        protocol=lambda: rng.choice(["TCP", "UDP"]),
        packet_count=lambda: rng.integers(2000, 20000),
        total_bytes=lambda: rng.normal(300000, 80000),
        duration=lambda: rng.normal(0.2, 0.1),
    )

    # Port scan: tiny packets, many distinct low-numbered dest ports, near-zero bytes
    add(
        "port_scan", n_per_class,
        source_port=lambda: rng.integers(1024, 65535),
        dest_port=lambda: rng.integers(1, 1024),
        protocol=lambda: "TCP",
        packet_count=lambda: rng.integers(1, 4),
        total_bytes=lambda: rng.normal(120, 60),
        duration=lambda: rng.normal(0.05, 0.03),
    )

    # Brute force: repeated small requests to a single auth port over longer duration
    add(
        "brute_force", n_per_class,
        source_port=lambda: rng.integers(1024, 65535),
        dest_port=lambda: rng.choice([22, 21, 3389, 445]),
        protocol=lambda: "TCP",
        packet_count=lambda: rng.integers(50, 400),
        total_bytes=lambda: rng.normal(15000, 4000),
        duration=lambda: rng.normal(5.0, 2.0),
    )

    df = pd.DataFrame(rows)
    df["total_bytes"] = df["total_bytes"].clip(lower=1)
    df["duration"] = df["duration"].clip(lower=0.01)
    df["packet_count"] = df["packet_count"].clip(lower=1)
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    df["protocol_num"] = df["protocol"].map(protocol_map).fillna(0).astype(int)
    df["bytes_per_packet"] = df["total_bytes"] / df["packet_count"].replace(0, 1)
    df["packets_per_second"] = df["packet_count"] / df["duration"].replace(0, 0.01)
    return df


def train(csv_path: str | None = None) -> dict:
    if csv_path:
        df = pd.read_csv(csv_path)
        # Expect columns matching FEATURES (minus engineered ones) + 'label'
    else:
        df = generate_synthetic_dataset()

    df = engineer_features(df)

    X = df[FEATURES]
    y = df["label"]

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=15, random_state=42, n_jobs=-1
    )
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    report = classification_report(
        y_test, y_pred, target_names=le.classes_, output_dict=True, zero_division=0
    )

    dump({"model": clf, "scaler": scaler, "label_encoder": le, "features": FEATURES}, MODEL_PATH)

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the IDS RandomForest model")
    parser.add_argument("--csv", default=None, help="Path to a real labeled flow CSV")
    args = parser.parse_args()

    result = train(args.csv)
    print(f"✓ Model trained and saved to {MODEL_PATH}")
    print(f"  Accuracy: {result['accuracy']:.4f}")
    for label in LABELS:
        if label in result:
            print(f"  {label:12s} precision={result[label]['precision']:.2f} recall={result[label]['recall']:.2f}")
