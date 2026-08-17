# Shared loading/scoring helpers for 05_evaluation.ipynb. Deliberately not
# importing train.py (re-trains and overwrites models/ as an import side
# effect) — only loads already-trained artifacts, with the same eval
# conventions (filename->label mapping, purity/IF-accuracy) copied here as
# pure functions so evaluation can't mutate the production model files.
import glob
import os
import re
import time

import joblib
import numpy as np
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AI_SERVER_DIR = os.path.dirname(SCRIPT_DIR)
MODEL_DIR = os.path.join(AI_SERVER_DIR, "models")
DATA_DIR = os.path.join(AI_SERVER_DIR, "data")
REPORT_DIR = os.path.join(AI_SERVER_DIR, "reports")

# Identical to train.py's LABEL_MAP — kept in sync so ground-truth labels for
# evaluation match what the models were actually trained against.
LABEL_MAP = [
    (r"benign", "Benign"),
    (r"^arp_spoofing", "ARP_Spoofing"),
    (r"arp.*spoof", "ARP_Spoofing"),
    (r"^mqtt.*flood", "MQTT_Publish_Flood"),
    (r"^mqtt.*malformed", "MQTT_Brute_Force"),
    (r"mqtt.*flood", "MQTT_Publish_Flood"),
    (r"mqtt.*malformed", "MQTT_Brute_Force"),
    (r"^mqtt", "MQTT_Publish_Flood"),
    (r"^recon", "Recon"),
    (r"recon", "Recon"),
    (r"^tcp_ip.*(dos|ddos).*(syn|tcp|icmp|udp)", "DoS_TCP"),
    (r"tcp.ip.*(dos|ddos).*(syn|tcp|icmp|udp)", "DoS_TCP"),
]


def filename_to_label(fname: str) -> str:
    stem = os.path.splitext(os.path.basename(fname))[0].lower()
    stem = re.sub(r"[_\-](train|test)(\.pcap)?$", "", stem)
    stem = re.sub(r"\.pcap$", "", stem)
    for pattern, label in LABEL_MAP:
        if re.search(pattern, stem, re.IGNORECASE):
            return label
    return stem.replace("-", "_").replace(" ", "_").title()


def load_artifacts() -> dict:
    """Load every trained artifact in models/ — never fit/refit anything here."""
    rf = joblib.load(os.path.join(MODEL_DIR, "random_forest.pkl"))
    iso = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    km = joblib.load(os.path.join(MODEL_DIR, "kmeans.pkl"))
    # Trained with verbose=1 (see train.py) — that setting is part of the
    # pickled estimator, so predict() re-emits training-style joblib.Parallel
    # progress logs unless silenced here. Logging verbosity only, no effect
    # on predictions.
    for est in (rf, iso, km):
        if hasattr(est, "verbose"):
            est.verbose = 0
    return {
        "rf": rf,
        "iso": iso,
        "km": km,
        "scaler": joblib.load(os.path.join(MODEL_DIR, "scaler.pkl")),
        "le": joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl")),
        "feature_cols": list(joblib.load(os.path.join(MODEL_DIR, "feature_cols.pkl"))),
        "if_threshold": joblib.load(os.path.join(MODEL_DIR, "if_threshold.pkl")),
    }


def load_csv_dir(directory: str) -> pd.DataFrame:
    """Glob every *.csv in `directory`, label each by filename, concatenate.
    Same convention as train.py's load_and_merge() for data/test."""
    csv_files = sorted(glob.glob(os.path.join(directory, "*.csv")))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {os.path.abspath(directory)}")
    frames = []
    for f in csv_files:
        try:
            df = pd.read_csv(f, low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(f, encoding="latin1", low_memory=False)
        df["label"] = filename_to_label(f)
        df["__source_file"] = os.path.basename(f)
        frames.append(df)
    combined = pd.concat(frames, ignore_index=True)
    combined.columns = combined.columns.str.strip()
    combined.dropna(how="all", inplace=True)
    return combined.reset_index(drop=True)


def load_iomt_test_set() -> pd.DataFrame:
    """The 'IoMT test set' referenced throughout Phase 9 — every CSV under
    data/test/*.csv concatenated, exactly how test.py builds its own test set
    (no single iomt_test.csv file exists in this repo)."""
    return load_csv_dir(os.path.join(DATA_DIR, "test"))


def prepare_features(df: pd.DataFrame, feature_cols: list, scaler) -> np.ndarray:
    """Select the exact trained feature columns (order matters), coerce numeric,
    and apply the ALREADY-FITTED scaler (never refit — refitting here would
    silently invalidate every saved model's decision boundary).

    train.py/test.py drop any row with a non-numeric feature value instead of
    fillna(0.0)-ing it; this function can't safely do the same, because its
    one caller (hospital_scenarios.py's build_scenario()) aligns this
    function's output back to the input `df` by positional index — dropping
    rows here without also filtering the caller's `rows`/`tiers`/`shifts` in
    lockstep would silently misalign ground-truth labels against predictions,
    which is worse than a zero-filled outlier. Surfacing the count instead so
    a divergence from train.py's dropna() is visible rather than silent.
    """
    coerced = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    n_bad = int(coerced.isna().sum().sum())
    if n_bad:
        print(f"[prepare_features] WARNING: {n_bad} non-numeric feature value(s) across "
              f"{int(coerced.isna().any(axis=1).sum())} row(s) coerced to 0.0 instead of dropped "
              f"(train.py/test.py would drop these rows) — evaluation metrics may be skewed.")
    X_raw = coerced.fillna(0.0).values.astype(np.float64)
    return scaler.transform(X_raw)


def clustering_purity(true_labels, cluster_ids) -> float:
    """Majority-vote purity — identical definition to train.py's."""
    df = pd.DataFrame({"true": true_labels, "cluster": cluster_ids})
    correct = 0
    for cid in df["cluster"].unique():
        subset = df.loc[df["cluster"] == cid, "true"]
        if len(subset) == 0:
            continue
        correct += subset.value_counts().iloc[0]
    return correct / len(df)


def if_binary_accuracy(y_pred_iso_arr, y_true_raw_arr) -> float:
    """Identical definition to train.py's — IF anomaly flag vs true Benign/Attack."""
    pred_attack = (np.asarray(y_pred_iso_arr) == -1).astype(int)
    true_attack = (np.asarray(y_true_raw_arr) != "Benign").astype(int)
    return (pred_attack == true_attack).mean()


def run_full_pipeline(X_scaled: np.ndarray, artifacts: dict) -> pd.DataFrame:
    """RF + IF + K-Means over an already-scaled feature matrix — the same three
    models the live CAAP dashboard calls per alert. Returns one row per input
    row with every raw model output (label, confidence, iso_score, anomaly
    flag, cluster) needed to feed cas_engine.score_alert()."""
    rf, iso, km, le = artifacts["rf"], artifacts["iso"], artifacts["km"], artifacts["le"]
    if_threshold = artifacts["if_threshold"]

    t0 = time.perf_counter()
    y_pred_idx = rf.predict(X_scaled)
    y_proba = rf.predict_proba(X_scaled)
    rf_elapsed = time.perf_counter() - t0

    predicted_label = le.inverse_transform(y_pred_idx)
    confidence = y_proba.max(axis=1)

    t0 = time.perf_counter()
    iso_scores = iso.decision_function(X_scaled)
    iso_elapsed = time.perf_counter() - t0
    is_anomaly = iso_scores < if_threshold

    t0 = time.perf_counter()
    cluster_idx = km.predict(X_scaled)
    km_elapsed = time.perf_counter() - t0

    return pd.DataFrame({
        "predicted_label": predicted_label,
        "confidence": confidence,
        "iso_score": iso_scores,
        "is_anomaly": is_anomaly,
        "cluster": cluster_idx,
    }), {"rf_seconds": rf_elapsed, "iso_seconds": iso_elapsed, "km_seconds": km_elapsed, "n_rows": len(X_scaled)}
