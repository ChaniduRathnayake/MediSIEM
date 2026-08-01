"""
CAAP AI Server — Phase 6
=========================
Flask server exposing POST /predict.

Loads the three trained models (Random Forest, Isolation Forest, K-Means) plus
the fitted StandardScaler, runs a single flow through all three, computes the
5-dimension Clinical Alert Score (CAS), maps it to an action, and returns a
SHAP-based explanation.

Run:
    python src/app.py

Test:
    curl -X POST http://localhost:5001/predict -H "Content-Type: application/json" -d @sample_row.json
"""

import os
import joblib
import numpy as np
import pandas as pd
import shap
from flask import Flask, request, jsonify
from flask_cors import CORS

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model")

# The 44 core network features the models were trained on, in the exact order
# used during training. Replace this list with the real column order from
# your iomt_train.csv if it differs.
FEATURE_COLUMNS = [
    "flow_bytes_s", "flow_packets_s", "flow_duration",
    "fwd_pkt_len_mean", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_std",
    "bwd_pkt_len_mean", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_std",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    # ... extend to the full 44 — keep in sync with training notebook
]

# Behavioural subset used specifically by Isolation Forest (Phase 4, 9.1)
IF_FEATURES = ["flow_bytes_s", "flow_packets_s", "fwd_pkt_len_mean", "active_mean", "idle_mean"]

# Flow-context subset used by K-Means (Phase 4, 9.3)
KMEANS_FEATURES = ["flow_bytes_s", "flow_packets_s", "flow_iat_mean", "fwd_pkt_len_mean"]

# K-Means cluster label mapping.
# NOTE: empirical testing (Phase 5) showed k=2 gives better cluster separation
# than the originally planned k=3 — "routine" was dropped. If you re-trained
# with k=3, add "routine" back in here and in kmeans.pkl.
CLUSTER_LABELS = {0: "idle", 1: "active"}  # confirm actual index<->label mapping from training

# Clinical Criticality (CC) lookup — rule-based, no ML (Phase 2, Day 4)
CC_LOOKUP = {
    "ICU Ventilator": 5,
    "Infusion Pump": 4,
    "Radiology": 3,
    "Nurse WS": 2,
    "Admin PC": 1,
}
DEFAULT_CC = 1  # unknown device types treated as lowest criticality

# CAS formula weights (Phase 3)
CAS_WEIGHTS = {"TR": 0.25, "CC": 0.30, "TS": 0.25, "AE": 0.10, "TC": 0.10}

# Action thresholds (Phase 6, Day 3)
ACTION_THRESHOLDS = [(8, "Immediate"), (5, "Investigate")]
DEFAULT_ACTION = "Monitor"

# --------------------------------------------------------------------------
# App + model loading
# --------------------------------------------------------------------------

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # tighten origins for production (Node.js on :5000)

print("[CAAP] Loading models...")
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
rf_model = joblib.load(os.path.join(MODEL_DIR, "random_forest.pkl"))
iso_forest = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
kmeans = joblib.load(os.path.join(MODEL_DIR, "kmeans.pkl"))
print("[CAAP] Models loaded.")

# SHAP explainer built once at startup (tree explainer is fast for RF)
shap_explainer = shap.TreeExplainer(rf_model)


# --------------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------------

def to_feature_frame(payload: dict) -> pd.DataFrame:
    """Pull the 44 model features out of the incoming JSON, in training order."""
    row = {col: payload.get(col, 0.0) for col in FEATURE_COLUMNS}
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)


def rf_to_tr_score(confidence: float) -> float:
    """Map Random Forest confidence (0-1) -> Threat Risk score (1-5)."""
    return round(1 + confidence * 4, 2)


def if_to_ts_score(anomaly_score: float, hour_of_day: int) -> float:
    """
    Map Isolation Forest decision_function() output -> Time Sensitivity (1-5).
    score < -0.1  -> anomalous traffic -> TS = 5
    otherwise     -> routine traffic   -> TS driven by time-of-day
                     (off-hours = higher sensitivity, since fewer staff on duty)
    """
    if anomaly_score < -0.1:
        return 5.0
    if hour_of_day < 6 or hour_of_day >= 22:  # night shift, low staffing
        return 3.5
    return 1.5


def lookup_cc(device_type: str) -> float:
    return CC_LOOKUP.get(device_type, DEFAULT_CC)


def lookup_ae(cve_known_exploited: bool) -> float:
    """Active Exploitation — rule based on CVE/CVSS lookup (stubbed input flag)."""
    return 5.0 if cve_known_exploited else 1.0


def lookup_tc(hour_of_day: int) -> float:
    """Temporal Context — shift-based rule (night shift = higher weight)."""
    return 4.0 if (hour_of_day < 6 or hour_of_day >= 22) else 2.0


def compute_cas(tr, cc, ts, ae, tc) -> float:
    cas = (
        CAS_WEIGHTS["TR"] * tr
        + CAS_WEIGHTS["CC"] * cc
        + CAS_WEIGHTS["TS"] * ts
        + CAS_WEIGHTS["AE"] * ae
        + CAS_WEIGHTS["TC"] * tc
    )
    return round(cas, 2)


def cas_to_action(cas: float) -> str:
    for threshold, action in ACTION_THRESHOLDS:
        if cas >= threshold:
            return action
    return DEFAULT_ACTION


def top_shap_features(scaled_row: np.ndarray, n: int = 3) -> str:
    """Return a short text explanation naming the top-N contributing features."""
    shap_values = shap_explainer.shap_values(scaled_row)
    # shap_values shape: (n_classes, 1, n_features) for multi-class RF
    predicted_class_idx = int(np.argmax(rf_model.predict_proba(scaled_row)))
    class_shap = np.array(shap_values)[predicted_class_idx][0]
    top_idx = np.argsort(np.abs(class_shap))[::-1][:n]
    parts = [f"{FEATURE_COLUMNS[i]} ({class_shap[i]:+.2f})" for i in top_idx]
    return "Top contributing features: " + ", ".join(parts)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "models_loaded": True})


@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "Missing or invalid JSON body"}), 400

    try:
        # --- 1. Build feature frame + scale -------------------------------
        X = to_feature_frame(payload)
        X_scaled = scaler.transform(X)

        # --- 2. Random Forest — attack classification (TR) ----------------
        proba = rf_model.predict_proba(X_scaled)[0]
        pred_idx = int(np.argmax(proba))
        label = rf_model.classes_[pred_idx]
        confidence = float(proba[pred_idx])
        tr_score = rf_to_tr_score(confidence)

        # --- 3. Isolation Forest — anomaly detection (TS) -----------------
        X_if = pd.DataFrame([{c: payload.get(c, 0.0) for c in IF_FEATURES}], columns=IF_FEATURES)
        X_if_scaled = scaler.transform(X)[:, [FEATURE_COLUMNS.index(c) for c in IF_FEATURES]]
        anomaly_score = float(iso_forest.decision_function(X_if_scaled)[0])
        hour_of_day = int(payload.get("hour_of_day", 12))
        ts_score = if_to_ts_score(anomaly_score, hour_of_day)

        # --- 4. K-Means — traffic context ----------------------------------
        X_km = scaler.transform(X)[:, [FEATURE_COLUMNS.index(c) for c in KMEANS_FEATURES]]
        cluster_idx = int(kmeans.predict(X_km)[0])
        cluster_label = CLUSTER_LABELS.get(cluster_idx, "unknown")

        # --- 5. Rule-based dimensions (CC, AE, TC) -------------------------
        cc_score = lookup_cc(payload.get("device_type", ""))
        ae_score = lookup_ae(bool(payload.get("cve_known_exploited", False)))
        tc_score = lookup_tc(hour_of_day)

        # --- 6. CAS + action -------------------------------------------------
        cas = compute_cas(tr_score, cc_score, ts_score, ae_score, tc_score)
        action = cas_to_action(cas)

        # --- 7. SHAP explanation --------------------------------------------
        explanation = top_shap_features(X_scaled)

        return jsonify({
            "label": label,
            "confidence": round(confidence, 4),
            "TR_score": tr_score,
            "TS_score": ts_score,
            "cluster": cluster_label,
            "CC_score": cc_score,
            "AE_score": ae_score,
            "TC_score": tc_score,
            "CAS": cas,
            "action": action,
            "explanation": explanation,
        })

    except Exception as exc:  # keep the API resilient; log for debugging
        app.logger.exception("Prediction failed")
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    # Node.js backend runs on :5000 — Flask AI layer on :5001 (Phase 6, Day 5)
    app.run(host="0.0.0.0", port=5001, debug=True)
