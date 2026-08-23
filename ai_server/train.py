# CAAP IoMT IDS training script (Random Forest + Isolation Forest + K-Means).
# Drop pcap CSVs into data/train/ and data/test/ — labels are derived from
# filenames, FEATURE_COLS from whatever numeric columns are actually present.
# Isolation Forest is fit one-class (Benign rows only), per standard practice
# for unsupervised anomaly detectors.
# Author: R.M.C.B. Rathnayake | IT22061270 | SLIIT Cyber Security
# Usage: python train.py  ->  models/*.pkl, reports/*.png, reports/classification_report.txt

import os, re, sys, warnings, time, glob, datetime, json, hashlib
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Windows consoles default stdout to the system codepage (cp1252), which
# can't encode the ✓/✗/⚠/✅ markers this script prints throughout — would
# crash a multi-hour training run partway through on a stock Windows shell
# (this project's primary platform) instead of just displaying oddly.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, roc_auc_score, silhouette_score,
    roc_curve, auc as auc_score,
)
from sklearn.utils.class_weight import compute_sample_weight

warnings.filterwarnings("ignore")

# ── CONFIG ────────────────────────────────────────────────────────────────────
# Env-var overrides (defaults unchanged for the normal `python train.py` flow)
# so CI can point TRAIN/TEST_DIR at a tiny committed fixture set instead of the
# real (gitignored) dataset, and retrain_pipeline.py can point MODEL/REPORT_DIR
# at a staging directory instead of overwriting the live deployed models.
TRAIN_DIR  = os.environ.get("TRAIN_DATA_DIR", "data/train")
TEST_DIR   = os.environ.get("TEST_DATA_DIR", "data/test")
MODEL_DIR  = os.environ.get("MODEL_OUT_DIR", "models")
REPORT_DIR = os.environ.get("REPORT_OUT_DIR", "reports")
N_CLUSTERS = 2

# Verified against the actual fitted kmeans.pkl centroids (Tot sum/Tot size/AVG/
# Duration are all near-zero for cluster 0 across 98.7% of samples, and several
# std devs above the mean for cluster 1's remaining 1.3%) — 0 is the idle/
# baseline traffic cluster, 1 is the high-volume/active one. Must match
# src/app.py's CLUSTER_LABELS exactly; this dict was previously inverted
# relative to app.py, which had it right.
CLUSTER_LABELS = {0: "idle", 1: "active"}

# ── LABEL MAP: filename prefix → canonical label ──────────────────────────────
LABEL_MAP = [
    (r"benign",                      "Benign"),              # ← unanchored: catches
                                                               #   protocol-prefixed names
                                                               #   like "WiFI_and_MQTT-Benign-train..."
    (r"^arp_spoofing",               "ARP_Spoofing"),
    (r"arp.*spoof",                  "ARP_Spoofing"),
    (r"^mqtt.*flood",                "MQTT_Publish_Flood"),
    (r"^mqtt.*malformed",            "MQTT_Brute_Force"),
    (r"mqtt.*flood",                 "MQTT_Publish_Flood"),
    (r"mqtt.*malformed",             "MQTT_Brute_Force"),
    (r"^mqtt",                       "MQTT_Publish_Flood"),
    (r"^recon",                      "Recon"),
    (r"recon",                       "Recon"),
    (r"^tcp_ip.*(dos|ddos).*(syn|tcp|icmp|udp)", "DoS_TCP"),
    (r"tcp.ip.*(dos|ddos).*(syn|tcp|icmp|udp)",  "DoS_TCP"),
]

def filename_to_label(fname: str) -> str:
    """Derive label from a pcap CSV filename."""
    stem = os.path.splitext(os.path.basename(fname))[0].lower()
    stem = re.sub(r"[_\-](train|test)(\.pcap)?$", "", stem)
    stem = re.sub(r"\.pcap$", "", stem)
    for pattern, label in LABEL_MAP:
        if re.search(pattern, stem, re.IGNORECASE):
            return label
    return stem.replace("-", "_").replace(" ", "_").title()


# ── HELPERS ───────────────────────────────────────────────────────────────────
os.makedirs(MODEL_DIR,  exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
t_start = time.time()


def load_and_merge(directory: str) -> pd.DataFrame:
    """
    Reads every *.csv in `directory`. Raw pcap-derived CSVs have no 'label'
    column of their own, so those get one label for the whole file, derived
    from the filename. A CSV that already has a 'label' column — e.g. an
    admin's GET /api/alerts/training-feedback-export download, which mixes
    per-row verdict-derived labels (true-positive rows keep their original
    predicted attack label, false-positive/benign rows become "Benign")
    within a single file — keeps its own per-row labels untouched instead.
    Concatenates everything, drops NaNs, and returns the combined DataFrame.
    """
    csv_files = sorted(glob.glob(os.path.join(directory, "*.csv")))
    if not csv_files:
        raise FileNotFoundError(
            f"\n  ✗ No CSV files found in: {os.path.abspath(directory)}\n"
            f"  → Place your pcap CSV files there and re-run.\n"
        )

    frames = []
    for f in csv_files:
        try:
            df = pd.read_csv(f, low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(f, encoding="latin1", low_memory=False)

        if "label" in df.columns:
            counts = ", ".join(f"{v}×{c}" for v, c in df["label"].value_counts().items())
            frames.append(df)
            print(f"    {os.path.basename(f):<55}  {len(df):>8,} rows  →  per-row labels ({counts})")
        else:
            lbl = filename_to_label(f)
            df["label"] = lbl
            frames.append(df)
            print(f"    {os.path.basename(f):<55}  {len(df):>8,} rows  →  {lbl}")

    combined = pd.concat(frames, ignore_index=True)
    combined.columns = combined.columns.str.strip()
    combined.dropna(how="all", inplace=True)

    return combined.reset_index(drop=True)


# ── STEP 1 : LOAD DATA ────────────────────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 1 — LOADING & MERGING CSV FILES")
print("=" * 68)

print(f"\n  [TRAIN — {TRAIN_DIR}]")
train_df = load_and_merge(TRAIN_DIR)

print(f"\n  [TEST  — {TEST_DIR}]")
test_df  = load_and_merge(TEST_DIR)

print(f"\n  ✓ Train combined : {len(train_df):>8,} rows  |  {train_df.shape[1]} columns")
print(f"  ✓ Test  combined : {len(test_df):>8,} rows  |  {test_df.shape[1]} columns")
print(f"\n  Train labels : {sorted(train_df['label'].unique())}")
print(f"  Test  labels : {sorted(test_df['label'].unique())}")

# ── DIAGNOSTIC: label distribution (catch mismapped filenames early) ──────────
print(f"\n  Train label distribution:")
for lbl, cnt in train_df["label"].value_counts().items():
    print(f"    {lbl:<40} {cnt:>10,} rows")
if "Benign" not in set(train_df["label"].unique()):
    print(f"\n  ⚠  WARNING: No 'Benign' label found after filename mapping.")
    print(f"  ⚠  Your filenames may not contain the literal substring 'benign'.")
    print(f"  ⚠  Check the list above — if your normal-traffic class appears under")
    print(f"     a different name (e.g. 'Wifi_And_Mqtt_Idle'), either rename the")
    print(f"     files or add a pattern to LABEL_MAP mapping it to 'Benign'.")

# Drop test labels not seen during training
missing_in_train = set(test_df["label"].unique()) - set(train_df["label"].unique())
if missing_in_train:
    print(f"\n  ⚠  Labels in test but not train: {missing_in_train}")
    test_df = test_df[test_df["label"].isin(train_df["label"].unique())].reset_index(drop=True)
    print(f"  → Dropped. Test now {len(test_df):,} rows.")
else:
    print(f"  ✓ All test labels present in training data.")


# ── STEP 2 : PREPROCESSING ────────────────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 2 — PREPROCESSING")
print("=" * 68)

exclude    = {"label"}
FEATURE_COLS, dropped = [], []

for col in train_df.columns:
    if col in exclude:
        continue
    try:
        train_df[col] = pd.to_numeric(train_df[col], errors="raise")
        test_df[col]  = pd.to_numeric(test_df[col],  errors="raise")
        FEATURE_COLS.append(col)
    except Exception:
        dropped.append(col)

if dropped:
    print(f"  ⚠  Dropped non-numeric / text columns ({len(dropped)}): {dropped[:10]}{'...' if len(dropped)>10 else ''}")

train_df = train_df[FEATURE_COLS + ["label"]].dropna().reset_index(drop=True)
test_df  = test_df[FEATURE_COLS  + ["label"]].dropna().reset_index(drop=True)

print(f"  Network feature columns : {len(FEATURE_COLS)}")
print(f"  Feature list: {FEATURE_COLS}")
print(f"\n  After NaN drop — Train: {len(train_df):,}   Test: {len(test_df):,}")

# Label encoding
y_train_raw = train_df["label"].values
y_test_raw  = test_df["label"].values

le = LabelEncoder()
le.fit(np.concatenate([y_train_raw, y_test_raw]))
y_train = le.transform(y_train_raw)
y_test  = le.transform(y_test_raw)
print(f"\n  Classes ({len(le.classes_)}): {list(le.classes_)}")

# Feature matrices
X_train_raw = train_df[FEATURE_COLS].values.astype(np.float64)
X_test_raw  = test_df[FEATURE_COLS].values.astype(np.float64)

scaler  = StandardScaler()
X_train = scaler.fit_transform(X_train_raw)
X_test  = scaler.transform(X_test_raw)
print(f"  StandardScaler fitted on {len(X_train):,} training rows ✓")

sample_weights = compute_sample_weight("balanced", y_train)

print(f"\n  Class distribution (train):")
for cls, cnt in sorted(zip(*np.unique(y_train_raw, return_counts=True)), key=lambda x: -x[1]):
    pct = cnt / len(y_train_raw) * 100
    bar = "█" * int(pct / 2)
    print(f"    {cls:<28} {cnt:>10,}  ({pct:5.1f}%)  {bar}")

# ── BENIGN-ONLY SPLIT (for Isolation Forest) ──────────────────────────────────
if "Benign" not in set(y_train_raw):
    raise ValueError(
        "\n  ✗ No 'Benign' rows found in the training set.\n"
        "  → Isolation Forest requires benign-only data to train on.\n"
        "  → Check your LABEL_MAP / filenames in data/train/.\n"
    )

benign_mask = (y_train_raw == "Benign")
X_train_benign  = X_train[benign_mask]
X_train_attacks = X_train[~benign_mask]

# Hold out 20% of benign rows — NOT used to fit IF — so we can honestly
# calibrate its decision threshold afterwards against data it has never seen,
# combined with real attack rows (also never seen by IF during .fit()).
X_iso_fit, X_iso_calib_benign = train_test_split(
    X_train_benign, test_size=0.2, random_state=42
)

print(f"\n  Isolation Forest data split:")
print(f"    Fit (Benign, seen by IF)          : {X_iso_fit.shape[0]:,} rows")
print(f"    Calibration (Benign, held out)     : {X_iso_calib_benign.shape[0]:,} rows")
print(f"    Calibration (Attack, from train)   : {X_train_attacks.shape[0]:,} rows")


# ── STEP 3 : TRAIN MODELS ─────────────────────────────────────────────────────

# ── 3a : Random Forest ────────────────────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 3a — Random Forest  [main classifier]")
print("=" * 68)

rf = RandomForestClassifier(
    n_estimators     = 300,
    max_depth        = None,
    min_samples_leaf = 1,
    min_samples_split= 2,
    max_features     = "sqrt",
    class_weight     = "balanced",
    bootstrap        = True,
    oob_score        = True,
    random_state     = 42,
    n_jobs           = -1,
    verbose          = 1,
)
rf.fit(X_train, y_train, sample_weight=sample_weights)
print(f"\n  ✓ Random Forest trained | OOB Score: {rf.oob_score_ * 100:.2f}%")

# ── 3b : Isolation Forest  [ONE-CLASS — Benign-only training] ─────────────────
print("\n" + "=" * 68)
print("  STEP 3b — Isolation Forest  [anomaly detector | Benign-only]")
print("=" * 68)

iso = IsolationForest(
    n_estimators  = 300,
    contamination = "auto",   # ← don't rely on contamination's blind quantile
                               #   heuristic; we tune the real decision threshold
                               #   below using labeled data instead
    max_samples   = "auto",
    max_features  = 1.0,
    random_state  = 42,
    n_jobs        = -1,
    verbose       = 1,
)
iso.fit(X_iso_fit)   # ← trained ONLY on the Benign fit-split, never sees attacks
                      #   or the held-out benign calibration rows
print(f"  ✓ Isolation Forest trained on Benign-only data")

# ── THRESHOLD TUNING — pick the anomaly cutoff using labeled data ────────────
# iso.decision_function(): higher score = more "normal", lower/negative = more
# anomalous. iso.predict()'s built-in -1/+1 threshold is derived purely from
# the training (benign) score distribution and the `contamination` guess — it
# has never seen an actual attack, so there's no reason to expect it lands in
# a good place. Instead, we build a calibration set of (never-seen-by-IF)
# benign rows + real attack rows, score them, and pick the threshold on the
# ROC curve that best separates the two — this is what actually improves
# attack detection instead of guessing at contamination.
print("\n" + "=" * 68)
print("  STEP 3b-2 — Tuning Isolation Forest threshold (ROC on calibration set)")
print("=" * 68)

X_calib = np.vstack([X_iso_calib_benign, X_train_attacks])
y_calib_is_attack = np.concatenate([
    np.zeros(len(X_iso_calib_benign), dtype=int),   # benign = 0
    np.ones(len(X_train_attacks), dtype=int),        # attack = 1
])

calib_scores   = iso.decision_function(X_calib)   # higher = more normal
anomaly_scores = -calib_scores                     # higher = more anomalous

fpr, tpr, roc_thresholds = roc_curve(y_calib_is_attack, anomaly_scores)

# Youden's J statistic — the threshold that best balances TPR and FPR
youden_idx = np.argmax(tpr - fpr)
best_anomaly_threshold = roc_thresholds[youden_idx]
IF_THRESHOLD = -best_anomaly_threshold   # back to iso_score scale:
                                          # is_anomaly  <=>  iso_score < IF_THRESHOLD

roc_auc_if = auc_score(fpr, tpr)
print(f"  ROC-AUC (Benign vs Attack separability) : {roc_auc_if:.4f}")
print(f"  Youden-optimal cutoff — FPR: {fpr[youden_idx]*100:.2f}%  "
      f"TPR (detection): {tpr[youden_idx]*100:.2f}%")

print(f"\n  {'Target FPR':>12}  {'Actual FPR':>11}  {'Detection Rate':>15}")
print("  " + "-" * 44)
for target in (0.01, 0.05, 0.10, 0.15, 0.20):
    idx = np.searchsorted(fpr, target)
    idx = min(idx, len(fpr) - 1)
    print(f"  {target*100:>10.0f}%  {fpr[idx]*100:>10.2f}%  {tpr[idx]*100:>14.2f}%")

print(f"\n  ✓ Using Youden-optimal threshold by default (IF_THRESHOLD = {IF_THRESHOLD:.4f})")
print(f"    → If you want tighter FPR control, override IF_THRESHOLD below using")
print(f"      the target-FPR table above (e.g. pick the row matching your")
print(f"      acceptable false-positive tolerance for a hospital SOC).")

# ── OPTIONAL MANUAL OVERRIDE ───────────────────────────────────────────────
# Uncomment and set to fix a specific False Positive Rate instead of Youden's
# balance point, e.g. to cap FPR at 5% for a hospital SOC:
#
# target_fpr = 0.05
# idx = np.searchsorted(fpr, target_fpr)
# IF_THRESHOLD = -roc_thresholds[min(idx, len(roc_thresholds) - 1)]

# ── 3c : K-Means ─────────────────────────────────────────────────────────────
print("\n" + "=" * 68)
print(f"  STEP 3c — K-Means k={N_CLUSTERS}  [traffic behaviour clustering]")
print("=" * 68)

km = KMeans(
    n_clusters   = N_CLUSTERS,
    init         = "k-means++",
    n_init       = 20,
    max_iter     = 500,
    random_state = 42,
    verbose      = 1,
)
km.fit(X_train)
print(f"  ✓ K-Means trained")


# ── STEP 4 : SAVE ARTIFACTS ───────────────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 4 — SAVING ARTIFACTS  →  models/")
print("=" * 68)

joblib.dump(rf,           os.path.join(MODEL_DIR, "random_forest.pkl"))
joblib.dump(iso,          os.path.join(MODEL_DIR, "isolation_forest.pkl"))
joblib.dump(km,           os.path.join(MODEL_DIR, "kmeans.pkl"))
joblib.dump(scaler,       os.path.join(MODEL_DIR, "scaler.pkl"))
joblib.dump(le,           os.path.join(MODEL_DIR, "label_encoder.pkl"))
joblib.dump(FEATURE_COLS, os.path.join(MODEL_DIR, "feature_cols.pkl"))
joblib.dump(IF_THRESHOLD, os.path.join(MODEL_DIR, "if_threshold.pkl"))

for fname in ["random_forest.pkl", "isolation_forest.pkl", "kmeans.pkl",
              "scaler.pkl", "label_encoder.pkl", "feature_cols.pkl", "if_threshold.pkl"]:
    size = os.path.getsize(os.path.join(MODEL_DIR, fname)) / 1024
    print(f"  ✓ {fname:<32}  ({size:>8.1f} KB)")


# ── STEP 5 : EVALUATE ─────────────────────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 5 — EVALUATING ON TEST SET")
print("=" * 68)

y_pred_rf  = rf.predict(X_test)
y_proba_rf = rf.predict_proba(X_test)
confidence = y_proba_rf.max(axis=1)
y_pred_iso = np.where(iso.decision_function(X_test) < IF_THRESHOLD, -1, 1)
iso_scores = iso.decision_function(X_test)
y_pred_km  = km.predict(X_test)

acc = accuracy_score(y_test, y_pred_rf)
print(f"\n  ✅  Random Forest Accuracy  : {acc * 100:.2f}%")

try:
    auc = roc_auc_score(y_test, y_proba_rf, multi_class="ovr", average="macro")
    print(f"  ✅  AUC-ROC (macro OvR)     : {auc:.4f}")
except Exception:
    auc = None

n_anom = (y_pred_iso == -1).sum()
print(f"  ✅  IF Anomalies detected   : {n_anom:,} / {len(y_pred_iso):,} "
      f"({n_anom / len(y_pred_iso) * 100:.1f}%)")

# ── IF benign-vs-attack separation (this is the key metric for a one-class IF) ─
is_benign_test = (y_test_raw == "Benign")
fp_rate = (y_pred_iso[is_benign_test] == -1).mean() * 100 if is_benign_test.any() else float("nan")
detect_rate = (y_pred_iso[~is_benign_test] == -1).mean() * 100 if (~is_benign_test).any() else float("nan")
print(f"  ✅  IF False Positive Rate  : {fp_rate:.2f}%  (benign test rows flagged as anomalous)")
print(f"  ✅  IF Attack Detection Rate: {detect_rate:.2f}%  (attack test rows flagged as anomalous)")

try:
    sil_idx = np.random.choice(len(X_test), min(5000, len(X_test)), replace=False)
    sil = silhouette_score(X_test[sil_idx], y_pred_km[sil_idx])
    print(f"  ✅  K-Means Silhouette     : {sil:.4f}")
except Exception:
    sil = None

print(f"\n{classification_report(y_test, y_pred_rf, target_names=le.classes_)}")

with open(os.path.join(REPORT_DIR, "classification_report.txt"), "w") as f:
    f.write("CAAP IoMT IDS — Random Forest Classification Report\n")
    f.write("Author : R.M.C.B. Rathnayake | IT22061270 | SLIIT Cyber Security\n")
    f.write(f"Overall Test Accuracy : {acc * 100:.2f}%\n")
    if auc:
        f.write(f"AUC-ROC (macro OvR)   : {auc:.4f}\n")
    f.write(f"\nIsolation Forest (Benign-only trained, {X_iso_fit.shape[0]:,} fit rows, "
            f"threshold={IF_THRESHOLD:.4f})\n")
    f.write(f"  False Positive Rate   : {fp_rate:.2f}%\n")
    f.write(f"  Attack Detection Rate : {detect_rate:.2f}%\n")
    f.write("\n")
    f.write(classification_report(y_test, y_pred_rf, target_names=le.classes_))

print(f"\n  K-Means traffic clusters:")
u, c = np.unique(y_pred_km, return_counts=True)
for ui, ci in zip(u, c):
    print(f"    {CLUSTER_LABELS.get(ui, '?'):8s}: {ci:,}")


# ── STEP 6 : PER-CLASS ACCURACY ───────────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 6 — PER ATTACK TYPE ACCURACY")
print("=" * 68)
print(f"  {'Attack Type':<32} {'Samples':>8}  {'Accuracy':>9}  {'Status'}")
print("  " + "─" * 65)

class_accs = {}
for attack in le.classes_:
    mask = y_test_raw == attack
    if not mask.any():
        continue
    ai = accuracy_score(y_test[mask], y_pred_rf[mask])
    class_accs[attack] = ai * 100
    bar    = "█" * int(ai * 20)
    status = "✅" if ai >= 0.90 else "⚠️ " if ai >= 0.75 else "❌"
    print(f"  {status} {attack:<30} {mask.sum():>8,}  {ai * 100:>8.2f}%  {bar}")

# ── STEP 6b : PER-CLASS IF ANOMALY RATE ────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 6b — PER ATTACK TYPE — ISOLATION FOREST ANOMALY RATE")
print("=" * 68)
print(f"  {'Attack Type':<32} {'Samples':>8}  {'Anomaly Rate':>12}")
print("  " + "─" * 58)

for attack in le.classes_:
    mask = y_test_raw == attack
    if not mask.any():
        continue
    anom_rate = (y_pred_iso[mask] == -1).mean() * 100
    expected  = "low ✅" if attack == "Benign" else ("high ✅" if anom_rate >= 50 else "low ⚠️")
    print(f"  {attack:<32} {mask.sum():>8,}  {anom_rate:>10.2f}%   ({expected})")


# ── STEP 7 : SAVE FULL PREDICTIONS ────────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 7 — SAVING PREDICTIONS CSV")
print("=" * 68)

out = test_df[["label"]].copy().reset_index(drop=True)
out["predicted"]  = le.inverse_transform(y_pred_rf)
out["confidence"] = np.round(confidence, 4)
out["iso_score"]  = np.round(iso_scores, 4)
out["is_anomaly"] = y_pred_iso == -1
out["cluster"]    = [CLUSTER_LABELS.get(ci, str(ci)) for ci in y_pred_km]
out["correct"]    = out["label"] == out["predicted"]

out.to_csv(os.path.join(REPORT_DIR, "predictions.csv"), index=False)
print(f"  ✓ {len(out):,} rows saved → reports/predictions.csv")


# ── STEP 8 : CHARTS ───────────────────────────────────────────────────────────
print("\n" + "=" * 68)
print("  STEP 8 — GENERATING CHARTS  →  reports/")
print("=" * 68)

plt.style.use("seaborn-v0_8-whitegrid")

# 8a — Confusion Matrix
fig, ax = plt.subplots(figsize=(12, 9))
cm = confusion_matrix(y_test, y_pred_rf)
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=le.classes_, yticklabels=le.classes_,
            ax=ax, linewidths=0.4, cbar_kws={"shrink": 0.8})
ax.set_title(f"Confusion Matrix — RF Accuracy: {acc * 100:.2f}%", fontsize=14, pad=12)
ax.set_ylabel("Actual Label"); ax.set_xlabel("Predicted Label")
plt.xticks(rotation=40, ha="right"); plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, "confusion_matrix.png"), dpi=150)
plt.close(); print("  ✓ confusion_matrix.png")

# 8b — Per-Class Accuracy
colors = ["#2ecc71" if v >= 90 else "#e67e22" if v >= 75 else "#e74c3c"
          for v in class_accs.values()]
fig, ax = plt.subplots(figsize=(14, 5))
bars = ax.bar(class_accs.keys(), class_accs.values(),
              color=colors, edgecolor="white", linewidth=0.8)
ax.axhline(90, color="#27ae60", linestyle="--", alpha=0.7, label="90% target")
ax.axhline(75, color="#e67e22", linestyle="--", alpha=0.5, label="75% baseline")
for bar, val in zip(bars, class_accs.values()):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
            f"{val:.1f}%", ha="center", fontsize=9, fontweight="bold")
ax.set_title("Per-Class Accuracy on Test Set", fontsize=14)
ax.set_ylabel("Accuracy (%)"); ax.set_ylim(0, 115)
plt.xticks(rotation=35, ha="right"); plt.legend(); plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, "per_class_accuracy.png"), dpi=150)
plt.close(); print("  ✓ per_class_accuracy.png")

# 8c — Training Class Distribution
fig, ax = plt.subplots(figsize=(14, 4))
counts = pd.Series(y_train_raw).value_counts()
bars2 = ax.bar(counts.index, counts.values, color="steelblue", edgecolor="white")
ax.set_title("Training Set — Samples per Class", fontsize=14)
ax.set_ylabel("Count"); ax.set_xlabel("Attack / Traffic Type")
for bar, val in zip(bars2, counts.values):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(counts) * 0.01,
            f"{val:,}", ha="center", fontsize=9)
plt.xticks(rotation=35, ha="right"); plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, "class_distribution.png"), dpi=150)
plt.close(); print("  ✓ class_distribution.png")

# 8d — Feature Importances (Top 20)
importances = pd.Series(rf.feature_importances_, index=FEATURE_COLS)
top20 = importances.nlargest(20).sort_values()
fig, ax = plt.subplots(figsize=(11, 7))
colors_fi = ["#e74c3c" if v >= top20.quantile(0.75) else "#3498db" for v in top20.values]
top20.plot(kind="barh", ax=ax, color=colors_fi, edgecolor="white")
ax.set_title("Top 20 Feature Importances — Random Forest", fontsize=13)
ax.set_xlabel("Importance Score"); plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, "feature_importances.png"), dpi=150)
plt.close(); print("  ✓ feature_importances.png")

# 8e — Isolation Forest Score Distribution
fig, ax = plt.subplots(figsize=(11, 4))
is_attack = y_test_raw != "Benign"
ax.hist(iso_scores[~is_attack], bins=80, alpha=0.65, color="#3498db",
        label="Benign", density=True)
ax.hist(iso_scores[is_attack],  bins=80, alpha=0.65, color="#e74c3c",
        label="Attack", density=True)
ax.axvline(0, color="black", linestyle="--", alpha=0.5, label="IF boundary (0)")
ax.set_title("Isolation Forest — Anomaly Score Distribution (Benign-only trained)", fontsize=13)
ax.set_xlabel("IF Decision Score (more negative = more anomalous)")
ax.set_ylabel("Density"); ax.legend(); plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, "if_anomaly_dist.png"), dpi=150)
plt.close(); print("  ✓ if_anomaly_dist.png")

# 8f — K-Means Cluster Sizes
fig, ax = plt.subplots(figsize=(6, 4))
ax.bar([CLUSTER_LABELS.get(ui, str(ui)) for ui in u], c,
       color=["#e74c3c", "#2ecc71"], edgecolor="white")
ax.set_title("K-Means — Traffic Behaviour Groups", fontsize=13)
ax.set_ylabel("Sample Count"); plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, "kmeans_clusters.png"), dpi=150)
plt.close(); print("  ✓ kmeans_clusters.png")

# 8g — Model Comparison Summary
fig, ax = plt.subplots(figsize=(9, 5))
summary = {
    "RF Accuracy (%)":            acc * 100,
    "RF OOB Score (%)":           rf.oob_score_ * 100,
    "IF Attack Detection (%)":    detect_rate,
    "IF False Positive (%)":      fp_rate,
    "AUC-ROC (×100)":             (auc * 100) if auc else 0,
    "K-Means Silhouette\n(×100)": (sil * 100) if sil else 0,
}
bar_colors = ["#2ecc71", "#27ae60", "#9b59b6", "#e74c3c", "#f39c12", "#3498db"]
hbars = ax.barh(list(summary.keys()), list(summary.values()),
                color=bar_colors, edgecolor="white")
for bar, val in zip(hbars, summary.values()):
    ax.text(val + 0.5, bar.get_y() + bar.get_height() / 2,
            f"{val:.1f}", va="center", fontweight="bold")
ax.set_xlim(0, 115)
ax.set_title("CAAP Multi-Model Summary", fontsize=13)
ax.set_xlabel("Score"); plt.tight_layout()
plt.savefig(os.path.join(REPORT_DIR, "model_summary.png"), dpi=150)
plt.close(); print("  ✓ model_summary.png")


# ── STEP 9 : MODEL ACCURACY SUMMARY  (single file — Train / Test / Overall) ───
print("\n" + "=" * 68)
print("  STEP 9 — MODEL ACCURACY SUMMARY  →  reports/model_accuracy_summary.txt")
print("=" * 68)


def clustering_purity(true_labels, cluster_ids) -> float:
    """
    Majority-vote purity: each cluster is assigned the majority true label
    among its members; accuracy = fraction of rows matching their cluster's
    majority label. Standard proxy for 'accuracy' in unsupervised clustering.
    """
    df = pd.DataFrame({"true": true_labels, "cluster": cluster_ids})
    correct = 0
    for cid in df["cluster"].unique():
        subset = df.loc[df["cluster"] == cid, "true"]
        if len(subset) == 0:
            continue
        correct += subset.value_counts().iloc[0]
    return correct / len(df)


def if_binary_accuracy(y_pred_iso_arr, y_true_raw_arr) -> float:
    """
    Isolation Forest as a binary Normal/Attack detector:
    predicted 'attack' = anomaly flag (-1); true 'attack' = label != 'Benign'.
    """
    pred_attack = (y_pred_iso_arr == -1).astype(int)
    true_attack = (y_true_raw_arr != "Benign").astype(int)
    return (pred_attack == true_attack).mean()


# ── Random Forest ──────────────────────────────────────────────────────────
y_pred_rf_train = rf.predict(X_train)
rf_train_acc = accuracy_score(y_train, y_pred_rf_train)
rf_test_acc  = acc  # already computed in Step 5
rf_overall_acc = accuracy_score(
    np.concatenate([y_train, y_test]),
    np.concatenate([y_pred_rf_train, y_pred_rf]),
)

# ── Isolation Forest (binary Normal vs Attack accuracy) ───────────────────
y_pred_iso_train = np.where(iso.decision_function(X_train) < IF_THRESHOLD, -1, 1)
if_train_acc = if_binary_accuracy(y_pred_iso_train, y_train_raw)
if_test_acc  = if_binary_accuracy(y_pred_iso, y_test_raw)
if_overall_acc = if_binary_accuracy(
    np.concatenate([y_pred_iso_train, y_pred_iso]),
    np.concatenate([y_train_raw, y_test_raw]),
)

# ── K-Means (majority-vote cluster purity) ─────────────────────────────────
y_pred_km_train = km.predict(X_train)
km_train_acc = clustering_purity(y_train_raw, y_pred_km_train)
km_test_acc  = clustering_purity(y_test_raw, y_pred_km)
km_overall_acc = clustering_purity(
    np.concatenate([y_train_raw, y_test_raw]),
    np.concatenate([y_pred_km_train, y_pred_km]),
)

summary_lines = []
summary_lines.append("=" * 72)
summary_lines.append("  CAAP IoMT IDS — MODEL ACCURACY SUMMARY")
summary_lines.append("  Author : R.M.C.B. Rathnayake | IT22061270 | SLIIT Cyber Security")
summary_lines.append(f"  Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
summary_lines.append("=" * 72)
summary_lines.append("")
summary_lines.append(f"  Training set : {len(X_train):,} rows   |   Test set : {len(X_test):,} rows")
summary_lines.append(f"  Feature columns : {len(FEATURE_COLS)}   |   Classes : {list(le.classes_)}")
summary_lines.append("")
summary_lines.append(f"  {'Model':<22} {'Metric Type':<28} {'Train Acc':>10}  {'Test Acc':>10}  {'Overall Acc':>12}")
summary_lines.append("  " + "-" * 88)
summary_lines.append(
    f"  {'Random Forest':<22} {'Classification accuracy':<28} "
    f"{rf_train_acc*100:>9.2f}%  {rf_test_acc*100:>9.2f}%  {rf_overall_acc*100:>11.2f}%"
)
summary_lines.append(
    f"  {'Isolation Forest':<22} {'Binary Normal/Attack acc.':<28} "
    f"{if_train_acc*100:>9.2f}%  {if_test_acc*100:>9.2f}%  {if_overall_acc*100:>11.2f}%"
)
summary_lines.append(
    f"  {'K-Means':<22} {'Majority-vote cluster purity':<28} "
    f"{km_train_acc*100:>9.2f}%  {km_test_acc*100:>9.2f}%  {km_overall_acc*100:>11.2f}%"
)
summary_lines.append("")
summary_lines.append("  Notes:")
summary_lines.append("  - Random Forest: standard multi-class classification accuracy.")
summary_lines.append("  - Isolation Forest: trained ONLY on Benign rows (one-class setup).")
summary_lines.append("    Accuracy here = agreement between its anomaly flag and the true")
summary_lines.append("    Benign/Attack label (i.e. treated as a binary detector).")
summary_lines.append(f"    IF False Positive Rate (test)   : {fp_rate:.2f}%")
summary_lines.append(f"    IF Attack Detection Rate (test) : {detect_rate:.2f}%")
summary_lines.append("  - K-Means: unsupervised, so 'accuracy' = majority-vote cluster")
summary_lines.append("    purity against the true attack-type labels (standard proxy")
summary_lines.append("    metric for evaluating clustering quality against ground truth).")
if auc:
    summary_lines.append("")
    summary_lines.append(f"  Random Forest AUC-ROC (macro OvR) : {auc:.4f}")
if sil:
    summary_lines.append(f"  K-Means Silhouette Score          : {sil:.4f}")
summary_lines.append(f"  Random Forest OOB Score           : {rf.oob_score_*100:.2f}%")
summary_lines.append("")
summary_lines.append("=" * 72)

summary_text = "\n".join(summary_lines)
print("\n" + summary_text)

summary_path = os.path.join(REPORT_DIR, "model_accuracy_summary.txt")
with open(summary_path, "w", encoding="utf-8") as f:
    f.write(summary_text + "\n")

print(f"\n  ✓ Saved → {summary_path}")


# ── STEP 9b : MODEL METADATA  (versioning + drift baseline — models/model_meta.json) ──
# Consumed by ai_server/src/app.py at startup (model_version in /health and
# /predict) and by ai_server/check_drift.py (feature_stats as the "what does
# normal training data look like" baseline to compare live captured flows
# against). feature_columns_hash lets a consumer notice a retrain changed the
# feature set without diffing the full column list by eye.
print("\n" + "=" * 68)
print("  STEP 9b — SAVING MODEL METADATA  →  models/model_meta.json")
print("=" * 68)

feature_columns_hash = hashlib.sha256(",".join(FEATURE_COLS).encode("utf-8")).hexdigest()[:16]
feature_stats = {
    col: {"mean": float(np.mean(X_train_raw[:, i])), "std": float(np.std(X_train_raw[:, i]))}
    for i, col in enumerate(FEATURE_COLS)
}

model_meta = {
    "trained_at": datetime.datetime.utcnow().isoformat() + "Z",
    "feature_columns": FEATURE_COLS,
    "feature_columns_hash": feature_columns_hash,
    "classes": list(le.classes_),
    "models": {
        "random_forest": {
            "metric": "classification_accuracy",
            "train_pct": round(rf_train_acc * 100, 2),
            "test_pct": round(rf_test_acc * 100, 2),
            "overall_pct": round(rf_overall_acc * 100, 2),
        },
        "isolation_forest": {
            "metric": "binary_normal_attack_accuracy",
            "train_pct": round(if_train_acc * 100, 2),
            "test_pct": round(if_test_acc * 100, 2),
            "overall_pct": round(if_overall_acc * 100, 2),
        },
        "kmeans": {
            "metric": "cluster_purity",
            "train_pct": round(km_train_acc * 100, 2),
            "test_pct": round(km_test_acc * 100, 2),
            "overall_pct": round(km_overall_acc * 100, 2),
        },
    },
    # Per-feature train-set mean/std (raw, pre-scaling) — the baseline
    # check_drift.py z-scores newly captured flows against.
    "feature_stats": feature_stats,
}

meta_path = os.path.join(MODEL_DIR, "model_meta.json")
with open(meta_path, "w", encoding="utf-8") as f:
    json.dump(model_meta, f, indent=2)
print(f"  ✓ Saved → {meta_path}")


# ── FINAL SUMMARY ─────────────────────────────────────────────────────────────
elapsed = time.time() - t_start
print("\n" + "=" * 68)
print(f"  ✅  ALL DONE!")
print(f"  Classes trained on          : {list(le.classes_)}")
print(f"  Feature columns             : {len(FEATURE_COLS)}")
print(f"  RF Overall Accuracy         : {acc * 100:.2f}%")
if auc:
    print(f"  RF AUC-ROC                  : {auc:.4f}")
print(f"  RF OOB Score                : {rf.oob_score_ * 100:.2f}%")
print(f"  IF fit rows (Benign)        : {X_iso_fit.shape[0]:,}")
print(f"  IF decision threshold       : {IF_THRESHOLD:.4f}")
print(f"  IF False Positive Rate      : {fp_rate:.2f}%")
print(f"  IF Attack Detection Rate    : {detect_rate:.2f}%")
print(f"  Training time                : {elapsed:.1f}s")
print("=" * 68)
print(f"  Models  → {MODEL_DIR}/")
print(f"  Reports → {REPORT_DIR}/")
print(f"  Accuracy summary → {summary_path}")
print("=" * 68 + "\n")
