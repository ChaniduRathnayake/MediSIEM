# CAAP Flask AI Server — Phase 6 Files

## Where these go in your project

Your project structure (from Phase 1) is:
```
caap-project/
├── data/
├── src/
├── models/        <- note: your Phase 1 plan uses "models/", app.py looks in "model/" — pick one and stay consistent
├── notebooks/
├── docker/
└── dashboard/
```

Copy the files from this folder as follows:

| File here | Goes to | Purpose |
|---|---|---|
| `src/app.py` | `caap-project/src/app.py` | The Flask server itself |
| `requirements.txt` | `caap-project/requirements.txt` | Python dependencies (project root) |
| `sample_row.json` | `caap-project/sample_row.json` | Test payload for curl/Postman |

## What you must already have in place

`app.py` expects these 4 files to already exist (from Phases 2 & 4) at `../model/` relative to `src/app.py`, i.e. `caap-project/model/`:

- `scaler.pkl`
- `random_forest.pkl`
- `isolation_forest.pkl`
- `kmeans.pkl`

If your folder is actually named `models/` (plural, per your Phase 1 plan) instead of `model/`, either rename the folder to `model/` or edit this line near the top of `app.py`:

```python
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model")
```

## Setup & run

```bash
cd caap-project
source caap-env/bin/activate          # the venv from Phase 1
pip install -r requirements.txt --break-system-packages
python src/app.py
```

Server starts on **http://localhost:5001**.

## Test it

```bash
# health check
curl http://localhost:5001/health

# full prediction
curl -X POST http://localhost:5001/predict \
  -H "Content-Type: application/json" \
  -d @sample_row.json
```

## Before this is really "done" (per your Phase 6 checklist)

1. **`FEATURE_COLUMNS`** in `app.py` — currently a partial stub list. Replace with the real 44 column names, in the exact order used when you fit `scaler.pkl` / trained `random_forest.pkl`.
2. **`CLUSTER_LABELS`** — confirm which K-Means cluster index (0 or 1) is actually "idle" vs "active" by checking cluster centroids (lower `flow_bytes_s` = idle).
3. **CORS** — currently open to all origins (`"*"`) for local testing. Once your Node.js backend (port 5000) is calling this, tighten it in `app.py`:
   ```python
   CORS(app, resources={r"/*": {"origins": "http://localhost:5000"}})
   ```
4. **`hour_of_day`** and **`cve_known_exploited`** — these feed the rule-based AE/TC dimensions. Decide whether Node.js sends them in the request, or Flask derives them itself (timestamp → hour, CVE lookup service).
