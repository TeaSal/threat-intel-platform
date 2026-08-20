# AI-Powered Threat Intelligence Platform — Review 2 Build

A working prototype: collects CVE data (NVD) and malicious-IP data (AbuseIPDB), normalizes
both into one schema, deduplicates, stores in SQLite, engineers cross-source features,
generates heuristic priority labels, trains/evaluates ML models (Logistic Regression,
Decision Tree, Random Forest), and serves a ranked Streamlit dashboard.

## IMPORTANT — read this first

This code was written and tested in a sandbox **with no internet access**, so the real
API collectors (`src/collectors/nvd_collector.py`, `src/collectors/abuseipdb_collector.py`)
could not be executed here. They are complete, real implementations of the actual NVD 2.0
and AbuseIPDB v2 APIs — you just need to run them on a machine with internet access.

To let you test and demo the *entire rest of the pipeline* right now, without waiting on
API access, `scripts/generate_sample_data.py` produces realistic **synthetic** data in the
exact raw JSON shape both APIs actually return. The normalization code that processes this
synthetic data is the *same* code that will process real API responses — nothing about
`src/pipeline/normalize.py` changes when you switch from synthetic to real data.

**Before Review 2**, replace synthetic data with real data:
1. Get a free AbuseIPDB API key: https://www.abuseipdb.com/register
2. Get an NVD API key (optional but recommended, avoids rate limits): https://nvd.nist.gov/developers/request-an-api-key
3. Put both in a `.env` file (see `.env.example`)
4. Run `python scripts/run_pipeline.py --live` instead of `--synthetic`

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # then fill in your ABUSEIPDB_API_KEY (and optional NVD_API_KEY)
```

## Run the full pipeline (offline / synthetic — works right now, no API keys needed)

```bash
python scripts/run_pipeline.py --synthetic
```

This will:
1. Generate synthetic raw CVE + AbuseIPDB records (`scripts/generate_sample_data.py`)
2. Normalize both into the common schema (`src/pipeline/normalize.py`)
3. Deduplicate (`src/pipeline/dedup.py`)
4. Store everything in `data/threat_intel.db` (`src/pipeline/db.py`)
5. Engineer features (`src/pipeline/feature_engineering.py`)
6. Generate heuristic priority labels (`src/pipeline/labeling.py`)
7. Train Logistic Regression, Decision Tree, Random Forest (`src/ml/train.py`)
8. Evaluate all three and save metrics + confusion matrices to `reports/` (`src/ml/evaluate.py`)
9. Write predicted priorities back into the database

## Run with real live data (once you have API keys and internet)

```bash
python scripts/run_pipeline.py --live
```

## Launch the dashboard

```bash
streamlit run src/dashboard/app.py
```

## Project structure

```
src/
  config.py                     # env vars, constants
  schema.py                     # the common normalized schema (single source of truth)
  collectors/
    nvd_collector.py            # real NVD 2.0 API client
    abuseipdb_collector.py      # real AbuseIPDB v2 API client
  pipeline/
    normalize.py                # raw source JSON -> common schema
    dedup.py                    # dedupe by natural key (CVE-ID / IP)
    db.py                       # SQLite storage layer
    feature_engineering.py      # common schema -> ML feature matrix
    labeling.py                 # heuristic priority labels (documented, not "ground truth")
  ml/
    train.py                    # trains LogReg / Decision Tree / Random Forest
    evaluate.py                 # metrics, confusion matrices, feature importance
  dashboard/
    app.py                      # Streamlit dashboard, reads from data/threat_intel.db
scripts/
  generate_sample_data.py       # offline synthetic data generator (raw API-shaped JSON)
  run_pipeline.py                # orchestrates the whole pipeline end-to-end
data/
  threat_intel.db               # SQLite database (created on first run)
reports/
  metrics.json, confusion_matrix_*.png, feature_importance.png
```

## Honest labeling note (say this out loud in Review 2)

We do **not** have analyst-verified ground-truth priority labels — no public dataset
provides that for a blended cross-source dataset like this one. `src/pipeline/labeling.py`
implements a documented heuristic (CVSS severity band + recency + report volume +
source reliability, and a KEV-style "known exploited" flag for CVEs) and the ML models
are trained to generalize this heuristic across the full feature set — not simply to
memorize it. This is a standard, defensible approach for weak/heuristic-label problems,
and we say so explicitly rather than presenting the labels as if they were ground truth.
