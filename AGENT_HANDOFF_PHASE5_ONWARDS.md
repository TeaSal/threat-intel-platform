# Agent Handoff — Phase 5 Onwards
## AI-Powered Threat Intelligence Platform

**Last updated:** Phase 4 complete  
**Repo:** https://github.com/TeaSal/threat-intel-platform  
**HEAD commit:** `afd6cb7`  
**Branch:** `main`  
**Working directory:** `c:\Users\tiyas\Downloads\threat_intel_platform\threat_intel_platform\`  
**Venv:** `.\venv\` (Python 3.13, activate with `.\venv\Scripts\Activate.ps1`)  
**Run dashboard:** `.\venv\Scripts\streamlit.exe run src/dashboard/app.py`  
**Run pipeline:** `.\venv\Scripts\python.exe scripts/run_pipeline.py --retrain`

---

## CURRENT IMPLEMENTATION STATUS (Phases 0–4 DONE)

### Architecture
```
NVD API + AbuseIPDB API
        ↓
Data Collection  (src/collectors/)
        ↓
Normalization    (src/pipeline/normalize.py)
        ↓
Deduplication    (src/pipeline/dedup.py)
        ↓
SQLite Database  (data/threat_intel.db)
        ↓
Feature Engineering  (src/pipeline/feature_engineering.py)
        ↓
Heuristic Labeling   (src/pipeline/labeling.py)
        ↓
ML Models            (src/ml/train.py + evaluate.py)
        ↓
Predictions + Ranking
        ↓
Threat Clustering    (src/pipeline/clustering.py)   ← Phase 1
        ↓
AI Summaries         (src/pipeline/summarizer.py)   ← Phase 2
        ↓
MITRE ATT&CK Mapping (src/pipeline/mitre_mapper.py) ← Phase 3
        ↓
Monitoring / History (db.pipeline_runs + threat_history) ← Phase 4
        ↓
Streamlit Dashboard  (src/dashboard/app.py)
```

### File structure
```
src/
  config.py                  — env vars, paths, constants
  schema.py                  — NormalizedThreat dataclass
  collectors/
    nvd_collector.py         — real NVD API v2.0
    abuseipdb_collector.py   — real AbuseIPDB blacklist API
  pipeline/
    normalize.py             — NVD + AbuseIPDB → NormalizedThreat
    dedup.py                 — dedup on id + last_seen
    db.py                    — ALL database operations (see DB section below)
    feature_engineering.py   — 9-feature matrix builder
    labeling.py              — heuristic priority scorer
    clustering.py            — K-Means, auto k (silhouette), TF-IDF text
    summarizer.py            — 7-section template-based NLP per threat
    mitre_mapper.py          — 3-tier ATT&CK inference (CWE/keyword/type)
  ml/
    train.py                 — LR + DT + RF, joblib persistence
    evaluate.py              — confusion matrix + feature importance PNGs
  dashboard/
    app.py                   — Streamlit, 5 tabs (see Dashboard section)
scripts/
  run_pipeline.py            — 13-step orchestrator
  generate_sample_data.py    — synthetic NVD/AbuseIPDB data
data/
  threat_intel.db            — SQLite (DO NOT DELETE)
models/
  *.joblib                   — trained models + scaler
reports/
  metrics.json, *.png        — evaluation artefacts
requirements.txt             — pandas, scikit-learn, streamlit, requests,
                               python-dotenv, matplotlib, scipy, joblib
.env                         — API keys (ABUSEIPDB_API_KEY, NVD_API_KEY)
```

### Database schema (current)
```sql
-- PRIMARY TABLE
threats (
  id TEXT PK, threat_type, title, description,
  severity_raw REAL, report_count INTEGER,
  first_seen TEXT, last_seen TEXT,
  source TEXT, source_reliability REAL,
  exploited_flag INTEGER, extra_json TEXT,
  predicted_priority TEXT, predicted_priority_score REAL,
  heuristic_label TEXT,
  cluster_id INTEGER,       -- Phase 1
  ai_summary TEXT           -- Phase 2
)

-- Phase 3
mitre_mappings (
  rowid PK AUTOINCREMENT,
  threat_id TEXT, tactic TEXT, technique_id TEXT,
  technique_name TEXT, confidence TEXT, basis TEXT,
  UNIQUE(threat_id, technique_id)
)

-- Phase 4
pipeline_runs (
  run_id PK AUTOINCREMENT, run_at TEXT, mode TEXT,
  total_threats INT, new_threats INT, updated_threats INT,
  unchanged_threats INT, n_critical INT, n_high INT,
  n_medium INT, n_low INT, duration_secs REAL, notes TEXT
)
threat_history (
  history_id PK AUTOINCREMENT, threat_id TEXT, run_id INT,
  run_at TEXT, previous_priority TEXT, new_priority TEXT,
  previous_score REAL, new_score REAL,
  change_type TEXT  -- 'new' | 'escalated' | 'reduced'
)
```

### Dashboard tabs (current — 5 tabs)
1. **🔒 Threats** — ranked table, pagination, Threat Details panel with
   AI summary + inline MITRE mappings
2. **🔗 Clusters** — clickable expander cards, donut charts, NLP cluster
   summaries, collapsible member tables
3. **🧩 MITRE ATT&CK** — tactic bar chart, top-techniques table,
   per-threat lookup with ATT&CK deep-links
4. **📡 Monitoring** — run history, new/changed chart, activity feed,
   per-threat priority timeline
5. **🤖 Model Evaluation** — accuracy metrics, confusion matrices,
   feature importance charts

### ML details
- **Features (9):** severity_raw, report_count_norm, recency_score,
  source_reliability, exploited_flag, reference_count_norm,
  high_risk_country, is_cve, is_malicious_ip
- **Labels:** heuristic (Critical ≥ 0.72, High ≥ 0.52, Medium ≥ 0.38, Low)
- **Models:** Logistic Regression, Decision Tree, Random Forest (best)
- **Accuracy:** ~94% on synthetic data (heuristic labels, not ground truth)

### Heuristic label weights
```
severity:           35%
cwe_risk:           12%
exploited_flag:     18%
reference_bonus:    10%
report_count_norm:  10%
recency_score:       8%
source_reliability:  7%
+ geographic boost: +5% for high-risk country IPs with severity ≥ 4
```

### Key coding conventions
- All DB changes use safe `ALTER TABLE` via `_MIGRATION_COLUMNS` list
- New tables go in `SCHEMA_SQL`-style constants + added to `init_db()`
- Pipeline steps numbered sequentially (currently 1–13) in `run_pipeline.py`
- Dashboard: purple dark theme, `st.tabs()`, `st.expander()` for details,
  matplotlib with `facecolor="#0d0d1a"` / `"#130d2e"` for dark charts
- No hardcoded API keys — always `os.getenv()` via `src/config.py`
- New dependencies → add to `requirements.txt` with `>=` version pin

---

## REMAINING PHASES TO IMPLEMENT

### PHASE 5 — Alerts and Notifications
**Goal:** Surface important events to the analyst without requiring them to
manually scan every run.

**What to build:**

1. **`alerts` table in DB:**
   ```sql
   alerts (
     alert_id PK AUTOINCREMENT,
     threat_id TEXT,
     run_id INT,
     alert_type TEXT,   -- see types below
     severity TEXT,     -- 'critical' | 'high' | 'warning' | 'info'
     message TEXT,
     created_at TEXT,
     status TEXT        -- 'new' | 'acknowledged' | 'dismissed'
   )
   ```

2. **`src/pipeline/alerting.py`** — new module:
   - `generate_alerts(diff, rows, run_id)` → list of alert dicts
   - Alert types to detect:
     - `new_critical` — new threat with Critical priority
     - `new_high` — new threat with High priority
     - `priority_escalated` — existing threat escalated to Critical or High
     - `exploit_appeared` — exploited_flag flipped 0→1 (needs history)
     - `notable_cluster` — a cluster crossed the "notable" threshold
     - `spike` — new_threats count > 2× the rolling average of previous runs
   - Each alert must have: threat_id, alert_type, severity, human-readable message
   - `upsert_alerts(alerts)` in db.py — idempotent on (threat_id, run_id, alert_type)

3. **Wire into `run_pipeline.py`** as **step 14** (after step 13 monitoring):
   ```python
   from src.pipeline.alerting import generate_alerts
   alerts = generate_alerts(diff, fresh_rows, run_id)
   db.upsert_alerts(alerts)
   print(f"[alerts] {len(alerts)} alerts generated")
   ```

4. **Dashboard — Alerts section in Monitoring tab** OR new `🚨 Alerts` tab:
   - Show new/unacknowledged alerts at the top with colour-coded severity
   - Allow analyst to acknowledge/dismiss each alert (use `st.button` +
     `db.update_alert_status(alert_id, status)`)
   - Badge count on the tab label if there are unacknowledged alerts
   - Keep `status='new'` alerts visually prominent (red border)

**Rules:**
- Do NOT send external emails/webhooks unless explicitly configured
- All alerts are dashboard-only by default
- Do not generate duplicate alerts for the same (threat_id, run_id, alert_type)

---

### PHASE 6 — Automated Threat Intelligence Reports
**Goal:** Generate a downloadable report summarising the threat landscape.

**What to build:**

1. **`src/pipeline/reporter.py`** — new module:
   - `generate_html_report(rows, runs, history, mitre, alerts)` → HTML string
   - Report sections:
     - Executive summary (total threats, critical/high counts, new this run)
     - Priority distribution (table + bar chart embedded as base64 PNG)
     - Top 10 threats by priority score
     - Priority changes since last run (escalated / reduced)
     - Cluster summary (table of all clusters)
     - MITRE ATT&CK coverage (top tactics/techniques)
     - Alerts summary
     - Appendix: full threat table
   - Use only stdlib + existing dependencies (no WeasyPrint, no Puppeteer)
   - Embed matplotlib charts as base64 `<img>` tags
   - Dark-themed HTML with inline CSS matching the dashboard colour palette

2. **Dashboard — Reports section** (add to Monitoring tab OR new tab):
   - "Generate Report" button → calls `generate_html_report(...)` → `st.download_button`
   - Show report timestamp
   - Option to select date range if multiple runs exist

3. **Save reports** to `reports/` directory with timestamp filename:
   `reports/threat_report_YYYYMMDD_HHMMSS.html`

**Rules:**
- Report must be reproducible from the DB alone (no external API calls)
- Do not fabricate data — every number must come from a DB query

---

### PHASE 7 — Additional CTI Sources
**Goal:** Extend collection beyond NVD + AbuseIPDB.

**Recommended source:** GreyNoise Community API (free tier)
- URL: `https://api.greynoise.io/v3/community/{ip}`
- Returns: noise classification, intent, tags for individual IPs
- No API key required for community tier
- Useful signal: complements AbuseIPDB with different classification

**What to build:**

1. **`src/collectors/greynoise_collector.py`**:
   - `fetch_greynoise_context(ip_list)` → list of raw records
   - Handles rate limiting (1 req/s community tier)
   - Returns raw JSON per IP

2. **`src/pipeline/normalize.py`**:
   - Add `normalize_greynoise_record(raw)` function
   - Map to `NormalizedThreat` with `source="greynoise"`,
     `threat_type="malicious_ip"`
   - Add `"greynoise": 0.7` to `SOURCE_RELIABILITY` in `config.py`
   - Update `normalize_batch()` to accept a third list

3. **`src/pipeline/dedup.py`**: no changes needed (already deduplicates on id=IP)

4. **`scripts/run_pipeline.py`**: add greynoise collection to `collect_live()`
   (NOT synthetic — no fake GreyNoise data needed)

5. **Dashboard**: source filter already works generically — no changes needed
   as long as source="greynoise" is stored correctly

**Rules:**
- Do not add GreyNoise to `--synthetic` mode
- Keep API key in `.env` as `GREYNOISE_API_KEY` even if community tier
  doesn't require it (future-proofing)
- Do not break NVD or AbuseIPDB collection

**Alternative if GreyNoise is unavailable:** AlienVault OTX (free API,
`pip install OTXv2`). Key = `OTX_API_KEY`.

---

### PHASE 8 — Better Explainability
**Goal:** Tell the analyst exactly why the ML model gave a threat its priority.

**What to build:**

1. **`src/pipeline/explainer.py`** — new module:
   - `explain_prediction(row, model, feature_cols, scaler=None)` → dict
   - Two approaches, implement both and show whichever is available:

   **Approach A — Feature contribution (manual, always available):**
   - For Random Forest: use `model.feature_importances_` × feature values
     to compute per-feature contribution to the predicted class
   - Normalise contributions to sum to 1
   - Return top-5 contributing features with direction (positive/negative)

   **Approach B — SHAP (optional, install `shap` package):**
   - `shap.TreeExplainer(model).shap_values(X_row)`
   - If `shap` is not installed, fall back to Approach A silently
   - Add `shap>=0.42` to `requirements.txt` only if implementing this

2. **`explain_all(rows, model, feature_cols)` → `{id: explanation_dict}`**

3. **Store explanations** as JSON in a new `explanation_json TEXT` column
   on the `threats` table (safe ALTER TABLE migration)

4. **Dashboard — Threat Details panel** (already has AI summary section):
   - Add "Why this priority?" section after the AI summary
   - Show a horizontal bar chart of feature contributions (top 5)
   - Plain-English sentence: "The top factors were: high severity (9.5/10),
     exploitation evidence present, 12 advisory references."

**Example output structure:**
```python
{
  "top_features": [
    {"feature": "severity_raw",    "value": 9.5,  "contribution": 0.52, "direction": "+"},
    {"feature": "exploited_flag",  "value": 1,    "contribution": 0.23, "direction": "+"},
    {"feature": "reference_count_norm", "value": 0.8, "contribution": 0.11, "direction": "+"},
  ],
  "plain_english": "High priority because: very high severity (9.5/10); exploitation evidence present; high advisory reference count.",
  "predicted_class": "High",
  "confidence": 0.87
}
```

**Rules:**
- Never produce explanations that contradict the model's actual prediction
- SHAP is optional — the module must work without it

---

### PHASE 9 — Analyst-Validated Ground Truth Labels
**Goal:** Allow a real analyst to validate/correct ML predictions and build
a ground-truth dataset for future retraining.

**What to build:**

1. **`analyst_feedback` table in DB:**
   ```sql
   analyst_feedback (
     feedback_id PK AUTOINCREMENT,
     threat_id TEXT UNIQUE,
     analyst_label TEXT,   -- 'Confirmed_Critical'|'Confirmed_High'|
                           --  'Confirmed_Medium'|'Confirmed_Low'|
                           --  'False_Positive'|'Needs_Review'
     feedback_notes TEXT,
     analyst_id TEXT,      -- placeholder, e.g. "analyst_1"
     created_at TEXT,
     updated_at TEXT
   )
   ```

2. **`db.py`** — add:
   - `upsert_analyst_feedback(threat_id, label, notes, analyst_id)`
   - `fetch_analyst_feedback()` → list of dicts
   - `fetch_feedback_for_threat(threat_id)` → dict or None

3. **Dashboard — Threat Details panel** (in Threats tab):
   - After the AI summary + MITRE section, add an "Analyst Feedback" section
   - Three columns:
     - Label dropdown: Confirmed Critical / High / Medium / Low /
       False Positive / Needs Review
     - Notes text input
     - Submit button → calls `db.upsert_analyst_feedback()`
   - Show existing feedback if already submitted
   - Display all three labels clearly: Heuristic | ML Predicted | Analyst Validated

4. **Dashboard — new column in Threats table:**
   - Add `analyst_label` column to the ranked threats table (show "—" if not set)

5. **`scripts/run_pipeline.py`** — add `--retrain-validated` flag:
   - Fetches only threats with `analyst_feedback.analyst_label IS NOT NULL`
   - Uses analyst labels instead of heuristic labels for training
   - Prints a warning if < 50 validated examples (too few for reliable training)

**Rules:**
- Original heuristic label and ML prediction must NEVER be overwritten
- Analyst label stored separately — never merged into `predicted_priority`
- Show all three labels distinctly in the UI

---

### PHASE 10 — Organisational Context
**Goal:** Let analysts configure their asset environment so threat priority
can be contextualised against what actually matters to their organisation.

**What to build:**

1. **`src/config_org.py`** — new file (NOT `config.py`):
   - Loads from `org_context.json` in the project root (gitignored)
   - Schema:
     ```json
     {
       "org_name": "Demo Organisation",
       "high_value_assets": ["Apache", "Microsoft", "OpenSSL"],
       "internet_exposed": true,
       "criticality": "high",
       "ignored_sources": []
     }
     ```
   - `load_org_context()` → dict, returns empty defaults if file missing

2. **`src/pipeline/context_scorer.py`** — new module:
   - `apply_context_boost(row, org_context)` → adjusted priority score
   - Rules:
     - If CVE vendor matches `high_value_assets` → +0.10 score boost
     - If `internet_exposed=true` and threat is Critical/High → +0.05
     - If source in `ignored_sources` → skip entirely
   - Store as `context_adjusted_score REAL` column on threats table
   - This score is for DISPLAY only — do not retrain ML on it

3. **Dashboard — Settings page** (new tab OR sidebar section):
   - Form to set org_name, high_value_assets (multiselect), internet_exposed
   - Saves to `org_context.json` on submit
   - Show "Context-Adjusted Score" column in the threats table when configured

4. **Dashboard — Threat Details panel:**
   - Show context adjustment note: "This threat matches your high-value assets
     (Apache) — score boosted by +0.10"

**Rules:**
- The `org_context.json` file must be in `.gitignore`
- Never invent an organisation's assets — only use what is explicitly configured
- Context score must be clearly labelled as separate from the ML prediction

---

### PHASE 11 — Class Imbalance Improvements
**Goal:** Improve detection of rare Critical/High threats.

**What to build:**

1. **Investigate current class distribution:**
   - Print class counts in `run_pipeline.py` after labeling (already done)
   - Calculate per-class precision/recall/F1 from `classification_report`
     (already in `evaluate.py` — surface these in the dashboard)

2. **`src/ml/train.py`** — add two new training strategies:
   - **Strategy B:** SMOTE oversampling (`pip install imbalanced-learn`)
     ```python
     from imblearn.over_sampling import SMOTE
     sm = SMOTE(random_state=RANDOM_SEED)
     X_resampled, y_resampled = sm.fit_resample(X_train, y_train)
     ```
   - **Strategy C:** Threshold tuning — after RF training, tune the
     classification threshold per class to maximise F1 on minority classes
   - Compare all three strategies in `evaluate.py` and report which performs
     best on Critical/High F1

3. **Dashboard — Model Evaluation tab:**
   - Add per-class F1 scores as a table (not just overall accuracy)
   - Highlight Critical/High rows in red if F1 < 0.5
   - Add a note: "Training labels are heuristic — F1 scores reflect how well
     the model learns the heuristic, not real-world analyst agreement."

4. **`requirements.txt`:**
   - Add `imbalanced-learn>=0.11` only if SMOTE is implemented

**Rules:**
- Do not artificially inflate metrics
- Compare strategies honestly — if SMOTE makes no difference, say so
- The default training path must remain unchanged — new strategies are
  optional (`--strategy` flag or config setting)

---

## IMPLEMENTATION ORDER FOR REMAINING PHASES

```
Phase 5 (Alerts)         → implement first, depends on Phase 4 diff output
Phase 6 (Reports)        → depends on Phase 5 alerts table for report content
Phase 7 (More Sources)   → independent, can be done any time after Phase 4
Phase 8 (Explainability) → depends on existing ML models (already done)
Phase 9 (Analyst Labels) → independent feature, can run in parallel with 8
Phase 10 (Org Context)   → independent, add after Phase 9
Phase 11 (Imbalance)     → last, after all data and label improvements done
```

---

## IMPORTANT CONSTRAINTS FOR ALL REMAINING PHASES

1. **Never overwrite working functionality.** Read the relevant files before
   editing. Use `str_replace` for targeted edits, not full rewrites.

2. **DB migrations are safe ALTER TABLE only.** Add new columns to
   `_MIGRATION_COLUMNS` list in `db.py`. Add new tables as separate `*_SCHEMA_SQL`
   constants. Call `conn.execute(NEW_SCHEMA_SQL)` inside `init_db()`.

3. **Pipeline steps are numbered 1–13.** New steps continue from 14 onwards.
   Import new modules at the top of `run_pipeline.py` with the others.

4. **Dashboard tabs.** Current tabs in order:
   `tab_threats, tab_clusters, tab_mitre, tab_monitor, tab_models`
   New tabs go before `tab_models` (Model Evaluation stays last).
   Update the `st.tabs([...])` call and add the corresponding `with tab_X:` block.

5. **Colour palette** (keep consistent across all new UI):
   - Background: `#0d0d1a`, card bg: `#1a0a3d`, border: `#4a1d96`
   - Purple accent: `#a855f7`, `#7c3aed`, `#c084fc`
   - Critical: `#fda4af` / `#4c0519`, High: `#fdba74` / `#431407`
   - Medium: `#fde68a` / `#3b2509`, Low: `#86efac` / `#052e16`
   - Chart backgrounds: `fig.patch.set_facecolor("#0d0d1a")`, `ax.set_facecolor("#130d2e")`

6. **After every phase:** run `python scripts/run_pipeline.py --retrain`,
   verify no errors, check dashboard starts, then commit + push to `main`.

7. **Commit message format:**
   ```
   feat: implement Phase N - <short title>
   
   - bullet summary of what was added
   ```

8. **Never claim** that heuristic labels are ground truth, that a cluster is
   a confirmed campaign, or that MITRE mappings are analyst-verified.

9. **No paid LLM APIs** unless wrapped in an optional try/except with template
   fallback. The platform must run fully offline.

10. **No hardcoded secrets.** All API keys via `os.getenv()` in `src/config.py`.

---

## HOW TO RUN THE CURRENT SYSTEM

```powershell
# Activate venv
cd "c:\Users\tiyas\Downloads\threat_intel_platform\threat_intel_platform"
.\venv\Scripts\Activate.ps1

# Run full pipeline (offline, no API keys needed)
python scripts/run_pipeline.py --synthetic

# Run pipeline with real APIs (needs .env keys)
python scripts/run_pipeline.py --live

# Retrain on existing DB without re-collecting
python scripts/run_pipeline.py --retrain

# Launch dashboard
streamlit run src/dashboard/app.py
```

---

## CURRENT TEST DATA STATE

- **1550 threats** in DB (1500 original synthetic + 50 from second run)
- **2 pipeline runs** recorded in `pipeline_runs`
- **62 history entries** in `threat_history` (50 new + 7 escalated + 5 reduced)
- **2709 MITRE mappings** (613 High / 126 Medium / 1970 Low confidence)
- **4 clusters** (k=4, silhouette-optimal)
- **All 1550 threats** have `ai_summary` populated

---

*This file can be deleted once all phases are implemented.*
