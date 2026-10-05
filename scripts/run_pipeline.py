"""
Orchestrates the full pipeline end-to-end:
collect -> normalize -> dedup -> store -> feature-engineer -> label -> train -> evaluate -> write predictions -> cluster -> summarize -> mitre -> monitor

Usage:
    python scripts/run_pipeline.py --synthetic     # offline, no API keys / internet needed
    python scripts/run_pipeline.py --live           # real NVD + AbuseIPDB APIs (needs keys + internet)
"""
import sys
import time
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd

from src.pipeline.normalize import normalize_batch
from src.pipeline.dedup import deduplicate
from src.pipeline import db
from src.pipeline.feature_engineering import build_feature_matrix
from src.pipeline.labeling import apply_heuristic_labels
from src.pipeline.clustering import cluster_threats
from src.pipeline.summarizer import generate_all_summaries
from src.pipeline.mitre_mapper import map_all_threats
from src.pipeline.alerting import generate_alerts
from src.ml.train import train_all_models
from src.ml.evaluate import evaluate_all


def collect_synthetic(n_cves=300, n_ips=300):
    from scripts.generate_sample_data import generate_raw_nvd_response, generate_raw_abuseipdb_response
    print(f"[collect] generating {n_cves} synthetic CVE records + {n_ips} synthetic IP records "
          f"(offline test data — see README.md)")
    return generate_raw_nvd_response(n_cves), generate_raw_abuseipdb_response(n_ips)


def collect_live():
    from src.collectors.nvd_collector import fetch_recent_cves
    from src.collectors.abuseipdb_collector import fetch_malicious_ips
    from src.collectors.greynoise_collector import fetch_greynoise_context
    from src.config import GREYNOISE_API_KEY

    print("[collect] fetching real data from NVD + AbuseIPDB (requires internet + API keys)...")
    raw_nvd       = fetch_recent_cves()
    raw_abuseipdb = fetch_malicious_ips()

    # Phase 7: enrich AbuseIPDB IPs with GreyNoise context (community tier, no key needed)
    # Build the IP list from the AbuseIPDB records already fetched
    ip_list = [r["ipAddress"] for r in raw_abuseipdb if r.get("ipAddress")]
    if ip_list:
        key_note = "with API key" if GREYNOISE_API_KEY else "community tier, no key"
        print(f"[collect] querying GreyNoise for {len(ip_list)} IPs ({key_note}, ~1 req/s)...")
        raw_greynoise = fetch_greynoise_context(ip_list, max_ips=200)
        print(f"[collect] GreyNoise returned {len(raw_greynoise)} classified records")
    else:
        raw_greynoise = []
        print("[collect] no IPs to query GreyNoise for")

    return raw_nvd, raw_abuseipdb, raw_greynoise


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--synthetic", action="store_true", help="Use offline synthetic data")
    mode.add_argument("--live", action="store_true", help="Use real live APIs (needs keys + internet)")
    mode.add_argument("--retrain", action="store_true",
                      help="Skip collection; re-label and retrain on existing DB records")
    parser.add_argument("--n-cves", type=int, default=300)
    parser.add_argument("--n-ips", type=int, default=300)
    args = parser.parse_args()

    pipeline_start = time.time()
    run_mode = "synthetic" if args.synthetic else "live" if args.live else "retrain"

    # ── Phase 4: snapshot state BEFORE this run ────────────────────────────
    db.init_db()   # ensure tables exist before snapshot
    ids_before        = set(r["id"] for r in db.fetch_all_as_dicts())
    priorities_before = db.snapshot_priorities()

    # 1. Collect
    if args.retrain:
        total_in_db = db.count()
        if total_in_db == 0:
            print("[collect] ERROR: --retrain requires existing records in the DB. Run --live first.")
            sys.exit(1)
        print(f"[collect] --retrain: skipping collection, using {total_in_db} existing DB records")
        raw_nvd = raw_abuseipdb = raw_greynoise = []
    elif args.synthetic:
        raw_nvd, raw_abuseipdb = collect_synthetic(args.n_cves, args.n_ips)
        raw_greynoise = []   # no synthetic GreyNoise data (per Phase 7 spec)
    else:
        raw_nvd, raw_abuseipdb, raw_greynoise = collect_live()

    if not args.retrain:
        print(f"[collect] raw records: {len(raw_nvd)} NVD, {len(raw_abuseipdb)} AbuseIPDB"
              + (f", {len(raw_greynoise)} GreyNoise" if raw_greynoise else ""))

        # 2. Normalize
        normalized = normalize_batch(raw_nvd, raw_abuseipdb,
                                     raw_greynoise if raw_greynoise else None)
        print(f"[normalize] {len(normalized)} records mapped to common schema")

        # 3. Deduplicate
        deduped = deduplicate(normalized)
        print(f"[dedup] {len(normalized)} -> {len(deduped)} after deduplication")

        # 4. Store
        db.upsert_threats(deduped)
        total_in_db = db.count()
        print(f"[db] stored. total rows in database now: {total_in_db}")

    # 5. Feature engineering
    rows = db.fetch_all_as_dicts()
    feats, feature_cols = build_feature_matrix(rows)
    print(f"[features] built feature matrix: {feats.shape[0]} rows x {len(feature_cols)} features")

    # 6. Heuristic labeling
    labeled = apply_heuristic_labels(feats)
    print("[labeling] heuristic label distribution:")
    print(labeled["heuristic_label"].value_counts().to_string())
    db.update_heuristic_labels(dict(zip(labeled["id"], labeled["heuristic_label"])))

    # 7. Train models
    print("[train] training Logistic Regression, Decision Tree, Random Forest...")
    results, scaler = train_all_models(labeled)

    # 8. Evaluate
    print("[evaluate] evaluating all models...")
    metrics = evaluate_all(results)

    # 9. Write predictions back to DB using the best model (Random Forest, typically strongest)
    best_model_name = "random_forest"
    best_model = results[best_model_name]["model"]
    X_all = labeled[feature_cols].values
    pred_labels = best_model.predict(X_all)
    pred_probs = best_model.predict_proba(X_all)

    # IMPORTANT: the score we rank by must reflect PRIORITY, not model confidence.
    severity_rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    class_order = list(best_model.classes_)
    weights = [severity_rank[c] for c in class_order]
    expected_severity = (pred_probs * weights).sum(axis=1) / 3.0

    id_to_prediction = dict(zip(labeled["id"], zip(pred_labels, expected_severity)))
    db.update_predictions(id_to_prediction)
    print(f"[predict] wrote predictions to DB using {best_model_name} "
          f"(ranking score = probability-weighted expected severity, not raw confidence)")

    # ── Phase 4: diff old vs new priorities + record history ──────────────
    ids_after        = set(labeled["id"].tolist())
    priorities_after = {
        tid: (label, float(score))
        for tid, (label, score) in id_to_prediction.items()
    }
    diff = db.diff_threats(ids_before, ids_after, priorities_before, priorities_after)
    n_new       = len(diff["new"])
    n_escalated = len(diff["escalated"])
    n_reduced   = len(diff["reduced"])
    n_unchanged = len(diff["unchanged"])

    all_diff_entries = (
        diff["new"] + diff["escalated"] + diff["reduced"] + diff["unchanged"]
    )

    # Compute priority breakdown from current predictions
    priority_counts = pd.Series(pred_labels).value_counts()
    n_critical = int(priority_counts.get("Critical", 0))
    n_high     = int(priority_counts.get("High",     0))
    n_medium   = int(priority_counts.get("Medium",   0))
    n_low      = int(priority_counts.get("Low",      0))

    print(
        f"[monitor] this run: {n_new} new  |  "
        f"{n_escalated} escalated  |  {n_reduced} reduced  |  "
        f"{n_unchanged} unchanged"
    )
    if n_escalated:
        escalated_ids = [e["threat_id"] for e in diff["escalated"]]
        print(f"[monitor] escalated threats: {escalated_ids[:5]}"
              + (" ..." if len(escalated_ids) > 5 else ""))

    # 10. Cluster threats
    print("[cluster] running threat clustering...")
    rows_df = pd.DataFrame(rows)[["id", "source", "threat_type", "description"]]
    labeled_with_meta = labeled.merge(rows_df, on="id", how="left")
    id_to_cluster, cluster_summary, n_clusters = cluster_threats(labeled_with_meta)
    db.update_cluster_ids(id_to_cluster)
    print(f"[cluster] assigned {len(id_to_cluster)} threats to {n_clusters} clusters")

    # 11. Generate AI summaries for every threat record
    print("[summarize] generating AI threat summaries...")
    fresh_rows = db.fetch_all_as_dicts()
    id_to_summary = generate_all_summaries(fresh_rows)
    db.update_summaries(id_to_summary)
    print(f"[summarize] wrote summaries for {len(id_to_summary)} threats")

    # 12. MITRE ATT&CK mapping
    print("[mitre] inferring MITRE ATT&CK technique mappings...")
    mitre_rows = db.fetch_all_as_dicts()
    mitre_mappings, mitre_stats = map_all_threats(mitre_rows)
    db.upsert_mitre_mappings(mitre_mappings)
    print(
        f"[mitre] {mitre_stats['total_mappings']} mappings across "
        f"{mitre_stats['threats_mapped']} threats  "
        f"(High={mitre_stats['by_confidence']['High']}, "
        f"Medium={mitre_stats['by_confidence']['Medium']}, "
        f"Low={mitre_stats['by_confidence']['Low']})"
    )
    if mitre_stats["top_tactics"]:
        print("[mitre] top tactics: " +
              ", ".join(f"{t}({n})" for t, n in mitre_stats["top_tactics"]))

    # 13. Record this pipeline run + threat history (Phase 4)
    duration = time.time() - pipeline_start
    run_id = db.record_pipeline_run(
        mode=run_mode,
        total_threats=len(ids_after),
        new_threats=n_new,
        updated_threats=n_escalated + n_reduced,
        unchanged_threats=n_unchanged,
        n_critical=n_critical,
        n_high=n_high,
        n_medium=n_medium,
        n_low=n_low,
        duration_secs=duration,
        notes=(
            f"escalated={n_escalated}, reduced={n_reduced}, "
            f"RF_accuracy={metrics.get('random_forest', {}).get('accuracy', 0):.3f}"
        ),
    )
    db.record_threat_history(run_id, all_diff_entries)
    print(
        f"[monitor] run #{run_id} recorded  |  "
        f"duration {duration:.1f}s  |  "
        f"total {len(ids_after)} threats"
    )

    # 14. Generate and store alerts (Phase 5)
    print("[alerts] generating alerts...")
    # Fetch previous runs to compute rolling average for spike detection
    previous_runs = db.fetch_pipeline_runs(limit=51)  # includes current run
    # Exclude the run we just recorded (it will be the first in the list, newest first)
    prev_new_counts = [
        r["new_threats"] for r in previous_runs
        if r["run_id"] != run_id and r.get("new_threats") is not None
    ]
    alerts = generate_alerts(diff, fresh_rows, run_id,
                             previous_run_new_counts=prev_new_counts)
    db.upsert_alerts(alerts)
    n_critical_alerts = sum(1 for a in alerts if a["severity"] == "critical")
    n_high_alerts     = sum(1 for a in alerts if a["severity"] == "high")
    n_warn_alerts     = sum(1 for a in alerts if a["severity"] == "warning")
    print(
        f"[alerts] {len(alerts)} alerts generated  |  "
        f"critical={n_critical_alerts}  high={n_high_alerts}  warning={n_warn_alerts}"
    )

    print("\nPipeline complete. Run `streamlit run src/dashboard/app.py` to view the dashboard.")


if __name__ == "__main__":
    main()
