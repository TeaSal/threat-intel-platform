"""
Orchestrates the full pipeline end-to-end:
collect -> normalize -> dedup -> store -> feature-engineer -> label -> train -> evaluate -> write predictions

Usage:
    python scripts/run_pipeline.py --synthetic     # offline, no API keys / internet needed
    python scripts/run_pipeline.py --live           # real NVD + AbuseIPDB APIs (needs keys + internet)
"""
import sys
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
    print("[collect] fetching real data from NVD + AbuseIPDB (requires internet + API keys)...")
    return fetch_recent_cves(), fetch_malicious_ips()


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

    # 1. Collect
    if args.retrain:
        total_in_db = db.count()
        if total_in_db == 0:
            print("[collect] ERROR: --retrain requires existing records in the DB. Run --live first.")
            sys.exit(1)
        print(f"[collect] --retrain: skipping collection, using {total_in_db} existing DB records")
    elif args.synthetic:
        raw_nvd, raw_abuseipdb = collect_synthetic(args.n_cves, args.n_ips)
    else:
        raw_nvd, raw_abuseipdb = collect_live()

    if not args.retrain:
        print(f"[collect] raw records: {len(raw_nvd)} NVD, {len(raw_abuseipdb)} AbuseIPDB")

        # 2. Normalize
        normalized = normalize_batch(raw_nvd, raw_abuseipdb)
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
    # Using predict_proba().max() would rank "Low, 100% confident" above
    # "High, 90% confident" -- wrong for an analyst triage view. Instead we compute
    # an expected-severity score: each class's probability weighted by its severity
    # rank (Low=0 .. Critical=3), summed. This is monotonic with actual priority
    # and still reflects the model's uncertainty across classes.
    severity_rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    class_order = list(best_model.classes_)
    weights = [severity_rank[c] for c in class_order]
    # Always divide by 3 (Critical's rank) regardless of which classes are
    # present in this run — avoids scores of 1.0 when Critical is absent.
    expected_severity = (pred_probs * weights).sum(axis=1) / 3.0  # normalize to 0-1

    id_to_prediction = dict(zip(labeled["id"], zip(pred_labels, expected_severity)))
    db.update_predictions(id_to_prediction)
    print(f"[predict] wrote predictions to DB using {best_model_name} "
          f"(ranking score = probability-weighted expected severity, not raw confidence)")

    # 10. Cluster threats
    print("[cluster] running threat clustering...")
    # Attach source + threat_type + description back for richer text features
    rows_df = pd.DataFrame(rows)[["id", "source", "threat_type", "description"]]
    labeled_with_meta = labeled.merge(rows_df, on="id", how="left")
    id_to_cluster, cluster_summary, n_clusters = cluster_threats(labeled_with_meta)
    db.update_cluster_ids(id_to_cluster)
    print(f"[cluster] assigned {len(id_to_cluster)} threats to {n_clusters} clusters")

    # 11. Generate AI summaries for every threat record
    print("[summarize] generating AI threat summaries...")
    fresh_rows = db.fetch_all_as_dicts()          # re-fetch so summaries see cluster_id + priority
    id_to_summary = generate_all_summaries(fresh_rows)
    db.update_summaries(id_to_summary)
    print(f"[summarize] wrote summaries for {len(id_to_summary)} threats")

    # 12. MITRE ATT&CK mapping
    print("[mitre] inferring MITRE ATT&CK technique mappings...")
    mitre_rows = db.fetch_all_as_dicts()   # same fresh snapshot used for summaries
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

    print("\nPipeline complete. Run `streamlit run src/dashboard/app.py` to view the dashboard.")


if __name__ == "__main__":
    main()
