"""
Organisational Context Scorer — Phase 10
==========================================

Applies organisation-specific asset context to threat records, producing
a `context_adjusted_score` for DISPLAY purposes only.

IMPORTANT DESIGN CONSTRAINTS:
- This score is NEVER fed back into ML training. The ML model is trained
  solely on the generic heuristic labels.
- This score NEVER overwrites `predicted_priority` or `predicted_priority_score`.
- It is stored as a separate `context_adjusted_score` column so analysts can
  see how their environment changes the relevance of each threat.
- If no org_context.json is configured, every threat gets score = None and
  the dashboard shows the standard ML score unchanged.

Context rules applied (cumulative, capped at 1.0):
  1. Vendor/asset match: CVE vendor in org's high_value_assets → +0.10
  2. Keyword match:      CVE description mentions an asset name → +0.05
  3. Internet exposure:  internet_exposed=true AND threat is Critical/High → +0.05
  4. Source filter:      threat source in ignored_sources → score = 0.0 (suppressed)
  5. Org criticality:    global boost from CRITICALITY_BOOST dict
"""

import json
import re
from typing import Optional

from src.config_org import load_org_context, CRITICALITY_BOOST


def _parse_extra(extra_json) -> dict:
    if not extra_json:
        return {}
    if isinstance(extra_json, dict):
        return extra_json
    try:
        return json.loads(extra_json)
    except (ValueError, TypeError):
        return {}


def apply_context_score(row: dict, org_context: Optional[dict] = None) -> tuple[float | None, list[str]]:
    """
    Compute a context-adjusted priority score for a single threat row.

    Parameters
    ----------
    row         : threat dict from db.fetch_all_as_dicts()
    org_context : loaded org context dict (pass in to avoid re-loading per row)

    Returns
    -------
    (adjusted_score, reasons) where:
      adjusted_score : float 0.0–1.0, or None if org context not configured
      reasons        : list of plain-English strings explaining adjustments made
    """
    if org_context is None:
        org_context = load_org_context()

    # If no context is configured, return None — UI shows standard ML score
    if not org_context.get("org_name") and not org_context.get("high_value_assets"):
        return None, []

    base_score = float(row.get("predicted_priority_score") or 0.0)
    extra      = _parse_extra(row.get("extra_json"))
    source     = row.get("source", "")
    priority   = row.get("predicted_priority", "")
    description = (row.get("description") or "").lower()
    vendor      = (extra.get("vendor") or "").lower()

    reasons: list[str] = []
    boost = 0.0

    # Rule 1: Suppression — ignored source
    ignored = [s.lower() for s in org_context.get("ignored_sources", [])]
    if source.lower() in ignored:
        return 0.0, [f"Suppressed: source '{source}' is in your ignored_sources list."]

    # Rule 2: High-value asset vendor match (exact, case-insensitive)
    high_value = [a.lower() for a in org_context.get("high_value_assets", [])]
    matched_assets = []
    for asset in high_value:
        if asset in vendor or asset in description:
            matched_assets.append(asset.title())
    if matched_assets:
        asset_boost = min(0.10, 0.05 * len(matched_assets))
        boost += asset_boost
        reasons.append(
            f"Asset match: {', '.join(matched_assets)} found in threat data "
            f"(+{asset_boost:.2f} boost)."
        )

    # Rule 3: Internet exposure — high/critical threats matter more when exposed
    if org_context.get("internet_exposed") and priority in ("Critical", "High"):
        boost += 0.05
        reasons.append(
            "Internet exposure: your environment is internet-facing and this is a "
            f"{priority}-priority threat (+0.05 boost)."
        )

    # Rule 4: Organisational criticality global boost
    crit_key = org_context.get("criticality", "medium").lower()
    crit_boost = CRITICALITY_BOOST.get(crit_key, 0.0)
    if crit_boost > 0:
        boost += crit_boost
        reasons.append(
            f"Organisational criticality set to '{crit_key}' (+{crit_boost:.2f} global boost)."
        )

    if not reasons:
        reasons.append(
            "No context-specific adjustments apply to this threat in your configuration."
        )

    adjusted = min(1.0, base_score + boost)
    return round(adjusted, 4), reasons


def score_all_threats(rows: list, org_context: Optional[dict] = None) -> dict:
    """
    Score all threats and return {threat_id: (adjusted_score, reasons)}.
    Efficient — loads org_context once and reuses it.
    """
    if org_context is None:
        org_context = load_org_context()
    return {
        row["id"]: apply_context_score(row, org_context)
        for row in rows
        if row.get("id")
    }
