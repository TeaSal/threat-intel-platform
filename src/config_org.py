"""
Organisational Context Configuration — Phase 10
================================================

Loads the organisation's asset/environment profile from org_context.json
(gitignored — never committed). This file is SEPARATE from config.py to keep
global platform config clean.

If org_context.json does not exist, safe defaults are returned so every other
module continues to work without the file present.

Schema of org_context.json:
{
    "org_name":           "Demo Organisation",
    "high_value_assets":  ["Apache", "Microsoft", "OpenSSL", "Cisco"],
    "internet_exposed":   true,
    "criticality":        "high",    // "low" | "medium" | "high" | "critical"
    "ignored_sources":    []         // e.g. ["greynoise"] to skip a source
}
"""
import json
from pathlib import Path

_ORG_CONTEXT_PATH = Path(__file__).resolve().parent.parent / "org_context.json"

_DEFAULT_CONTEXT = {
    "org_name":          "",
    "high_value_assets": [],
    "internet_exposed":  False,
    "criticality":       "medium",
    "ignored_sources":   [],
}

# Criticality multipliers — applied on top of the ML score for display only.
CRITICALITY_BOOST = {
    "critical": 0.12,
    "high":     0.08,
    "medium":   0.04,
    "low":      0.00,
}


def load_org_context() -> dict:
    """
    Load and return the org context dict.
    Returns safe defaults if the file is missing or malformed.
    """
    if not _ORG_CONTEXT_PATH.exists():
        return dict(_DEFAULT_CONTEXT)
    try:
        with open(_ORG_CONTEXT_PATH, encoding="utf-8") as f:
            data = json.load(f)
        # Merge with defaults so missing keys don't cause KeyErrors downstream
        merged = dict(_DEFAULT_CONTEXT)
        merged.update({k: v for k, v in data.items() if k in _DEFAULT_CONTEXT})
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULT_CONTEXT)


def save_org_context(ctx: dict) -> None:
    """Persist the org context dict to org_context.json."""
    with open(_ORG_CONTEXT_PATH, "w", encoding="utf-8") as f:
        json.dump(ctx, f, indent=2)


def org_context_configured() -> bool:
    """True if an org_context.json with at least org_name or assets exists."""
    ctx = load_org_context()
    return bool(ctx.get("org_name") or ctx.get("high_value_assets"))
