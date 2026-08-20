"""
Deduplicates normalized threats by their natural key (`id`: CVE-ID or IP address).

If a duplicate is found (e.g. the same CVE fetched twice across pipeline runs),
we keep the record with the more recent `last_seen` timestamp, since it reflects
the freshest information.
"""
from typing import List
from src.schema import NormalizedThreat


def deduplicate(threats: List[NormalizedThreat]) -> List[NormalizedThreat]:
    best_by_id = {}
    for t in threats:
        existing = best_by_id.get(t.id)
        if existing is None or (t.last_seen or "") > (existing.last_seen or ""):
            best_by_id[t.id] = t
    return list(best_by_id.values())


if __name__ == "__main__":
    from src.schema import NormalizedThreat

    sample = [
        NormalizedThreat("CVE-2025-1", "cve", "t", "d", 5.0, 1, "2025-01-01", "2025-01-01",
                          "nvd", 0.9, False, {}),
        NormalizedThreat("CVE-2025-1", "cve", "t", "d", 5.0, 1, "2025-01-01", "2025-02-01",
                          "nvd", 0.9, False, {}),  # duplicate, newer last_seen
    ]
    result = deduplicate(sample)
    print(f"{len(sample)} -> {len(result)} after dedup (kept last_seen={result[0].last_seen})")
