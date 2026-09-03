"""
ThreatGate - Diff & Summary Module
差異比對與摘要產生模組

Input:  data/threat_intel_normalized.json  (today's deduped "confirmed" list)
        data/baseline_active_list.json      (the list currently live on the
                                              firewall - absent on first run)
Output: data/diff_summary.json              (added/removed summary for the
                                              approval flow to act on)

Design note: "baseline" means "what is actually live on the firewall right
now", not "whatever we computed today". It only advances when a human
approves a run AND that run is actually published (see app/approval.py) -
that's the two-key design this project demonstrates: compute vs. commit are
always separate steps.
"""

import csv
import json
import os
import sys
import uuid
from datetime import datetime, timezone

DATA_DIR = os.environ.get("THREATGATE_DATA_DIR", "data")
NORMALIZED_FILE = os.path.join(DATA_DIR, "threat_intel_normalized.json")
BASELINE_FILE = os.path.join(DATA_DIR, "baseline_active_list.json")
DIFF_OUTPUT_FILE = os.path.join(DATA_DIR, "diff_summary.json")
OBSERVATION_LOG_FILE = os.path.join(DATA_DIR, "observation_log.csv")

SOURCE_LIST = ["Feodo Tracker", "Spamhaus DROP", "ThreatFox", "URLhaus", "AlienVault OTX"]

# Anomaly detection: flag a run if it looks like a source went haywire rather
# than genuine threat-landscape movement. Tune these two knobs to your own
# traffic's normal day-to-day noise level.
ANOMALY_GROWTH_RATE = 0.2          # >20% growth over baseline
ANOMALY_ABSOLUTE_THRESHOLD = 450   # or an absolute jump this large


def load_json_or_default(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def entry_key(entry):
    return (entry["type"], entry["indicator"])


def compute_diff(baseline_entries, today_entries):
    baseline_map = {entry_key(e): e for e in baseline_entries}
    today_map = {entry_key(e): e for e in today_entries}

    added_keys = today_map.keys() - baseline_map.keys()
    removed_keys = baseline_map.keys() - today_map.keys()
    unchanged_keys = today_map.keys() & baseline_map.keys()

    added = [today_map[k] for k in added_keys]
    removed = [baseline_map[k] for k in removed_keys]

    return added, removed, len(unchanged_keys)


def check_anomaly(baseline_count, added_count):
    """Skip the check on the very first run - everything being 'new' is expected then."""
    if baseline_count == 0:
        return False, "First run - no baseline to compare against yet"

    growth_rate = added_count / baseline_count
    if added_count > ANOMALY_ABSOLUTE_THRESHOLD:
        return True, f"Added {added_count} exceeds the absolute threshold of {ANOMALY_ABSOLUTE_THRESHOLD} - verify sources"
    if growth_rate > ANOMALY_GROWTH_RATE:
        return True, f"Added count is {growth_rate:.1%} of baseline, above the {ANOMALY_GROWTH_RATE:.0%} threshold - verify sources"
    return False, "Within normal range"


def get_per_source_counts():
    counts = {s: {"confirmed": 0, "observation": 0} for s in SOURCE_LIST}
    raw_file = os.path.join(DATA_DIR, "threat_intel_raw.json")
    try:
        with open(raw_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return counts

    for entry in raw.get("entries", []):
        source = entry.get("source")
        tier = entry.get("confidence_tier", "confirmed")
        if source in counts:
            counts[source][tier] = counts[source].get(tier, 0) + 1

    return counts


def log_daily_observation(diff_summary):
    """Append one row per run - never overwritten, so history builds up in one CSV."""
    os.makedirs(DATA_DIR, exist_ok=True)
    file_exists = os.path.isfile(OBSERVATION_LOG_FILE)

    observation_count = ""
    try:
        with open(os.path.join(DATA_DIR, "threat_intel_observation.json"), "r", encoding="utf-8") as f:
            observation_count = json.load(f).get("total", "")
    except FileNotFoundError:
        pass

    per_source = get_per_source_counts()

    row = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "run_id": diff_summary["run_id"],
        "baseline_count": diff_summary["baseline_count"],
        "today_count": diff_summary["today_count"],
        "observation_count": observation_count,
        "added": diff_summary["added_count"],
        "removed": diff_summary["removed_count"],
        "unchanged": diff_summary["unchanged_count"],
        "is_first_run": diff_summary["is_first_run"],
        "is_anomaly": diff_summary["is_anomaly"],
        "anomaly_reason": diff_summary["anomaly_reason"],
    }

    for s in SOURCE_LIST:
        row[f"{s}-confirmed"] = per_source[s]["confirmed"]
        row[f"{s}-observation"] = per_source[s]["observation"]

    with open(OBSERVATION_LOG_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def promote_baseline(entries, baseline_file: str = None):
    """Set the given list as the new 'live on the firewall' baseline.
    In the real flow this is only called by app/approval.py after a
    publish actually succeeds - never speculatively."""
    baseline_file = baseline_file or BASELINE_FILE
    new_baseline = {
        "entries": entries,
        "promoted_at": datetime.now(timezone.utc).isoformat(),
    }
    os.makedirs(os.path.dirname(baseline_file) or ".", exist_ok=True)
    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(new_baseline, f, ensure_ascii=False, indent=2)


def run(promote: bool = False) -> dict:
    normalized = load_json_or_default(NORMALIZED_FILE, None)
    if normalized is None:
        raise FileNotFoundError(f"{NORMALIZED_FILE} not found - run dedupe_normalize first")

    today_entries = normalized.get("entries", [])
    baseline_data = load_json_or_default(BASELINE_FILE, {"entries": [], "promoted_at": None})
    baseline_entries = baseline_data.get("entries", [])

    is_first_run = baseline_data.get("promoted_at") is None

    added, removed, unchanged_count = compute_diff(baseline_entries, today_entries)
    is_anomaly, anomaly_reason = check_anomaly(len(baseline_entries), len(added))

    run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    diff_summary = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "is_first_run": is_first_run,
        "baseline_count": len(baseline_entries),
        "today_count": len(today_entries),
        "added_count": len(added),
        "removed_count": len(removed),
        "unchanged_count": unchanged_count,
        "is_anomaly": is_anomaly,
        "anomaly_reason": anomaly_reason,
        "added_entries": added,
        "removed_entries": removed,
    }

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DIFF_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(diff_summary, f, ensure_ascii=False, indent=2)

    log_daily_observation(diff_summary)

    print(f"run_id={run_id} added={len(added)} removed={len(removed)} unchanged={unchanged_count} anomaly={is_anomaly}")

    if promote:
        promote_baseline(today_entries)
        print("baseline manually promoted (demo/testing use only)")

    return diff_summary


if __name__ == "__main__":
    run(promote="--promote" in sys.argv)
