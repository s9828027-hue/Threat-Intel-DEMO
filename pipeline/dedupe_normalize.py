"""
ThreatGate - Dedupe & Normalize Module
去重與正規化模組

Input:  data/threat_intel_raw.json   (fetch_sources.py output, may contain
                                       cross-source duplicates)
Output: data/threat_intel_normalized.json  (deduped, validated "confirmed" list)
        data/threat_intel_observation.json (lower-confidence "observation" list)

Processing:
1. Cross-source dedupe: the same indicator reported by multiple sources is
   merged into one entry, keeping every source it was seen from.
2. Exclude private/reserved ranges so the pipeline never tries to block
   RFC1918 space, loopback, link-local, etc.
3. Flag (but don't drop) very large CIDR blocks for manual review - upstream
   sources already do their own filtering, this is just a "look twice" flag.
4. Exclude the organization's own public ranges (ORG_OWN_RANGES) so the
   pipeline can never accidentally block the organization's own traffic.

   In this public/demo build, ORG_OWN_RANGES defaults to the IANA-reserved
   "documentation" ranges (RFC 5737 / RFC 3849) - safe placeholder values.
   A real deployment sets ORG_OWN_RANGES_JSON to its own real public ranges.
"""

import ipaddress
import json
import os
from collections import defaultdict

DATA_DIR = os.environ.get("THREATGATE_DATA_DIR", "data")
INPUT_FILE = os.path.join(DATA_DIR, "threat_intel_raw.json")
OUTPUT_FILE = os.path.join(DATA_DIR, "threat_intel_normalized.json")
OBSERVATION_FILE = os.path.join(DATA_DIR, "threat_intel_observation.json")

# Documentation-only example ranges (RFC 5737 / RFC 3849) - NOT real infrastructure.
# Override with your own organization's real public ranges via ORG_OWN_RANGES_JSON,
# e.g. ORG_OWN_RANGES_JSON='["203.0.113.0/24", "198.51.100.128/25"]'
_DEFAULT_ORG_OWN_RANGES = [
    "192.0.2.0/24",     # TEST-NET-1 (example only)
    "198.51.100.0/24",  # TEST-NET-2 (example only)
    "203.0.113.0/24",   # TEST-NET-3 (example only)
]
try:
    ORG_OWN_RANGES = json.loads(os.environ.get("ORG_OWN_RANGES_JSON", "")) or _DEFAULT_ORG_OWN_RANGES
except json.JSONDecodeError:
    ORG_OWN_RANGES = _DEFAULT_ORG_OWN_RANGES

# CIDR prefixes shorter than this (i.e. larger networks) get flagged for manual review
LARGE_NETWORK_PREFIX_THRESHOLD = 16


def is_private_or_reserved(ip_or_network_str: str) -> bool:
    """RFC1918 private space, loopback, link-local, etc."""
    try:
        net = ipaddress.ip_network(ip_or_network_str, strict=False)
    except ValueError:
        return False
    return net.is_private or net.is_reserved or net.is_loopback or net.is_link_local


def is_org_own_range(ip_or_network_str: str) -> bool:
    """Whether the indicator overlaps one of the organization's own public ranges."""
    if not ORG_OWN_RANGES:
        return False
    try:
        target = ipaddress.ip_network(ip_or_network_str, strict=False)
    except ValueError:
        return False
    for own_range in ORG_OWN_RANGES:
        own_net = ipaddress.ip_network(own_range, strict=False)
        if target.subnet_of(own_net) or target.supernet_of(own_net) or target == own_net:
            return True
    return False


def is_large_network(cidr_str: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False
    return net.prefixlen < LARGE_NETWORK_PREFIX_THRESHOLD


def normalize(raw_entries):
    merged = {}
    excluded = []
    large_network_flags = []

    for entry in raw_entries:
        ind_type = entry.get("type")
        indicator = entry.get("indicator", "").strip()
        source = entry.get("source", "unknown")

        if not indicator:
            continue

        if ind_type in ("ip", "cidr"):
            if is_private_or_reserved(indicator):
                excluded.append({**entry, "exclude_reason": "private/reserved range"})
                continue
            if is_org_own_range(indicator):
                excluded.append({**entry, "exclude_reason": "organization's own range"})
                continue

        flagged_large = ind_type == "cidr" and is_large_network(indicator)

        key = (ind_type, indicator)
        entry_tier = entry.get("confidence_tier", "confirmed")
        if key not in merged:
            merged[key] = {
                "indicator": indicator,
                "type": ind_type,
                "sources": [source],
                "categories": [entry.get("category")] if entry.get("category") else [],
                "first_seen": entry.get("first_seen"),
                "large_network": flagged_large,
                "confidence_tier": entry_tier,
            }
            if flagged_large:
                large_network_flags.append(indicator)
        else:
            existing = merged[key]
            if source not in existing["sources"]:
                existing["sources"].append(source)
            cat = entry.get("category")
            if cat and cat not in existing["categories"]:
                existing["categories"].append(cat)
            fs = entry.get("first_seen")
            if fs and (not existing["first_seen"] or fs < existing["first_seen"]):
                existing["first_seen"] = fs
            # cross-source confirmation upgrades confidence, never downgrades it
            if entry_tier == "confirmed":
                existing["confidence_tier"] = "confirmed"

    normalized_list = list(merged.values())
    # entries confirmed by more sources sort first - easier to triage during review
    normalized_list.sort(key=lambda x: len(x["sources"]), reverse=True)

    confirmed_list = [x for x in normalized_list if x["confidence_tier"] == "confirmed"]
    observation_list = [x for x in normalized_list if x["confidence_tier"] == "observation"]

    return confirmed_list, observation_list, excluded, large_network_flags


def run(input_file: str = None, output_file: str = None, observation_file: str = None) -> dict:
    input_file = input_file or INPUT_FILE
    output_file = output_file or OUTPUT_FILE
    observation_file = observation_file or OBSERVATION_FILE

    with open(input_file, "r", encoding="utf-8") as f:
        raw = json.load(f)

    raw_entries = raw.get("entries", [])
    confirmed_list, observation_list, excluded, large_network_flags = normalize(raw_entries)

    multi_source_count = sum(1 for x in confirmed_list if len(x["sources"]) > 1)
    total_after_dedupe = len(confirmed_list) + len(observation_list)

    confirmed_output = {
        "normalized_at": raw.get("fetched_at"),
        "total_before_dedupe": len(raw_entries),
        "total_after_dedupe": total_after_dedupe,
        "confirmed_count": len(confirmed_list),
        "observation_count": len(observation_list),
        "duplicates_merged": len(raw_entries) - total_after_dedupe - len(excluded),
        "excluded_count": len(excluded),
        "multi_source_count": multi_source_count,
        "large_network_flagged_count": len(large_network_flags),
        "entries": confirmed_list,
        "excluded_entries": excluded,
    }
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(confirmed_output, f, ensure_ascii=False, indent=2)

    observation_output = {
        "normalized_at": raw.get("fetched_at"),
        "total": len(observation_list),
        "note": "Observation only - does not enter the approval / publish flow.",
        "entries": observation_list,
    }
    with open(observation_file, "w", encoding="utf-8") as f:
        json.dump(observation_output, f, ensure_ascii=False, indent=2)

    print(f"After dedupe: {len(confirmed_list)} confirmed / {len(observation_list)} observation")
    print(f"Excluded (private/org-own): {len(excluded)}")

    return confirmed_output


if __name__ == "__main__":
    run()
