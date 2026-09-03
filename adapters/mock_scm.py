"""
ThreatGate - Mock Firewall Adapter (demo mode)
模擬防火牆發布模組(Demo 模式)

Same interface as adapters/scm_write.py (publish_content / ensure_edl_object)
but never calls a real firewall API. It writes the approved list to a local
file and records a simulated "EDL object" state, so the public demo can walk
through the entire approve -> publish flow end-to-end without needing a real
Palo Alto SCM tenant or credentials.

Selected automatically when THREATGATE_DEMO_MODE=true (see app/publisher.py).
"""

import ipaddress
import json
import os
import time

DATA_DIR = os.environ.get("THREATGATE_DATA_DIR", "data")
NORMALIZED_FILE = os.path.join(DATA_DIR, "threat_intel_normalized.json")
PUBLISHED_FILE = os.path.join(DATA_DIR, "edl_blocklist.txt")
MOCK_EDL_STATE_FILE = os.path.join(DATA_DIR, "mock_edl_object.json")

EDL_NAME = os.environ.get("EDL_NAME", "ThreatGate-Blocklist")
EDL_FOLDER = os.environ.get("SCM_FOLDER", "Shared")
EDL_SOURCE_URL = os.environ.get("EDL_SOURCE_URL", "http://localhost:5000/edl/blocklist.txt")


def build_publish_content():
    with open(NORMALIZED_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    lines = []
    for entry in data.get("entries", []):
        if entry.get("type") not in ("ip", "cidr"):
            continue
        indicator = entry["indicator"]
        try:
            ipaddress.ip_network(indicator, strict=False)
        except ValueError:
            continue
        lines.append(indicator)

    return "\n".join(lines), len(lines)


def publish_content():
    content, count = build_publish_content()

    os.makedirs(os.path.dirname(PUBLISHED_FILE) or ".", exist_ok=True)
    with open(PUBLISHED_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    with open(PUBLISHED_FILE, "r", encoding="utf-8") as f:
        verify_content = f.read()
    if verify_content != content:
        raise RuntimeError("Post-publish verification failed: written content doesn't match")

    print(f"[mock] published {count} entries to {PUBLISHED_FILE} (no real firewall was contacted)")
    return count


def ensure_edl_object():
    """Simulates create-if-missing / confirm-if-exists against a fake EDL object store."""
    state = {
        "name": EDL_NAME,
        "folder": EDL_FOLDER,
        "url": EDL_SOURCE_URL,
        "recurring": "five_minute",
        "last_confirmed_at": time.time(),
        "note": "This is a simulated object - no real firewall/SCM API was called.",
    }
    os.makedirs(os.path.dirname(MOCK_EDL_STATE_FILE) or ".", exist_ok=True)
    existed = os.path.exists(MOCK_EDL_STATE_FILE)
    with open(MOCK_EDL_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    print(f"[mock] {'confirmed' if existed else 'created'} EDL object: {EDL_NAME}")
    return state


if __name__ == "__main__":
    count = publish_content()
    ensure_edl_object()
    print(f"\n[mock] done - {count} entries, EDL object simulated at {EDL_SOURCE_URL}")
