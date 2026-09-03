"""
ThreatGate - SCM Publish Adapter (real)
EDL 內容發布與 SCM 物件寫入模組(正式環境版)

This is the production adapter: it writes the approved list to a local file
served over HTTP (for the firewall's EDL object to poll), then calls the SCM
API to make sure the EDL object exists and points at that URL.

Only used when THREATGATE_DEMO_MODE is not "true" - see adapters/mock_scm.py
for the adapter the public demo deployment actually runs against.

Note: Palo Alto's EDL create/update payload shape below is a best-effort
reconstruction from public docs and testing against a real tenant - if you
adapt this, be ready to adjust field names from the API's error responses.
"""

import ipaddress
import json
import os

import requests

from adapters.scm_client import get_auth_header

SCM_API_BASE = "https://api.strata.paloaltonetworks.com/config/objects/v1"
EDL_ENDPOINT = f"{SCM_API_BASE}/external-dynamic-lists"

EDL_NAME = os.environ.get("EDL_NAME", "ThreatGate-Blocklist")
EDL_FOLDER = os.environ.get("SCM_FOLDER", "Shared")
# Must be reachable BY the firewall/SCM, not by you - change for your deployment.
EDL_SOURCE_URL = os.environ.get("EDL_SOURCE_URL", "http://CHANGE-ME:5000/edl/blocklist.txt")

DATA_DIR = os.environ.get("THREATGATE_DATA_DIR", "data")
NORMALIZED_FILE = os.path.join(DATA_DIR, "threat_intel_normalized.json")
PUBLISHED_FILE = os.path.join(DATA_DIR, "edl_blocklist.txt")

TIMEOUT = 20


def build_publish_content():
    """Only ip/cidr confirmed entries go out - domains aren't blocked at this layer."""
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
    """Write to the local file, then read it back to verify the write really happened."""
    content, count = build_publish_content()

    os.makedirs(os.path.dirname(PUBLISHED_FILE) or ".", exist_ok=True)
    with open(PUBLISHED_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    with open(PUBLISHED_FILE, "r", encoding="utf-8") as f:
        verify_content = f.read()

    if verify_content != content:
        raise RuntimeError("Post-publish verification failed: written content doesn't match")

    print(f"Published {count} entries to {PUBLISHED_FILE}")
    return count


def find_existing_edl():
    headers = get_auth_header()
    params = {"folder": EDL_FOLDER, "name": EDL_NAME}
    resp = requests.get(EDL_ENDPOINT, headers=headers, params=params, timeout=TIMEOUT)

    if resp.status_code == 404:
        return None

    resp.raise_for_status()
    data = resp.json()

    if isinstance(data, dict) and data.get("name") == EDL_NAME:
        return data.get("id")

    items = data if isinstance(data, list) else data.get("data", []) if isinstance(data, dict) else []
    for item in items:
        if item.get("name") == EDL_NAME:
            return item.get("id")

    return None


def _edl_payload():
    return {
        "name": EDL_NAME,
        "folder": EDL_FOLDER,
        "type": {
            "ip": {
                "url": EDL_SOURCE_URL,
                "recurring": {"five_minute": {}},
            }
        },
    }


def create_edl():
    headers = get_auth_header()
    headers["Content-Type"] = "application/json"
    resp = requests.post(EDL_ENDPOINT, headers=headers, json=_edl_payload(), timeout=TIMEOUT)
    resp.raise_for_status()
    print(f"Created EDL object: {EDL_NAME}")
    return resp.json()


def update_edl(edl_id):
    headers = get_auth_header()
    headers["Content-Type"] = "application/json"
    resp = requests.put(f"{EDL_ENDPOINT}/{edl_id}", headers=headers, json=_edl_payload(), timeout=TIMEOUT)
    resp.raise_for_status()
    print(f"Confirmed EDL object: {EDL_NAME} (id: {edl_id})")
    return resp.json()


def ensure_edl_object():
    existing_id = find_existing_edl()
    if existing_id:
        update_edl(existing_id)
    else:
        create_edl()


if __name__ == "__main__":
    count = publish_content()
    try:
        ensure_edl_object()
        print(f"\nDone. Published {count} entries, EDL object confirmed at {EDL_SOURCE_URL}")
    except requests.HTTPError as e:
        print(f"SCM API call failed: {e}")
        print(f"Response body: {e.response.text if e.response is not None else '(none)'}")
