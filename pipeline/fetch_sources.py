"""
ThreatGate - Source Ingestion Module
威脅情資蒐集模組

Pulls indicators of compromise (IOCs) from several public threat-intelligence
feeds and normalizes them into one common shape for downstream processing.

從多個公開威脅情資來源擷取入侵指標(IOC),正規化成統一格式,供後續模組使用。

Sources / 來源:
- Feodo Tracker  (abuse.ch)   - no auth required   / 免金鑰
- Spamhaus DROP                - no auth required   / 免金鑰
- ThreatFox      (abuse.ch)   - requires ABUSECH_AUTH_KEY (free)  / 需免費金鑰
- URLhaus        (abuse.ch)   - requires ABUSECH_AUTH_KEY (free)  / 需免費金鑰
- AlienVault OTX               - requires OTX_API_KEY (free)      / 需免費金鑰

Any source whose key is missing is skipped gracefully rather than failing
the whole run - the pipeline is designed to degrade, not crash.
任何一個來源缺金鑰或失敗都只會被跳過,不會讓整支排程中斷。
"""

import ipaddress
import json
import os
from datetime import datetime, timezone

import requests

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
SPAMHAUS_URL = "https://www.spamhaus.org/drop/drop.txt"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
OTX_SUBSCRIBED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# ThreatFox confidence threshold: at/above this is "confirmed", below is "observation"
THREATFOX_CONFIDENCE_THRESHOLD = 75

TIMEOUT = 15  # seconds, so one dead source can't hang the whole run

# secrets come from environment only - never hardcoded
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY")
OTX_API_KEY = os.environ.get("OTX_API_KEY")

RAW_OUTPUT_FILE = os.path.join(os.environ.get("THREATGATE_DATA_DIR", "data"), "threat_intel_raw.json")


def fetch_feodo_tracker():
    """Feodo Tracker: plain IP list, one IOC per line, '#' = comment."""
    results = []
    resp = requests.get(FEODO_URL, timeout=TIMEOUT)
    resp.raise_for_status()

    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            continue
        results.append({
            "indicator": line,
            "type": "ip",
            "source": "Feodo Tracker",
            "category": "Botnet C2",
            "confidence_tier": "confirmed",
        })
    return results


def fetch_spamhaus_drop():
    """Spamhaus DROP: CIDR list, format 'CIDR ; SBLxxxxx', ';' = comment."""
    results = []
    resp = requests.get(SPAMHAUS_URL, timeout=TIMEOUT)
    resp.raise_for_status()

    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        cidr_part = line.split(";")[0].strip()
        try:
            ipaddress.ip_network(cidr_part, strict=False)
        except ValueError:
            continue
        results.append({
            "indicator": cidr_part,
            "type": "cidr",
            "source": "Spamhaus DROP",
            "category": "Malicious network",
            "confidence_tier": "confirmed",
        })
    return results


def fetch_threatfox():
    """ThreatFox: last 24h of IOCs, IP:port type only (this pipeline blocks at IP layer)."""
    if not ABUSECH_AUTH_KEY:
        raise RuntimeError("ABUSECH_AUTH_KEY not set - skipping ThreatFox")

    results = []
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    payload = {"query": "get_iocs", "days": 1}

    resp = requests.post(THREATFOX_URL, headers=headers, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    if data.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox returned status: {data.get('query_status')}")

    for item in data.get("data", []):
        if item.get("ioc_type") != "ip:port":
            continue
        ip_part = item.get("ioc", "").split(":")[0]
        try:
            ipaddress.ip_address(ip_part)
        except ValueError:
            continue
        confidence = item.get("confidence_level", 0)
        tier = "confirmed" if confidence >= THREATFOX_CONFIDENCE_THRESHOLD else "observation"
        results.append({
            "indicator": ip_part,
            "type": "ip",
            "source": "ThreatFox",
            "category": item.get("threat_type", "unknown"),
            "malware": item.get("malware_printable", item.get("malware", "")),
            "first_seen": item.get("first_seen"),
            "confidence_level": confidence,
            "confidence_tier": tier,
        })
    return results


def fetch_urlhaus():
    """URLhaus: recent malicious URLs. IP hosts feed the firewall list; domains are
    collected but not auto-blocked (that needs DNS/proxy-layer enforcement, out of scope here)."""
    if not ABUSECH_AUTH_KEY:
        raise RuntimeError("ABUSECH_AUTH_KEY not set - skipping URLhaus")

    results = []
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}

    resp = requests.get(URLHAUS_RECENT_URL, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    if data.get("query_status") != "ok":
        raise RuntimeError(f"URLhaus returned status: {data.get('query_status')}")

    for item in data.get("urls", []):
        host = item.get("host", "").strip()
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            host_type = "ip"
        except ValueError:
            host_type = "domain"
        url_status = item.get("url_status")
        tier = "confirmed" if url_status == "online" else "observation"
        results.append({
            "indicator": host,
            "type": host_type,
            "source": "URLhaus",
            "category": item.get("threat", "unknown"),
            "url_status": url_status,
            "first_seen": item.get("date_added"),
            "confidence_tier": tier,
        })
    return results


def fetch_otx():
    """AlienVault OTX: indicators from subscribed pulses, IPv4/IPv6 only."""
    if not OTX_API_KEY:
        raise RuntimeError("OTX_API_KEY not set - skipping AlienVault OTX")

    results = []
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = OTX_SUBSCRIBED_URL
    page_count = 0
    max_pages = 5  # cap pagination so a huge subscription list can't stall the run

    while url and page_count < max_pages:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        for pulse in data.get("results", []):
            pulse_name = pulse.get("name", "unknown pulse")
            for ind in pulse.get("indicators", []):
                ind_type = ind.get("type")
                if ind_type not in ("IPv4", "IPv6"):
                    continue
                value = ind.get("indicator", "").strip()
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                results.append({
                    "indicator": value,
                    "type": "ip",
                    "source": "AlienVault OTX",
                    "category": pulse_name,
                    "first_seen": ind.get("created"),
                    "confidence_tier": "confirmed",
                })

        url = data.get("next")
        page_count += 1

    return results


def run(output_file: str = None) -> dict:
    """Run every source fetcher, merge results, write the raw output file, return the summary dict.

    Each fetcher is called as a bare module-level name (not a pre-bound
    reference captured in a table) so that tests can transparently
    patch.object(module, 'fetch_x', ...) per source.
    """
    output_file = output_file or RAW_OUTPUT_FILE
    all_entries = []
    source_status = {}

    for name, fetcher_name in [
        ("Feodo Tracker", "fetch_feodo_tracker"),
        ("Spamhaus DROP", "fetch_spamhaus_drop"),
        ("ThreatFox", "fetch_threatfox"),
        ("URLhaus", "fetch_urlhaus"),
        ("AlienVault OTX", "fetch_otx"),
    ]:
        try:
            entries = globals()[fetcher_name]()
            all_entries.extend(entries)
            source_status[name] = {"ok": True, "count": len(entries)}
            print(f"[{name}] fetched {len(entries)} entries")
        except Exception as e:
            source_status[name] = {"ok": False, "error": str(e)}
            print(f"[{name}] skipped: {e}")

    total_ip = sum(1 for x in all_entries if x["type"] == "ip")
    total_domain = sum(1 for x in all_entries if x["type"] == "domain")
    total_cidr = sum(1 for x in all_entries if x["type"] == "cidr")
    total_confirmed = sum(1 for x in all_entries if x.get("confidence_tier") == "confirmed")
    total_observation = sum(1 for x in all_entries if x.get("confidence_tier") == "observation")

    output = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total": len(all_entries),
        "total_ip": total_ip,
        "total_cidr": total_cidr,
        "total_domain": total_domain,
        "total_confirmed": total_confirmed,
        "total_observation": total_observation,
        "source_status": source_status,
        "entries": all_entries,
    }

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\nTotal fetched: {len(all_entries)} -> {output_file}")
    return output


if __name__ == "__main__":
    run()
