"""
Optional Google Chat notifications. Every call degrades gracefully when no
webhook is configured - the dashboard (app/dashboard.py) is always the
source of truth, chat is just a convenience ping on top of it.
"""

import os

import requests

WEBHOOK_URL = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL")
SUPERVISOR_WEBHOOK_URL = os.environ.get("GOOGLE_CHAT_SUPERVISOR_WEBHOOK_URL", WEBHOOK_URL)
TIMEOUT = 15


def send_chat_message(text: str, to_supervisor: bool = False):
    url = SUPERVISOR_WEBHOOK_URL if to_supervisor else WEBHOOK_URL
    if not url:
        print("[notify] no webhook configured, skipping chat notification")
        return
    try:
        requests.post(url, json={"text": text}, timeout=TIMEOUT)
    except Exception as e:
        print(f"[notify] failed to send chat message: {e}")


def format_run_summary(diff: dict, approve_url: str, reject_url: str, escalation_threshold: int) -> str:
    lines = []

    if diff.get("is_anomaly"):
        lines.append(f"⚠️ *Anomaly*: {diff['anomaly_reason']}")
        lines.append("")

    if diff.get("is_first_run"):
        lines.append("\U0001F195 *First run* - everything below is new")
        lines.append("")

    lines.append("*Daily threat-intel review*")
    lines.append(f"Baseline: {diff['baseline_count']} -> Today: {diff['today_count']}")
    lines.append(f"Added: {diff['added_count']} / Removed: {diff['removed_count']} / Unchanged: {diff['unchanged_count']}")
    lines.append("")

    added_count = diff.get("added_count", 0)
    if added_count > escalation_threshold:
        lines.append(f"⚠️ Added count exceeds {escalation_threshold} - will require supervisor approval")
        lines.append("")

    lines.append(f"<{approve_url}|✅ Approve>　<{reject_url}|❌ Reject>")

    return "\n".join(lines)
