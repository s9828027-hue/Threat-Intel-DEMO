"""
Orchestrates one full pipeline run: fetch -> dedupe/normalize -> diff -> excel
report -> approval tokens -> chat notification. Called both by the scheduler
(app/scheduler.py) and by the dashboard's manual "Run now" button.
"""

import os
import traceback

from app.approval import APPROVAL_API_BASE_URL, ESCALATION_THRESHOLD, generate_tokens_for_run, record_new_run
from app.notify import format_run_summary, send_chat_message
from pipeline import dedupe_normalize, diff_summary, export_excel, fetch_sources


def run_pipeline() -> dict:
    """Returns a small result dict; never raises - callers (scheduler, HTTP
    endpoint) both want a status back rather than a crashed process."""
    try:
        fetch_sources.run()
        dedupe_normalize.run()
        diff = diff_summary.run()

        try:
            export_excel.run()
        except Exception:
            # nice-to-have, must never block the actual approval flow
            print("[pipeline] excel export failed:\n" + traceback.format_exc())

        run_id = diff["run_id"]
        added_count = diff["added_count"]

        tokens = generate_tokens_for_run(run_id, added_count)
        record_new_run(run_id, diff, tokens)

        approve_url = f"{APPROVAL_API_BASE_URL}/approve/{tokens['approve']}"
        reject_url = f"{APPROVAL_API_BASE_URL}/reject/{tokens['reject']}"

        message = format_run_summary(diff, approve_url, reject_url, ESCALATION_THRESHOLD)
        send_chat_message(message)

        return {"ok": True, "run_id": run_id, "diff": diff}
    except Exception as e:
        print("[pipeline] run failed:\n" + traceback.format_exc())
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    result = run_pipeline()
    print(result)
