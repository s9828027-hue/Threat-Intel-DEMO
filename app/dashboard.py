"""
Web dashboard: replaces "you have to be in the right Google Chat space to see
anything" with a page anyone with the link can open. Shows recent pipeline
runs and their approval status, and offers a manual "run now" button so a
visitor doesn't have to wait for the schedule to demo the flow.
"""

import threading
import time

from flask import Blueprint, redirect, render_template, url_for

from app.approval import ESCALATION_THRESHOLD, load_state
from app.publisher import is_demo_mode

bp = Blueprint("dashboard", __name__)

_run_lock = threading.Lock()
_last_run_started_at = {"ts": None}


def _run_in_background():
    from app.pipeline_runner import run_pipeline
    if not _run_lock.acquire(blocking=False):
        return
    try:
        _last_run_started_at["ts"] = time.time()
        run_pipeline()
    finally:
        _run_lock.release()


@bp.route("/")
def home():
    state = load_state()

    def _sort_key(entry):
        history = entry.get("history") or []
        if history:
            return history[-1].get("at", 0)
        # no decision yet - fall back to when the run was recorded
        return entry.get("created_at", 0)

    runs = sorted(state.values(), key=_sort_key, reverse=True)
    return render_template(
        "dashboard.html",
        runs=runs,
        escalation_threshold=ESCALATION_THRESHOLD,
        demo_mode=is_demo_mode(),
        run_in_progress=_run_lock.locked(),
    )


@bp.route("/run-now", methods=["POST"])
def run_now():
    threading.Thread(target=_run_in_background, daemon=True).start()
    return redirect(url_for("dashboard.home"))
