"""
Runs the pipeline on a schedule (default: every hour) using APScheduler's
in-process background scheduler. Fine for a single-instance deployment like
the free tier this demo targets; a multi-instance production deployment
would move this to an external cron/queue instead.
"""

import os

from apscheduler.schedulers.background import BackgroundScheduler

_scheduler = None


def start_scheduler(app):
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    interval_minutes = int(os.environ.get("PIPELINE_INTERVAL_MINUTES", "60"))
    if interval_minutes <= 0:
        print("[scheduler] PIPELINE_INTERVAL_MINUTES <= 0, scheduler disabled (manual runs only)")
        return None

    def job():
        with app.app_context():
            from app.pipeline_runner import run_pipeline
            run_pipeline()

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(job, "interval", minutes=interval_minutes, id="threatgate-pipeline",
                        next_run_time=None)  # first run is manual/on-demand, not at boot
    _scheduler.start()
    print(f"[scheduler] started - pipeline runs every {interval_minutes} minute(s)")
    return _scheduler
