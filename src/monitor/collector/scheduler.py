from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from ..app import App

log = logging.getLogger(__name__)


def build_scheduler(app: App) -> BackgroundScheduler:
    cfg = app.settings.section("scheduler")
    fast = int(cfg.get("fast_interval_seconds", 60))
    slow = int(cfg.get("slow_interval_seconds", 600))
    sched = BackgroundScheduler(job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 30})
    app.scheduler = sched

    for name in app.registry.names():
        schedule_target(app, name)
        # One full (fast + slow) collection right away, so a restart doesn't leave slow checks empty for 10 minutes.
        sched.add_job(app.collect, args=[name, False, True], id=f"first:{name}", replace_existing=True)

    sched.add_job(app.run_governance, "cron", hour=int(cfg.get("governance_cron_hour", 6)), minute=0,
                  id="governance")
    sched.add_job(app.prune_metrics, "cron", hour=3, minute=30, id="prune")
    log.info("scheduled %d targets (fast=%ss slow=%ss)", len(app.registry.names()), fast, slow)
    return sched


def schedule_target(app: App, name: str) -> None:
    cfg = app.settings.section("scheduler")
    sched = app.scheduler
    fast = int(cfg.get("fast_interval_seconds", 60))
    slow = int(cfg.get("slow_interval_seconds", 600))
    sched.add_job(app.collect, "interval", seconds=fast, args=[name, False], id=f"fast:{name}", jitter=5,
                  replace_existing=True)
    sched.add_job(app.collect, "interval", seconds=slow, args=[name, True], id=f"slow:{name}", jitter=15,
                  replace_existing=True)


def unschedule_target(app: App, name: str) -> None:
    for job_id in (f"fast:{name}", f"slow:{name}"):
        try:
            app.scheduler.remove_job(job_id)
        except Exception:  # noqa: BLE001 - job may not exist
            pass
