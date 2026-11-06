"""Command line entry point: `monitor <command>`."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time


def _app(args):
    from .app import App
    return App(settings_path=args.config)


def cmd_init_db(args):
    _app(args)
    print("State store initialised.")


def cmd_check(args):
    app = _app(args)
    for name, a in app.registry.items():
        print(f"{name:24} {a.engine:10} {json.dumps(a.health())}")


def cmd_collect_once(args):
    app = _app(args)
    names = [args.target] if args.target else app.registry.names()
    for n in names:
        events = app.collect(n, both=True)
        print(f"{n}: {len(events)} rule breaches" + "".join(f"\n  - [{e.rule.severity}] {e.rule.id}: {e.detail}"
                                                       for e in events))
    if args.wait:
        print("Waiting for investigations to finish...")
        app._pool.shutdown(wait=True)


def cmd_run(args):
    from .collector import build_scheduler
    app = _app(args)
    sched = build_scheduler(app)
    sched.start()
    print("Collectors running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        sched.shutdown(wait=False)
        app.shutdown()


def cmd_serve(args):
    import uvicorn
    from .api.main import create_api
    from .collector import build_scheduler
    app = _app(args)
    sched = None
    if not args.no_collect:
        sched = build_scheduler(app)
        sched.start()
    try:
        uvicorn.run(create_api(app), host=args.host, port=args.port, log_level="info")
    finally:
        if sched:
            sched.shutdown(wait=False)
        app.shutdown()


def cmd_investigate(args):
    app = _app(args)
    rca = app.investigator.investigate(args.incident_id)
    print(json.dumps(rca.model_dump() if rca else {"error": "investigation failed; see incident rca_error"}, indent=2))


def cmd_ask(args):
    print(_app(args).investigator.chat(args.question))


def cmd_governance(args):
    app = _app(args)
    gov = app.governance
    if args.gov_cmd == "scan":
        cfg = (app.settings.governance or {}).get("snowflake_inactive_users", {})
        for t in ([args.target] if args.target else cfg.get("targets", [])):
            det = gov.detect(t)
            print(f"{t}: {len(det['candidates'])} inactive of {det['total_users']} users")
            for c in det["candidates"]:
                print(f"  FLAG  {c['name']:32} {c['reason']}")
            for sk in det["skipped"]:
                print(f"  skip  {sk['name']:32} {sk['reason']}")
    elif args.gov_cmd == "run":
        print(json.dumps(app.run_governance(actor=args.actor), indent=2, default=str))
    elif args.gov_cmd == "approve":
        print(gov.approve(args.case_id, args.actor))
    elif args.gov_cmd == "keep":
        gov.keep(args.case_id, args.actor, args.note or "")
        print("kept")
    elif args.gov_cmd == "restore":
        print("\n".join(gov.restore(args.case_id, args.actor)))


def cmd_actions(args):
    app = _app(args)
    from sqlalchemy import select
    from .store import ActionRecord, session_scope
    if args.act_cmd == "list":
        with session_scope() as s:
            for a in s.scalars(select(ActionRecord).where(ActionRecord.status == "proposed")):
                print(f"#{a.id} [{a.target}] {a.action_type} risk={a.risk}\n    {a.rendered_sql}\n    {a.rationale[:200]}")
    elif args.act_cmd == "approve":
        rec = app.executor.approve_and_execute(args.action_id, args.actor)
        print(rec.status, json.dumps(rec.result, default=str))
    elif args.act_cmd == "reject":
        app.executor.reject(args.action_id, args.actor, args.note or "")
        print("rejected")


def main(argv=None):
    p = argparse.ArgumentParser(prog="monitor", description="SQL & Snowflake monitoring agent")
    p.add_argument("--config", default="config/settings.yaml")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init-db").set_defaults(fn=cmd_init_db)
    sub.add_parser("check", help="test connectivity to every enabled target").set_defaults(fn=cmd_check)
    c = sub.add_parser("collect-once", help="collect + evaluate rules once")
    c.add_argument("--target")
    c.add_argument("--wait", action="store_true", help="wait for AI investigations to finish")
    c.set_defaults(fn=cmd_collect_once)
    sub.add_parser("run", help="run collectors on a schedule (no API)").set_defaults(fn=cmd_run)
    s = sub.add_parser("serve", help="collectors + API + dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--no-collect", action="store_true")
    s.set_defaults(fn=cmd_serve)
    i = sub.add_parser("investigate", help="run the AI investigation for an incident")
    i.add_argument("incident_id", type=int)
    i.set_defaults(fn=cmd_investigate)
    a = sub.add_parser("ask", help="ask the agent a question")
    a.add_argument("question")
    a.set_defaults(fn=cmd_ask)

    g = sub.add_parser("governance", help="Snowflake inactive-user cleanup")
    g.add_argument("gov_cmd", choices=["scan", "run", "approve", "keep", "restore"])
    g.add_argument("case_id", type=int, nargs="?")
    g.add_argument("--target")
    g.add_argument("--actor", default="cli")
    g.add_argument("--note")
    g.set_defaults(fn=cmd_governance)

    ac = sub.add_parser("actions", help="list/approve/reject proposed actions")
    ac.add_argument("act_cmd", choices=["list", "approve", "reject"])
    ac.add_argument("action_id", type=int, nargs="?")
    ac.add_argument("--actor", default="cli")
    ac.add_argument("--note")
    ac.set_defaults(fn=cmd_actions)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.cmd in ("governance", "actions") and getattr(args, "gov_cmd", getattr(args, "act_cmd", None)) not in (
            "scan", "run", "list") and getattr(args, "case_id", getattr(args, "action_id", None)) is None:
        p.error("this command needs an id")
    args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
