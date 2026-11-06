"""Severity-based routing to Slack, Microsoft Teams, PagerDuty and email.

Each channel is optional: if its webhook/key isn't configured it is skipped silently.
Approvals happen in the dashboard (links are included in every message).
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import httpx

from ..config import Settings

log = logging.getLogger(__name__)

SEV_COLOR = {"P1": "#B42318", "P2": "#D9480F", "P3": "#B7791F", "P4": "#2F6FEB", "OK": "#2E7D32"}


class Notifier:
    def __init__(self, settings: Settings, http: httpx.Client | None = None):
        self.cfg = settings.section("notifications")
        self.routes = self.cfg.get("routes", {})
        self.dashboard = (self.cfg.get("dashboard_url") or "").rstrip("/")
        self.http = http or httpx.Client(timeout=10)

    # ---- public --------------------------------------------------------------------------
    def incident_opened(self, inc) -> None:
        title = f"[{inc.severity}] {inc.title}"
        latest = (inc.context or {}).get("latest", {})
        body = f"Target: {inc.target} ({inc.engine})\nRule: {inc.rule_id}\nValue: {latest.get('value')}"
        self._send(inc.severity, title, body, self._link(inc.id), dedup=f"incident-{inc.id}", event="trigger")

    def incident_rca(self, inc, n_actions: int) -> None:
        rca = inc.rca or {}
        title = f"[{inc.severity}] RCA: {inc.title}"
        body = (f"Target: {inc.target}\nSummary: {rca.get('summary')}\nRoot cause: {rca.get('root_cause')}\n"
                f"Confidence: {rca.get('confidence')}\nProposed actions awaiting approval: {n_actions}")
        # RCA updates go to chat channels only; the page was already sent when the incident opened.
        self._send(inc.severity, title, body, self._link(inc.id), channels=["slack", "teams"])

    def incident_resolved(self, inc) -> None:
        self._send(inc.severity, f"[RESOLVED] {inc.title}", f"Target: {inc.target}", self._link(inc.id),
                   dedup=f"incident-{inc.id}", event="resolve", color="OK")

    def message(self, title: str, body: str, severity: str = "P4") -> None:
        self._send(severity, title, body, self.dashboard or None, channels=["slack", "teams", "email"])

    # ---- internals -----------------------------------------------------------------------
    def _link(self, incident_id: int) -> str | None:
        return f"{self.dashboard}/#incident-{incident_id}" if self.dashboard else None

    def _send(self, severity: str, title: str, body: str, link: str | None, *, channels: list[str] | None = None,
              dedup: str | None = None, event: str = "trigger", color: str | None = None) -> None:
        route = channels if channels is not None else self.routes.get(severity, ["slack"])
        for ch in route:
            try:
                fn = getattr(self, f"_{ch}")
                fn(severity, title, body, link, dedup=dedup, event=event, color=SEV_COLOR.get(color or severity))
            except Exception as e:  # noqa: BLE001 - one channel failing must not block the others
                log.warning("notification via %s failed: %s", ch, e)

    def _slack(self, severity, title, body, link, *, color, **_):
        url = (self.cfg.get("slack") or {}).get("webhook_url")
        if not url:
            return
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*\n{body}"}}]
        if link:
            blocks.append({"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "Open in dashboard"}, "url": link}]})
        self.http.post(url, json={"text": title, "attachments": [{"color": color, "blocks": blocks}]}).raise_for_status()

    def _teams(self, severity, title, body, link, **_):
        url = (self.cfg.get("teams") or {}).get("webhook_url")
        if not url:
            return
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.4", "body": [
                    {"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
                    {"type": "TextBlock", "text": body.replace("\n", "\n\n"), "wrap": True}]}
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in dashboard", "url": link}]
        payload = {"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
        self.http.post(url, json=payload).raise_for_status()

    def _pagerduty(self, severity, title, body, link, *, dedup, event, **_):
        key = (self.cfg.get("pagerduty") or {}).get("routing_key")
        if not key:
            return
        payload = {"routing_key": key, "event_action": event, "dedup_key": dedup or title}
        if event == "trigger":
            payload["payload"] = {"summary": title[:1024], "source": "sql-monitor-agent",
                                  "severity": "critical" if severity == "P1" else "error",
                                  "custom_details": {"details": body}}
            if link:
                payload["links"] = [{"href": link, "text": "Dashboard"}]
        self.http.post("https://events.pagerduty.com/v2/enqueue", json=payload).raise_for_status()

    def _email(self, severity, title, body, link, *, event, **_):
        e = self.cfg.get("email") or {}
        if not e.get("smtp_host") or not e.get("to_addrs") or not e.get("from_addr"):
            return
        msg = EmailMessage()
        msg["Subject"], msg["From"] = title, e["from_addr"]
        msg["To"] = ", ".join(a.strip() for a in str(e["to_addrs"]).split(",") if a.strip())
        msg.set_content(body + (f"\n\n{link}" if link else ""))
        with smtplib.SMTP(e["smtp_host"], int(e.get("smtp_port") or 587), timeout=15) as smtp:
            smtp.starttls()
            if e.get("smtp_user"):
                smtp.login(e["smtp_user"], e.get("smtp_password", ""))
            smtp.send_message(msg)
