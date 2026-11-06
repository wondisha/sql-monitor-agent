"""Snowflake inactive-user lifecycle.

  detect  -> flagged         (daily; report to owners)
  approve -> snapshot grants + ALTER USER ... SET DISABLED = TRUE   -> disabled
  grace period passes and nobody re-enabled the user:
          -> REVOKE every role, unset keys, DROP USER                -> dropped (+ orphaned-role report)
  keep    -> excluded for keep_days
  restore -> re-enable + re-grant (or re-create after drop) from the snapshot

Detection uses the read-only monitor role. SHOW USERS / SHOW GRANTS and every change use the executor role
(GOV_EXECUTOR), which needs MANAGE GRANTS and ownership of users (e.g. granted from USERADMIN/SECURITYADMIN).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy import select

from ..adapters import AdapterRegistry
from ..config import Settings
from ..store import GovernanceCase, session_scope
from ..store.db import audit, jsonable
from ..store.models import utcnow

log = logging.getLogger(__name__)

OPEN_STATES = ("flagged", "approved", "disabled")
SYSTEM_ROLES = {"PUBLIC"}


def q_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def q_str(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _dt(v) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.replace(tzinfo=None)
    try:
        return datetime.fromisoformat(str(v)).replace(tzinfo=None)
    except ValueError:
        return None


class GovernanceError(RuntimeError):
    pass


class SnowflakeUserGovernance:
    def __init__(self, settings: Settings, registry: AdapterRegistry, notify: Callable[[str, str], None] | None = None):
        self.settings = settings
        self.registry = registry
        self.cfg = (settings.governance or {}).get("snowflake_inactive_users", {}) or {}
        self.notify = notify or (lambda title, body: None)

    # ---- config helpers ------------------------------------------------------------------
    @property
    def dry_run(self) -> bool:
        return bool(self.cfg.get("dry_run", True))

    @property
    def inactive_days(self) -> int:
        return int(self.cfg.get("inactive_days", 90))

    def _self_users(self, target: str) -> set[str]:
        t = self.settings.target(target)
        return {str(t.monitor.get("user", "")).upper(), str(t.executor.get("user", "")).upper()} - {""}

    # ---- detection -----------------------------------------------------------------------
    def detect(self, target: str) -> dict:
        """Return {'total_users', 'candidates': [...], 'skipped': [...]} without changing anything."""
        a = self.registry.get(target)
        cutoff = utcnow() - timedelta(days=self.inactive_days)
        try:
            users = a.query("""SELECT name, login_name, type, default_role, created_on, last_success_login, disabled,
                                      owner, email FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE deleted_on IS NULL""",
                            max_rows=100000)
        except Exception:  # noqa: BLE001 - older accounts without the TYPE column
            users = a.query("""SELECT name, login_name, NULL AS type, default_role, created_on, last_success_login,
                                      disabled, owner, email FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE deleted_on IS NULL""",
                            max_rows=100000)
        total = len(users)

        protected_roles = {r.upper() for r in self.cfg.get("protected_roles", [])}
        protected_users = self._users_with_roles(a, self._role_closure(a, protected_roles))
        allow = {u.upper() for u in self.cfg.get("allowlist_users", [])} | self._self_users(target)
        tagged = self._tagged_keep_users(a)

        stale, skipped = [], []
        for u in users:
            name = u["name"]
            last = _dt(u.get("last_success_login")) or _dt(u.get("created_on"))
            if last is None or last >= cutoff:
                continue
            reason = None
            utype = (u.get("type") or "").upper()
            if utype in ("SERVICE", "LEGACY_SERVICE") and not self.cfg.get("include_service_users", False):
                reason = f"service user (TYPE={utype})"
            elif name.upper() in allow:
                reason = "allowlisted"
            elif name.upper() in protected_users:
                reason = "holds a protected admin role"
            elif name.upper() in tagged:
                reason = "has keep tag"
            if reason:
                skipped.append({"name": name, "reason": reason})
            else:
                stale.append(u)

        # Belt and braces: any query activity in the window means the user is not inactive.
        active = self._users_with_recent_queries(a, [u["name"] for u in stale], cutoff)
        candidates = []
        for u in stale:
            if u["name"] in active:
                skipped.append({"name": u["name"], "reason": "has query activity in the window"})
                continue
            never = u.get("last_success_login") is None
            candidates.append({
                **u,
                "reason": ("never logged in; created " if never else "last login ")
                          + str(u.get("last_success_login") or u.get("created_on"))[:19]
                          + f" (> {self.inactive_days} days)",
            })
        return {"total_users": total, "candidates": candidates, "skipped": skipped}

    def _role_closure(self, a, protected: set[str]) -> set[str]:
        """All roles that include a protected role, directly or through the role hierarchy."""
        if not protected:
            return set()
        edges = a.safe("""SELECT name AS child, grantee_name AS parent FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
                          WHERE granted_on = 'ROLE' AND privilege = 'USAGE' AND deleted_on IS NULL""", max_rows=200000)
        parents: dict[str, set[str]] = {}
        for e in edges:
            parents.setdefault(e["child"].upper(), set()).add(e["parent"].upper())
        closure, frontier = set(protected), list(protected)
        while frontier:
            role = frontier.pop()
            for p in parents.get(role, ()):
                if p not in closure:
                    closure.add(p)
                    frontier.append(p)
        return closure

    def _users_with_roles(self, a, roles: set[str]) -> set[str]:
        if not roles:
            return set()
        rows = a.safe("""SELECT grantee_name, role FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
                         WHERE deleted_on IS NULL""", max_rows=200000)
        return {r["grantee_name"].upper() for r in rows if r["role"].upper() in roles}

    def _tagged_keep_users(self, a) -> set[str]:
        tag = (self.cfg.get("keep_tag") or "").strip()
        if not tag:
            return set()
        parts = tag.upper().split(".")
        if len(parts) != 3:
            log.warning("keep_tag must be DATABASE.SCHEMA.TAG, got %s", tag)
            return set()
        rows = a.safe("""SELECT object_name FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                         WHERE domain = 'USER' AND tag_database = %s AND tag_schema = %s AND tag_name = %s
                           AND LOWER(tag_value) = 'true'""", tuple(parts), max_rows=100000)
        return {r["object_name"].upper() for r in rows}

    def _users_with_recent_queries(self, a, names: list[str], cutoff: datetime) -> set[str]:
        found: set[str] = set()
        for i in range(0, len(names), 200):
            chunk = names[i:i + 200]
            marks = ",".join(["%s"] * len(chunk))
            rows = a.safe(f"""SELECT DISTINCT user_name FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                              WHERE start_time > %s AND user_name IN ({marks})""",
                          (cutoff.isoformat(), *chunk), max_rows=10000)
            found |= {r["user_name"] for r in rows}
        return found

    # ---- the daily run -------------------------------------------------------------------
    def run(self, target: str, actor: str = "scheduler") -> dict:
        summary = {"target": target, "dry_run": self.dry_run, "flagged": 0, "cleared": 0,
                   "disabled": 0, "dropped": 0, "cancelled": 0, "errors": []}
        det = self.detect(target)
        total, cands = det["total_users"], det["candidates"]
        pct = 100.0 * len(cands) / max(total, 1)
        summary.update(total_users=total, candidates=len(cands), skipped=len(det["skipped"]))
        if pct > float(self.cfg.get("max_flagged_pct", 20)):
            msg = (f"Safety stop: {len(cands)} of {total} users ({pct:.0f}%) flagged as inactive on {target}, above "
                   f"max_flagged_pct. Nothing was changed. Check ACCOUNT_USAGE freshness and the config.")
            with session_scope() as s:
                audit(s, actor, "governance_safety_stop", target, candidates=len(cands), total=total)
            self.notify("Snowflake user cleanup halted", msg)
            summary["halted"] = msg
            return summary

        now = utcnow()
        cand_names = {c["name"] for c in cands}
        with session_scope() as s:
            existing = s.scalars(select(GovernanceCase).where(GovernanceCase.target == target)).all()
            by_user: dict[str, GovernanceCase] = {}
            for c in sorted(existing, key=lambda c: c.id):
                by_user[c.user_name] = c
            for c in existing:  # flagged users who logged in again are cleared
                if c.state == "flagged" and c.user_name not in cand_names:
                    c.state, c.error = "cleared", "user became active or is now excluded"
                    summary["cleared"] += 1
            for cand in cands:
                prev = by_user.get(cand["name"])
                if prev and (prev.state in OPEN_STATES or (prev.state == "kept" and prev.keep_until and prev.keep_until > now)):
                    continue
                s.add(GovernanceCase(target=target, user_name=cand["name"], state="flagged", reason=cand["reason"],
                                     last_success_login=_dt(cand.get("last_success_login")),
                                     user_created_on=_dt(cand.get("created_on"))))
                summary["flagged"] += 1
            audit(s, actor, "governance_scan", target,
                  **{k: v for k, v in summary.items() if k not in ("errors", "target")})

        budget = int(self.cfg.get("max_users_per_run", 25))
        with session_scope() as s:
            approved = [c.id for c in s.scalars(select(GovernanceCase).where(
                GovernanceCase.target == target, GovernanceCase.state == "approved"))]
            grace = now - timedelta(days=int(self.cfg.get("grace_period_days", 14)))
            due = [c.id for c in s.scalars(select(GovernanceCase).where(
                GovernanceCase.target == target, GovernanceCase.state == "disabled", GovernanceCase.disabled_at <= grace))]

        for cid in approved:
            if budget <= 0:
                break
            res = self._safe_step(self.disable, cid, actor, summary)
            if res == "disabled":
                summary["disabled"] += 1
                budget -= 1
        for cid in due:
            if budget <= 0:
                break
            res = self._safe_step(self.revoke_and_drop, cid, actor, summary)
            if res == "dropped":
                summary["dropped"] += 1
                budget -= 1
            elif res == "cancelled":
                summary["cancelled"] += 1

        if summary["flagged"] or summary["disabled"] or summary["dropped"]:
            self.notify("Snowflake inactive-user cleanup",
                        f"{target}: {summary['flagged']} newly flagged, {summary['disabled']} disabled, "
                        f"{summary['dropped']} dropped{' (DRY RUN)' if self.dry_run else ''}. Review in the dashboard.")
        return summary

    def _safe_step(self, fn, case_id: int, actor: str, summary: dict) -> str | None:
        try:
            return fn(case_id, actor)
        except Exception as e:  # noqa: BLE001
            log.exception("governance step failed for case %s", case_id)
            with session_scope() as s:
                c = s.get(GovernanceCase, case_id)
                c.error = str(e)[:2000]
                audit(s, actor, "governance_error", c.target, case_id=case_id, user=c.user_name, error=str(e)[:500])
            summary["errors"].append({"case_id": case_id, "error": str(e)[:300]})
            return None

    # ---- human decisions -----------------------------------------------------------------
    def approve(self, case_id: int, approver: str) -> str:
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            if c is None or c.state != "flagged":
                raise GovernanceError("only flagged cases can be approved")
            c.state, c.decided_by, c.decided_at = "approved", approver, utcnow()
            audit(s, approver, "governance_approved", c.target, case_id=case_id, user=c.user_name)
        return self.disable(case_id, approver)

    def keep(self, case_id: int, approver: str, note: str = "") -> None:
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            if c is None or c.state not in ("flagged", "approved"):
                raise GovernanceError("only flagged/approved cases can be kept")
            c.state, c.decided_by, c.decided_at = "kept", approver, utcnow()
            c.keep_until = utcnow() + timedelta(days=int(self.cfg.get("keep_days", 90)))
            c.error = note or None
            audit(s, approver, "governance_kept", c.target, case_id=case_id, user=c.user_name, note=note)

    # ---- lifecycle steps -----------------------------------------------------------------
    def _live_user(self, run, user: str) -> dict | None:
        rows = run(f"SHOW USERS LIKE {q_str(user)}")
        rows = [r for r in rows if r.get("name") == user]
        return rows[0] if rows else None

    def _snapshot(self, run, user: str) -> dict:
        grants = run(f"SHOW GRANTS TO USER {q_ident(user)}")
        props = run(f"DESCRIBE USER {q_ident(user)}")
        return {"taken_at": utcnow().isoformat(), "grants": grants,
                "properties": {p.get("property"): p.get("value") for p in props}}

    def disable(self, case_id: int, actor: str) -> str:
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            if c.state != "approved":
                raise GovernanceError(f"case {case_id} is {c.state}, expected approved")
            target, user = c.target, c.user_name
        if user.upper() in self._self_users(target):
            raise GovernanceError("refusing to act on the monitor/executor user")

        adapter = self.registry.get(target)
        with adapter.privileged() as run:
            live = self._live_user(run, user)
            if live is None:
                return self._set_state(case_id, actor, "dropped", note="user no longer exists")
            last = _dt(live.get("last_success_login"))
            if last and last > utcnow() - timedelta(days=self.inactive_days):
                return self._set_state(case_id, actor, "cleared", note=f"logged in at {last} (live check)")
            snap = self._snapshot(run, user)
            roles = sorted({g["role"] for g in snap["grants"] if g.get("role")})
            stmt = f"ALTER USER {q_ident(user)} SET DISABLED = TRUE"
            if self.dry_run:
                with session_scope() as s:
                    c = s.get(GovernanceCase, case_id)
                    c.snapshot, c.roles = jsonable({**snap, "dry_run_plan": [stmt]}), roles
                    audit(s, actor, "governance_dry_run", target, case_id=case_id, user=user, sql=[stmt])
                return "dry_run"
            # Snapshot is persisted BEFORE any change so a rollback is always possible.
            with session_scope() as s:
                c = s.get(GovernanceCase, case_id)
                c.snapshot, c.roles = jsonable(snap), roles
                audit(s, actor, "governance_snapshot", target, case_id=case_id, user=user, roles=roles)
            run(stmt)
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            c.state, c.disabled_at, c.error = "disabled", utcnow(), None
            audit(s, actor, "governance_disabled", target, case_id=case_id, user=user, sql=stmt)
        return "disabled"

    def revoke_and_drop(self, case_id: int, actor: str) -> str:
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            if c.state != "disabled":
                raise GovernanceError(f"case {case_id} is {c.state}, expected disabled")
            target, user = c.target, c.user_name
        if user.upper() in self._self_users(target):
            raise GovernanceError("refusing to act on the monitor/executor user")
        never = {r.upper() for r in self.cfg.get("roles_never_revoked", ["PUBLIC"])} | SYSTEM_ROLES

        adapter = self.registry.get(target)
        with adapter.privileged() as run:
            live = self._live_user(run, user)
            if live is None:
                return self._set_state(case_id, actor, "dropped", note="user already removed outside this tool")
            if str(live.get("disabled", "")).lower() not in ("true", "1"):
                return self._set_state(case_id, actor, "cancelled", note="user was re-enabled during the grace period")

            grants = run(f"SHOW GRANTS TO USER {q_ident(user)}")  # current state, not the snapshot
            roles = sorted({g["role"] for g in grants if g.get("role") and g["role"].upper() not in never})
            stmts = [f"REVOKE ROLE {q_ident(r)} FROM USER {q_ident(user)}" for r in roles]
            stmts += [f"ALTER USER {q_ident(user)} UNSET RSA_PUBLIC_KEY",
                      f"ALTER USER {q_ident(user)} UNSET RSA_PUBLIC_KEY_2",
                      f"DROP USER {q_ident(user)}"]
            if self.dry_run:
                with session_scope() as s:
                    audit(s, actor, "governance_dry_run", target, case_id=case_id, user=user, sql=stmts)
                return "dry_run"
            for stmt in stmts:
                try:
                    run(stmt)
                except Exception as e:  # noqa: BLE001
                    if "RSA_PUBLIC_KEY" in stmt:   # key may not be set; not fatal
                        continue
                    raise GovernanceError(f"failed at `{stmt}`: {e}") from e
                with session_scope() as s:
                    audit(s, actor, "governance_sql", target, case_id=case_id, user=user, sql=stmt)

            orphaned = []
            for r in roles:
                try:
                    if not run(f"SHOW GRANTS OF ROLE {q_ident(r)}"):
                        orphaned.append(r)
                except Exception:  # noqa: BLE001
                    pass
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            c.state, c.dropped_at, c.orphaned_roles, c.error = "dropped", utcnow(), orphaned, None
            audit(s, actor, "governance_dropped", target, case_id=case_id, user=user, revoked=roles, orphaned=orphaned)
        if orphaned:
            self.notify("Orphaned Snowflake roles", f"After dropping {user} on {target}, these roles have no grantees "
                        f"left and may be obsolete (review manually, not dropped): {', '.join(orphaned)}")
        return "dropped"

    def restore(self, case_id: int, actor: str) -> list[str]:
        """Undo: re-enable and re-grant (disabled case) or re-create the user from the snapshot (dropped case)."""
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            if c is None or c.state not in ("disabled", "dropped") or not c.snapshot:
                raise GovernanceError("only disabled/dropped cases with a snapshot can be restored")
            target, user, snap, state = c.target, c.user_name, dict(c.snapshot), c.state
        never = {r.upper() for r in self.cfg.get("roles_never_revoked", ["PUBLIC"])} | SYSTEM_ROLES
        roles = sorted({g["role"] for g in snap.get("grants", []) if g.get("role") and g["role"].upper() not in never})
        props = snap.get("properties", {})
        stmts = []
        if state == "dropped":
            opts = []
            for key in ("LOGIN_NAME", "DISPLAY_NAME", "EMAIL", "DEFAULT_WAREHOUSE", "DEFAULT_ROLE", "COMMENT"):
                val = props.get(key)
                if val not in (None, "", "null"):
                    opts.append(f"{key} = {q_str(val)}")
            stmts.append(f"CREATE USER {q_ident(user)} {' '.join(opts)}".strip())
        else:
            stmts.append(f"ALTER USER {q_ident(user)} SET DISABLED = FALSE")
        stmts += [f"GRANT ROLE {q_ident(r)} TO USER {q_ident(user)}" for r in roles]

        with self.registry.get(target).privileged() as run:
            for stmt in stmts:
                run(stmt)
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            c.state = "restored"
            c.error = "password/keys must be re-issued" if state == "dropped" else None
            audit(s, actor, "governance_restored", target, case_id=case_id, user=user, sql=stmts)
        return stmts

    def _set_state(self, case_id: int, actor: str, state: str, note: str = "") -> str:
        with session_scope() as s:
            c = s.get(GovernanceCase, case_id)
            c.state, c.error = state, note or None
            audit(s, actor, f"governance_{state}", c.target, case_id=case_id, user=c.user_name, note=note)
        return state
