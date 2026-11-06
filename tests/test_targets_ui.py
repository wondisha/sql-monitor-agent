"""Adding/removing servers from the dashboard: validation, secrets to .env, no secrets in YAML, live registration."""
import os

import yaml
from fastapi.testclient import TestClient

from monitor import targets_store
from monitor.api.main import create_api
from monitor.app import App
from monitor.config import load_settings

from .conftest import make_settings

FORM = {
    "name": "prod-pg1", "engine": "postgres",
    "connection": {"host": "db1.corp", "port": "5432", "dbname": "app", "sslmode": "require"},
    "monitor": {"user": "monitor", "password": "s3cret-mon"},
    "executor": {"user": "dba", "password": "s3cret-exec"},
}


def make_app(tmp_path, monkeypatch):
    monkeypatch.setenv("MONITOR_USERS", "alice:approver:alice-token-123456,vic:viewer:viewer-token-1234567")
    (tmp_path / ".env").write_text("MONITOR_USERS=keep-me\n", encoding="utf-8")
    settings = make_settings(tmp_path)
    settings.base_dir = tmp_path
    settings.raw["ui_targets_file"] = "targets_ui.yaml"
    return App(settings=settings)


def test_build_validates_and_separates_secrets(tmp_path, monkeypatch, db):
    app = make_app(tmp_path, monkeypatch)
    target, entry, secrets = targets_store.build(app.settings, FORM)
    assert target.monitor["password"] == "s3cret-mon" and target.monitor["port"] == 5432
    assert entry["monitor"]["password"] == "${MON_PROD_PG1_MONITOR_PASSWORD}"
    assert secrets == {"MON_PROD_PG1_MONITOR_PASSWORD": "s3cret-mon", "MON_PROD_PG1_EXECUTOR_PASSWORD": "s3cret-exec"}
    for bad in ({**FORM, "name": "Bad Name!"}, {**FORM, "engine": "oracle"},
                {**FORM, "connection": {**FORM["connection"], "host": ""}}, {**FORM, "monitor": {"user": ""}}):
        try:
            targets_store.build(app.settings, bad)
            raise AssertionError(f"accepted invalid form {bad}")
        except targets_store.TargetFormError:
            pass


def test_snowflake_requires_key_or_password(tmp_path, monkeypatch, db):
    app = make_app(tmp_path, monkeypatch)
    form = {"name": "sf", "engine": "snowflake", "connection": {"account": "org-acct"},
            "monitor": {"user": "MONITOR_SVC", "role": "MONITOR_ROLE"}, "executor": {}}
    try:
        targets_store.build(app.settings, form)
        raise AssertionError("accepted snowflake login without key or password")
    except targets_store.TargetFormError as e:
        assert "private key" in str(e)


def test_api_add_and_remove_server(tmp_path, monkeypatch, db):
    app = make_app(tmp_path, monkeypatch)
    client = TestClient(create_api(app))
    alice = {"Authorization": "Bearer alice-token-123456"}
    vic = {"Authorization": "Bearer viewer-token-1234567"}
    ok = {"monitor": {"ok": True, "metrics_collected": 9}, "executor": {"ok": True}}
    monkeypatch.setattr("monitor.adapters.postgres.PostgresAdapter.health", lambda self: {"ok": True})
    monkeypatch.setattr("monitor.adapters.postgres.PostgresAdapter.collect_fast", lambda self: [1] * 9)
    monkeypatch.setattr("monitor.adapters.postgres.PostgresAdapter.collect_slow", lambda self: [])
    monkeypatch.setattr("monitor.adapters.base.EngineAdapter.privileged",
                        lambda self: __import__("contextlib").nullcontext(lambda sql, *a, **k: []))

    assert client.post("/api/targets", json=FORM, headers=vic).status_code == 403      # viewers can't add
    r = client.post("/api/targets", json=FORM, headers=alice)
    assert r.status_code == 200 and r.json()["test"] == ok
    assert "prod-pg1" in app.registry.names()                                           # live, no restart
    assert client.post("/api/targets", json=FORM, headers=alice).status_code == 400    # duplicate name

    ui_yaml = (tmp_path / "targets_ui.yaml").read_text(encoding="utf-8")
    assert "s3cret" not in ui_yaml                                                      # no secrets in YAML
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "MONITOR_USERS=keep-me" in env and "MON_PROD_PG1_EXECUTOR_PASSWORD=s3cret-exec" in env
    entry = yaml.safe_load(ui_yaml)["targets"][0]
    assert entry["executor"]["password"] == "${MON_PROD_PG1_EXECUTOR_PASSWORD}"

    listed = {t["name"]: t for t in client.get("/api/targets", headers=vic).json()}
    assert listed["prod-pg1"]["source"] == "ui" and listed["prod-pg1"]["has_executor"]

    assert client.delete("/api/targets/prod-pg1", headers=alice).status_code == 200
    assert "prod-pg1" not in app.registry.names()
    assert "MON_PROD_PG1" not in (tmp_path / ".env").read_text(encoding="utf-8")
    assert "MON_PROD_PG1_MONITOR_PASSWORD" not in os.environ


def test_failed_monitor_login_is_not_saved(tmp_path, monkeypatch, db):
    app = make_app(tmp_path, monkeypatch)
    client = TestClient(create_api(app))
    monkeypatch.setattr("monitor.adapters.postgres.PostgresAdapter.health",
                        lambda self: {"ok": False, "error": "password authentication failed"})
    r = client.post("/api/targets", json={**FORM, "executor": {}}, headers={"Authorization": "Bearer alice-token-123456"})
    assert r.status_code == 409 and "password authentication failed" in r.json()["detail"]
    assert not (tmp_path / "targets_ui.yaml").exists() and "prod-pg1" not in app.registry.names()


def test_ui_targets_load_on_startup_and_names_stay_unique(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "settings.yaml").write_text("state_db_url: sqlite://\n", encoding="utf-8")
    (cfg / "targets.yaml").write_text("targets:\n  - {name: a, engine: postgres}\n", encoding="utf-8")
    (cfg / "targets_ui.yaml").write_text("targets:\n  - {name: b, engine: mysql}\n", encoding="utf-8")
    s = load_settings(cfg / "settings.yaml")
    assert [(t.name, t.source) for t in s.targets] == [("a", "config"), ("b", "ui")]
    (cfg / "targets_ui.yaml").write_text("targets:\n  - {name: a, engine: mysql}\n", encoding="utf-8")
    try:
        load_settings(cfg / "settings.yaml")
        raise AssertionError("duplicate target names accepted")
    except ValueError:
        pass
