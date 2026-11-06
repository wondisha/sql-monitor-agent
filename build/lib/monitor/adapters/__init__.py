from __future__ import annotations

from ..config import Target
from .base import EngineAdapter, Metric  # noqa: F401


def build_adapter(target: Target, tool_limits: dict | None = None) -> EngineAdapter:
    engine = target.engine
    if engine == "postgres":
        from .postgres import PostgresAdapter as cls
    elif engine == "mysql":
        from .mysql import MySQLAdapter as cls
    elif engine == "mssql":
        from .mssql import MSSQLAdapter as cls
    elif engine == "snowflake":
        from .snowflake import SnowflakeAdapter as cls
    else:
        raise ValueError(f"Unsupported engine: {engine}")
    return cls(target, tool_limits)


class AdapterRegistry:
    """One adapter instance per enabled target, shared by collectors, the agent and the executor."""

    def __init__(self, targets: list[Target], tool_limits: dict | None = None):
        self._adapters = {t.name: build_adapter(t, tool_limits) for t in targets if t.enabled}

    def get(self, name: str) -> EngineAdapter:
        if name not in self._adapters:
            raise KeyError(f"Unknown or disabled target: {name}")
        return self._adapters[name]

    def items(self):
        return self._adapters.items()

    def names(self) -> list[str]:
        return list(self._adapters)

    def register(self, adapter: EngineAdapter) -> None:
        self._adapters[adapter.target.name] = adapter

    def remove(self, name: str) -> None:
        adapter = self._adapters.pop(name, None)
        if adapter is not None:
            adapter.close()
