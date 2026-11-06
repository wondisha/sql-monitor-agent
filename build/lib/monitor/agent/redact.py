"""Strip literal values from SQL text before it is sent to the LLM (PII protection).

Query text in DMVs/query history may contain customer values: WHERE email = 'a@b.com'.
We replace string literals and standalone numbers with '?', keeping the query shape.
"""
from __future__ import annotations

import re
from typing import Any

_STRING = re.compile(r"'(?:[^']|'')*'")
_DOLLAR = re.compile(r"\$\$.*?\$\$", re.DOTALL)
_NUMBER = re.compile(r"(?<![\w.$])-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?(?![\w.])")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

SQL_KEYS = re.compile(r"(query|sql|text|statement|graph|message|info)", re.IGNORECASE)
# Identifiers the agent needs verbatim (query_id, query_hash, sql_handle...) are never redacted.
ID_KEYS = re.compile(r"(_id|_ids|_hash|_handle|_tag)$", re.IGNORECASE)


def redact_sql(text: str) -> str:
    if not text:
        return text
    t = _DOLLAR.sub("$$?$$", text)
    t = _STRING.sub("'?'", t)
    t = _EMAIL.sub("<email>", t)
    t = _NUMBER.sub("?", t)
    return t


def redact_payload(obj: Any, key: str = "") -> Any:
    """Recursively redact string values whose key looks like SQL text or error messages."""
    if isinstance(obj, dict):
        return {k: redact_payload(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_payload(v, key) for v in obj]
    if isinstance(obj, str) and key and SQL_KEYS.search(key) and not ID_KEYS.search(key):
        return redact_sql(obj)
    return obj
