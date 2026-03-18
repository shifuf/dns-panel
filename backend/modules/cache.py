"""Redis cache module with graceful degradation.

All public functions silently return None / no-op when Redis is unavailable,
so the application falls back to calling upstream APIs directly.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

_pool = None
_disabled = False


def _get_redis():
    """Return a Redis client using a lazily-initialised ConnectionPool.

    Once a connection attempt fails the module marks itself *disabled* for the
    remainder of the process lifetime so subsequent calls are essentially free.
    """
    global _pool, _disabled
    if _disabled:
        return None
    if _pool is not None:
        try:
            import redis as _redis_mod
            return _redis_mod.Redis(connection_pool=_pool)
        except Exception:
            _disabled = True
            return None
    try:
        import redis as _redis_mod
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        _pool = _redis_mod.ConnectionPool.from_url(
            url,
            socket_connect_timeout=2,
            socket_timeout=1,
            decode_responses=True,
        )
        return _redis_mod.Redis(connection_pool=_pool)
    except Exception:
        _disabled = True
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def cache_get(key: str) -> Any:
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        return None


def cache_set(key: str, value: Any, ttl: int) -> None:
    r = _get_redis()
    if r is None:
        return
    try:
        r.setex(key, int(ttl), json.dumps(value, ensure_ascii=False))
    except Exception:
        pass


def cache_delete(key: str) -> None:
    r = _get_redis()
    if r is None:
        return
    try:
        r.delete(key)
    except Exception:
        pass


def cache_delete_pattern(pattern: str) -> int:
    """Delete all keys matching *pattern* using SCAN (non-blocking)."""
    r = _get_redis()
    if r is None:
        return 0
    try:
        count = 0
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                r.delete(*keys)
                count += len(keys)
            if cursor == 0:
                break
        return count
    except Exception:
        return 0


def cache_ping() -> bool:
    r = _get_redis()
    if r is None:
        return False
    try:
        return r.ping()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Key construction helpers
# ---------------------------------------------------------------------------

def _param_hash(**kwargs: Any) -> str:
    raw = json.dumps(kwargs, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def zones_key(cred_id: int, **params: Any) -> str:
    return f"dns:zones:cred:{cred_id}:{_param_hash(**params)}"


def records_key(cred_id: int, zone_id: str, **params: Any) -> str:
    return f"dns:records:cred:{cred_id}:z:{zone_id}:{_param_hash(**params)}"


def lines_key(cred_id: int, zone_id: str) -> str:
    return f"dns:lines:cred:{cred_id}:z:{zone_id}"


def providers_key() -> str:
    return "dns:providers"


def esa_sites_key(cred_id: int, **params: Any) -> str:
    return f"esa:sites:cred:{cred_id}:{_param_hash(**params)}"


def esa_records_key(cred_id: int, **params: Any) -> str:
    return f"esa:records:cred:{cred_id}:{_param_hash(**params)}"


def dashboard_summary_key(uid: int) -> str:
    return f"dashboard:summary:user:{uid}"


def ssl_certs_key(cred_id: int, **params: Any) -> str:
    return f"ssl:certs:cred:{cred_id}:{_param_hash(**params)}"


def ssl_cert_detail_key(cred_id: int, cert_id: str) -> str:
    return f"ssl:cert:{cred_id}:{cert_id}"
