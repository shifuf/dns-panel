"""Redis cache module with graceful degradation.

All public functions silently return None / no-op when Redis is unavailable,
so the application falls back to calling upstream APIs directly.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import threading
import time
from typing import Any

_pool = None
_disabled = False
# Circuit breaker: when a Redis op fails we stop trying for _RETRY_INTERVAL
# seconds. Without this, every cache_get/cache_set re-attempts a connection to
# an unreachable Redis and blocks on the connect timeout — adding seconds to
# *every* cached endpoint (domains ~4s, SSL ~9s) when Redis is down.
_RETRY_INTERVAL = 30.0
_redis_down_until = 0.0


def _mark_redis_down() -> None:
    global _redis_down_until
    _redis_down_until = time.monotonic() + _RETRY_INTERVAL

# ---------------------------------------------------------------------------
# In-process memory fallback
#
# When Redis is unavailable (not installed, not running, wrong URL) the module
# would otherwise become a permanent no-op, forcing every request to hit the
# upstream provider APIs (Cloudflare / DNSPod / Tencent) cold. That makes the
# domain list, DNS record pages and SSL certificate views slow on every load.
#
# This lightweight TTL dict keeps cached snapshots in the worker process so
# repeated reads (pagination, re-renders, navigating back and forth) stay fast
# without requiring a Redis deployment. Values are stored as JSON strings to
# mirror Redis semantics — callers always get an immutable copy.
# ---------------------------------------------------------------------------
_MEM_MAX_ENTRIES = 2000
_mem_store: dict[str, tuple[float, str]] = {}
_mem_lock = threading.Lock()


def _mem_purge_expired(now: float) -> None:
    """Drop expired entries; if still over capacity, evict oldest by expiry."""
    expired = [k for k, (exp, _) in _mem_store.items() if exp <= now]
    for k in expired:
        _mem_store.pop(k, None)
    if len(_mem_store) > _MEM_MAX_ENTRIES:
        for k, _ in sorted(_mem_store.items(), key=lambda kv: kv[1][0])[: len(_mem_store) - _MEM_MAX_ENTRIES]:
            _mem_store.pop(k, None)


def _mem_get(key: str) -> Any:
    now = time.monotonic()
    with _mem_lock:
        entry = _mem_store.get(key)
        if entry is None:
            return None
        exp, raw = entry
        if exp <= now:
            _mem_store.pop(key, None)
            return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _mem_set(key: str, value: Any, ttl: int) -> None:
    try:
        raw = json.dumps(value, ensure_ascii=False)
    except Exception:
        return
    now = time.monotonic()
    with _mem_lock:
        _mem_store[key] = (now + max(1, int(ttl)), raw)
        if len(_mem_store) > _MEM_MAX_ENTRIES:
            _mem_purge_expired(now)


def _mem_delete(key: str) -> None:
    with _mem_lock:
        _mem_store.pop(key, None)


def _mem_delete_pattern(pattern: str) -> int:
    with _mem_lock:
        matched = [k for k in _mem_store if fnmatch.fnmatchcase(k, pattern)]
        for k in matched:
            _mem_store.pop(k, None)
    return len(matched)


def _get_redis():
    """Return a Redis client, or None when Redis is unavailable.

    A circuit breaker (_redis_down_until) skips Redis entirely for a short
    cooldown after any failure, so a down Redis costs at most one short
    connect-timeout per _RETRY_INTERVAL instead of one on every call.
    """
    global _pool, _disabled
    if _disabled:
        return None
    if time.monotonic() < _redis_down_until:
        return None
    if _pool is not None:
        try:
            import redis as _redis_mod
            return _redis_mod.Redis(connection_pool=_pool)
        except Exception:
            _mark_redis_down()
            return None
    try:
        import redis as _redis_mod
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        _pool = _redis_mod.ConnectionPool.from_url(
            url,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
            decode_responses=True,
        )
        return _redis_mod.Redis(connection_pool=_pool)
    except Exception:
        _mark_redis_down()
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def cache_get(key: str) -> Any:
    r = _get_redis()
    if r is None:
        return _mem_get(key)
    try:
        raw = r.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        _mark_redis_down()
        return _mem_get(key)


def cache_set(key: str, value: Any, ttl: int) -> None:
    r = _get_redis()
    if r is None:
        _mem_set(key, value, ttl)
        return
    try:
        r.setex(key, int(ttl), json.dumps(value, ensure_ascii=False))
    except Exception:
        _mark_redis_down()
        _mem_set(key, value, ttl)


def cache_delete(key: str) -> None:
    r = _get_redis()
    if r is None:
        _mem_delete(key)
        return
    try:
        r.delete(key)
    except Exception:
        _mark_redis_down()
        _mem_delete(key)


def cache_delete_pattern(pattern: str) -> int:
    """Delete all keys matching *pattern* using SCAN (non-blocking)."""
    r = _get_redis()
    if r is None:
        return _mem_delete_pattern(pattern)
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
        _mark_redis_down()
        return _mem_delete_pattern(pattern)


def cache_ping() -> bool:
    r = _get_redis()
    if r is None:
        return False
    try:
        return r.ping()
    except Exception:
        _mark_redis_down()
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


def acceleration_sites_key(cred_id: int, provider: str, **params: Any) -> str:
    return f"acceleration:sites:cred:{cred_id}:p:{provider}:{_param_hash(**params)}"


def acceleration_domains_key(cred_id: int, provider: str, site_id: str, **params: Any) -> str:
    return f"acceleration:domains:cred:{cred_id}:p:{provider}:s:{site_id}:{_param_hash(**params)}"


def dashboard_summary_key(uid: int) -> str:
    return f"dashboard:summary:user:{uid}"


def ssl_certs_key(cred_id: int, **params: Any) -> str:
    return f"ssl:certs:cred:{cred_id}:{_param_hash(**params)}"


def ssl_cert_detail_key(cred_id: int, cert_id: str) -> str:
    return f"ssl:cert:{cred_id}:{cert_id}"


def ssl_certs_all_key(uid: int, **params: Any) -> str:
    return f"ssl:certs:all:user:{uid}:{_param_hash(**params)}"
