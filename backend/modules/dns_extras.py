"""DNS extras: history, templates, import/export, search, conflict & propagation checks."""
from __future__ import annotations

import csv
import io
import json
import socket
import time
from typing import Any, Dict, List, Optional, Tuple


def table_ready(conn_fn, name: str) -> bool:
    try:
        with conn_fn() as c:
            row = c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
                (name,),
            ).fetchone()
            return bool(row)
    except Exception:
        return False


def insert_history(
    conn_fn,
    *,
    user_id: int,
    credential_id: Any,
    zone_id: str,
    zone_name: str,
    record_id: Any,
    record_name: Any,
    record_type: Any,
    action: str,
    old_value: Any = None,
    new_value: Any = None,
) -> None:
    if not table_ready(conn_fn, "dns_record_history"):
        return
    try:
        with conn_fn() as c:
            c.execute(
                """
                INSERT INTO dns_record_history
                  (userId, credentialId, zoneId, zoneName, recordId, recordName, recordType, action, oldValue, newValue, createdAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    int(user_id),
                    int(credential_id) if credential_id is not None else None,
                    str(zone_id or ""),
                    str(zone_name or ""),
                    str(record_id or "") if record_id is not None else None,
                    str(record_name or "") if record_name is not None else None,
                    str(record_type or "") if record_type is not None else None,
                    str(action or "UPDATE"),
                    json.dumps(old_value, ensure_ascii=False) if isinstance(old_value, (dict, list)) else (str(old_value) if old_value is not None else None),
                    json.dumps(new_value, ensure_ascii=False) if isinstance(new_value, (dict, list)) else (str(new_value) if new_value is not None else None),
                ),
            )
            c.commit()
    except Exception:
        pass


def list_history(conn_fn, user_id: int, *, zone_id: str | None = None, record_id: str | None = None, page: int = 1, limit: int = 50) -> Dict[str, Any]:
    if not table_ready(conn_fn, "dns_record_history"):
        return {"items": [], "total": 0, "page": page, "limit": limit}
    where = ["userId = ?"]
    params: List[Any] = [int(user_id)]
    if zone_id:
        where.append("zoneId = ?")
        params.append(str(zone_id))
    if record_id:
        where.append("recordId = ?")
        params.append(str(record_id))
    sql_where = " AND ".join(where)
    with conn_fn() as c:
        total = c.execute(f"SELECT COUNT(*) AS c FROM dns_record_history WHERE {sql_where}", params).fetchone()["c"]
        rows = c.execute(
            f"""
            SELECT id, credentialId, zoneId, zoneName, recordId, recordName, recordType, action, oldValue, newValue, createdAt
            FROM dns_record_history
            WHERE {sql_where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, int(limit), (int(page) - 1) * int(limit)),
        ).fetchall()
    items = []
    for r in rows:
        items.append(
            {
                "id": r["id"],
                "credentialId": r["credentialId"],
                "zoneId": r["zoneId"],
                "zoneName": r["zoneName"],
                "recordId": r["recordId"],
                "recordName": r["recordName"],
                "recordType": r["recordType"],
                "action": r["action"],
                "oldValue": r["oldValue"],
                "newValue": r["newValue"],
                "createdAt": r["createdAt"],
            }
        )
    return {"items": items, "total": int(total or 0), "page": page, "limit": limit}


def get_history_row(conn_fn, user_id: int, history_id: int) -> Optional[Dict[str, Any]]:
    if not table_ready(conn_fn, "dns_record_history"):
        return None
    with conn_fn() as c:
        row = c.execute(
            """
            SELECT * FROM dns_record_history WHERE id = ? AND userId = ? LIMIT 1
            """,
            (int(history_id), int(user_id)),
        ).fetchone()
    if not row:
        return None
    return {k: row[k] for k in row.keys()}


def list_templates(conn_fn, user_id: int) -> List[Dict[str, Any]]:
    if not table_ready(conn_fn, "dns_record_templates"):
        return []
    with conn_fn() as c:
        rows = c.execute(
            "SELECT id, name, description, records, createdAt, updatedAt FROM dns_record_templates WHERE userId = ? ORDER BY id DESC",
            (int(user_id),),
        ).fetchall()
    out = []
    for r in rows:
        try:
            records = json.loads(r["records"] or "[]")
        except Exception:
            records = []
        out.append(
            {
                "id": r["id"],
                "name": r["name"],
                "description": r["description"],
                "records": records if isinstance(records, list) else [],
                "createdAt": r["createdAt"],
                "updatedAt": r["updatedAt"],
            }
        )
    return out


def create_template(conn_fn, user_id: int, name: str, description: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    with conn_fn() as c:
        c.execute(
            """
            INSERT INTO dns_record_templates (userId, name, description, records, createdAt, updatedAt)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (int(user_id), str(name), str(description or ""), json.dumps(records or [], ensure_ascii=False)),
        )
        tid = int(c.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])
        row = c.execute(
            "SELECT id, name, description, records, createdAt, updatedAt FROM dns_record_templates WHERE id = ?",
            (tid,),
        ).fetchone()
        c.commit()
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "records": json.loads(row["records"] or "[]"),
        "createdAt": row["createdAt"],
        "updatedAt": row["updatedAt"],
    }


def delete_template(conn_fn, user_id: int, template_id: int) -> bool:
    with conn_fn() as c:
        c.execute("DELETE FROM dns_record_templates WHERE id = ? AND userId = ?", (int(template_id), int(user_id)))
        c.commit()
        return c.total_changes > 0


def export_records(records: List[Dict[str, Any]], zone_name: str, fmt: str = "json") -> Tuple[str, str]:
    fmt = (fmt or "json").lower()
    zone_name = zone_name or "zone"
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["name", "type", "value", "ttl", "line", "priority", "weight", "status", "remark"])
        writer.writeheader()
        for r in records:
            writer.writerow(
                {
                    "name": r.get("name"),
                    "type": r.get("type"),
                    "value": r.get("value") or r.get("content"),
                    "ttl": r.get("ttl"),
                    "line": r.get("line"),
                    "priority": r.get("priority"),
                    "weight": r.get("weight"),
                    "status": r.get("status"),
                    "remark": r.get("remark"),
                }
            )
        return buf.getvalue(), f"{zone_name}.csv"
    if fmt == "bind":
        lines = [f"; BIND export for {zone_name}", f"$ORIGIN {zone_name}."]
        for r in records:
            name = str(r.get("name") or "@")
            if name.endswith(f".{zone_name}"):
                name = name[: -(len(zone_name) + 1)] or "@"
            ttl = r.get("ttl") or 600
            rtype = str(r.get("type") or "A")
            value = str(r.get("value") or r.get("content") or "")
            if rtype == "TXT" and not value.startswith('"'):
                value = f'"{value}"'
            lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{value}")
        return "\n".join(lines) + "\n", f"{zone_name}.zone"
    payload = {"zone": zone_name, "records": records, "exportedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    return json.dumps(payload, ensure_ascii=False, indent=2), f"{zone_name}.json"


def parse_import(content: str, fmt: str = "json") -> List[Dict[str, Any]]:
    fmt = (fmt or "json").lower()
    content = content or ""
    rows: List[Dict[str, Any]] = []
    if fmt == "csv":
        reader = csv.DictReader(io.StringIO(content))
        for r in reader:
            rows.append(
                {
                    "name": (r.get("name") or "").strip(),
                    "type": (r.get("type") or "A").strip().upper(),
                    "value": (r.get("value") or r.get("content") or "").strip(),
                    "ttl": int(r["ttl"]) if str(r.get("ttl") or "").isdigit() else None,
                    "line": r.get("line"),
                    "priority": int(r["priority"]) if str(r.get("priority") or "").isdigit() else None,
                    "weight": int(r["weight"]) if str(r.get("weight") or "").isdigit() else None,
                    "remark": r.get("remark"),
                }
            )
        return [x for x in rows if x.get("name") and x.get("value")]
    if fmt == "bind":
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith(";") or s.startswith("$"):
                continue
            parts = s.split()
            if len(parts) < 4:
                continue
            # name ttl IN type value...
            name = parts[0]
            if parts[1].isdigit() and len(parts) >= 5:
                ttl = int(parts[1])
                rtype = parts[3].upper()
                value = " ".join(parts[4:]).strip()
            else:
                ttl = None
                rtype = parts[2].upper() if len(parts) > 2 else "A"
                value = " ".join(parts[3:]).strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            rows.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
        return rows
    data = json.loads(content)
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        return [x for x in data["records"] if isinstance(x, dict)]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def detect_conflicts(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_name: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        name = str(r.get("name") or "").strip().lower().rstrip(".")
        if not name:
            continue
        by_name.setdefault(name, []).append(r)
    conflicts = []
    for name, items in by_name.items():
        types = sorted({str(x.get("type") or "").upper() for x in items if x.get("type")})
        if "CNAME" in types and len(types) > 1:
            conflicts.append(
                {
                    "name": name,
                    "types": types,
                    "message": f"{name} 同时存在 CNAME 与 {', '.join(t for t in types if t != 'CNAME')}，通常互斥",
                }
            )
        if types.count("CNAME") == 0 and "CNAME" in {str(x.get("type") or "").upper() for x in items}:
            pass
    return conflicts


def propagate_check(name: str, rtype: str = "A", expected: str | None = None) -> Dict[str, Any]:
    """Best-effort A/AAAA lookup via the system resolver.

    stdlib cannot pin public resolvers (8.8.8.8 / 1.1.1.1) without dnspython,
    so we only report the OS resolver result and do not claim multi-resolver consistency.
    """
    name = str(name or "").strip().rstrip(".")
    rtype = str(rtype or "A").upper()
    vals: List[str] = []
    err = None
    try:
        if rtype in {"A", "AAAA"}:
            family = socket.AF_INET if rtype == "A" else socket.AF_INET6
            # getaddrinfo has no per-call timeout; rely on OS resolver timeout.
            infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in vals:
                    vals.append(ip)
        else:
            err = f"stdlib 仅对 A/AAAA 做传播检测，当前类型 {rtype}"
    except Exception as exc:
        err = str(exc)

    answers = [{"resolver": "system", "values": vals, "error": err}]
    consistent = bool(vals)
    if expected:
        expected_n = str(expected).strip().lower()
        consistent = consistent and expected_n in [v.lower() for v in vals]
    return {
        "name": name,
        "type": rtype,
        "expected": expected,
        "answers": answers,
        "consistent": consistent,
        "note": "仅使用系统解析器；跨公共 DNS 一致性检测需安装 dnspython",
    }


def list_all_provider_records(api: Any, zone_id: str, *, page_size: int = 200, max_pages: int = 50) -> List[Dict[str, Any]]:
    """Paginate provider list_records until exhausted or max_pages."""
    all_rows: List[Dict[str, Any]] = []
    page = 1
    page_size = max(1, min(int(page_size or 200), 500))
    max_pages = max(1, min(int(max_pages or 50), 200))
    while page <= max_pages:
        try:
            res = api.list_records(zone_id, page, page_size, {})
        except Exception:
            break
        if not isinstance(res, dict):
            break
        batch = res.get("records") if isinstance(res.get("records"), list) else []
        for r in batch:
            if isinstance(r, dict):
                all_rows.append(r)
        total = res.get("total")
        if len(batch) < page_size:
            break
        if isinstance(total, int) and total >= 0 and len(all_rows) >= total:
            break
        page += 1
    return all_rows
