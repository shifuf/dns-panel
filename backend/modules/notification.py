"""Unified multi-channel notification service.

Supports: email / webhook / wecom / dingtalk / feishu / telegram / inapp.
No third-party deps — uses stdlib smtplib + urllib only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import smtplib
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional

SUPPORTED_CHANNEL_TYPES = frozenset(
    {"email", "webhook", "wecom", "dingtalk", "feishu", "telegram", "inapp"}
)

USER_AGENT = "dns-panel-notify/1.0"


# ── helpers ──────────────────────────────────────────────────────────


def _split_emails(value: Any) -> List[str]:
    recipients: List[str] = []
    seen = set()
    for item in re.split(r"[,;\s]+", str(value or "").strip()):
        email = item.strip()
        if not email or "@" not in email or email.lower() in seen:
            continue
        seen.add(email.lower())
        recipients.append(email)
    return recipients


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise ValueError("Webhook URL 不允许 HTTP 重定向")


_SAFE_OPENER = urllib.request.build_opener(_NoRedirect())


def validate_webhook_url(value: Any, *, allow_http: bool = False, wecom: bool = False) -> str:
    """Validate outbound webhook URL: scheme, no credentials, no private IPs, no link-local."""
    target = str(value or "").strip()
    if not target:
        raise ValueError("Webhook URL 未配置")
    parsed = urllib.parse.urlparse(target)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ({"https", "http"} if allow_http else {"https"}):
        raise ValueError("Webhook URL 必须使用 HTTPS" if not allow_http else "Webhook URL 必须以 http:// 或 https:// 开头")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Webhook URL 必须是无用户信息的合法地址")
    hostname = parsed.hostname.lower().rstrip(".")
    if wecom and hostname != "qyapi.weixin.qq.com":
        raise ValueError("企业微信机器人地址必须使用 qyapi.weixin.qq.com")
    # Block obviously dangerous hostnames even before DNS resolve.
    if hostname in {"localhost", "metadata", "metadata.google.internal"} or hostname.endswith(".local"):
        raise ValueError("Webhook URL 不能指向本机、内网或保留地址")
    try:
        # IPv4/IPv6 literal host
        ip_literal = ipaddress.ip_address(hostname)
        if not ip_literal.is_global:
            raise ValueError("Webhook URL 不能指向本机、内网、保留或链路本地地址")
    except ValueError as exc:
        if "不能指向" in str(exc):
            raise
        # hostname — resolve and check every address
        port = parsed.port or (443 if scheme == "https" else 80)
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)}
        except Exception as resolve_exc:
            raise ValueError(f"Webhook URL 无法解析: {resolve_exc}") from resolve_exc
        if not addresses:
            raise ValueError("Webhook URL 无法解析")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ValueError("Webhook URL 不能指向本机、内网、保留或链路本地地址")
    return target


def sanitize_notification_channels(channels: Any) -> List[Dict[str, Any]]:
    """Validate and normalize channel configs before persistence or test send."""
    if not isinstance(channels, list):
        raise ValueError("channels 必须是数组")
    out: List[Dict[str, Any]] = []
    for idx, item in enumerate(channels):
        if not isinstance(item, dict):
            raise ValueError(f"channels[{idx}] 无效")
        ctype = str(item.get("type") or "").strip().lower()
        if ctype not in SUPPORTED_CHANNEL_TYPES:
            raise ValueError(f"不支持的通知渠道: {ctype or '(空)'}")
        cfg_in = item.get("config") if isinstance(item.get("config"), dict) else {}
        cfg = {str(k): v for k, v in cfg_in.items() if str(k).strip()}
        # Never persist arbitrary callable / oversized blobs
        for secret_key in list(cfg.keys()):
            if secret_key in {"callback"}:
                cfg.pop(secret_key, None)
        if ctype in {"webhook", "wecom", "dingtalk", "feishu"}:
            url = str(cfg.get("url") or cfg.get("webhookUrl") or "").strip()
            if url:
                try:
                    validate_webhook_url(url, wecom=(ctype == "wecom"))
                except ValueError as exc:
                    # allow key-only wecom/dingtalk without free-form URL
                    if ctype == "wecom" and (cfg.get("key") or cfg.get("webhookKey")) and not url:
                        pass
                    else:
                        raise ValueError(f"channels[{idx}] ({ctype}): {exc}") from exc
            elif ctype == "wecom":
                key = str(cfg.get("key") or cfg.get("webhookKey") or "").strip()
                if not key:
                    # empty allowed for draft save; send path will fail clearly
                    pass
            elif ctype == "dingtalk":
                token = str(cfg.get("accessToken") or cfg.get("token") or "").strip()
                if not token and not url:
                    pass
            elif ctype == "webhook" and not url:
                pass
        if ctype == "telegram":
            token = str(cfg.get("botToken") or cfg.get("token") or "").strip()
            chat_id = str(cfg.get("chatId") or cfg.get("chat_id") or "").strip()
            if token and ("/" in token or " " in token or len(token) > 128):
                raise ValueError(f"channels[{idx}] telegram botToken 格式无效")
            if chat_id and len(chat_id) > 64:
                raise ValueError(f"channels[{idx}] telegram chatId 过长")
        if ctype == "email":
            to_val = cfg.get("to") or cfg.get("emailTo") or cfg.get("recipients")
            if to_val and not _split_emails(to_val):
                raise ValueError(f"channels[{idx}] 收件邮箱格式无效")
        out.append(
            {
                "type": ctype,
                "enabled": False if item.get("enabled") is False else True,
                "config": cfg,
            }
        )
    return out


def _http_json_post(
    url: str,
    payload: Dict[str, Any],
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    wecom: bool = False,
    skip_validate: bool = False,
) -> tuple[int, str]:
    target = str(url or "").strip()
    if not skip_validate:
        target = validate_webhook_url(target, wecom=wecom)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req_headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": USER_AGENT,
    }
    if headers:
        req_headers.update(headers)
    request = urllib.request.Request(target, method="POST", data=data, headers=req_headers)
    try:
        with _SAFE_OPENER.open(request, timeout=timeout) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            body = resp.read(8192).decode("utf-8", errors="replace")
            if status < 200 or status >= 300:
                raise ValueError(f"HTTP {status}: {body[:200]}")
            return status, body
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
        raise ValueError(f"HTTP {exc.code}: {raw[:200]}") from exc


def _safe_json(raw: str) -> Dict[str, Any]:
    try:
        data = json.loads(raw or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# ── channel senders ──────────────────────────────────────────────────


def _send_email(config: Dict[str, Any], title: str, content: str) -> None:
    host = str(config.get("smtpHost") or config.get("host") or "").strip()
    if not host:
        raise ValueError("SMTP 服务器未配置")
    secure = bool(config.get("smtpSecure") if "smtpSecure" in config else config.get("secure"))
    try:
        port = int(config.get("smtpPort") or config.get("port") or (465 if secure else 587))
    except Exception as exc:
        raise ValueError("SMTP 端口无效") from exc
    username = str(config.get("smtpUser") or config.get("user") or "").strip()
    password = str(config.get("smtpPass") or config.get("pass") or config.get("password") or "")
    sender = str(config.get("smtpFrom") or config.get("from") or username or "").strip()
    recipients = _split_emails(config.get("to") or config.get("emailTo") or config.get("recipients"))
    if not sender:
        raise ValueError("发件人未配置")
    if not recipients:
        raise ValueError("收件邮箱未配置")

    msg = EmailMessage()
    msg["Subject"] = str(title or "DNS Panel 通知")
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(str(content or ""))

    if secure or port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)
        return

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if port == 587 or bool(config.get("starttls", True)):
            try:
                smtp.starttls()
            except Exception:
                pass
        if username:
            smtp.login(username, password)
        smtp.send_message(msg)


def _send_webhook(config: Dict[str, Any], title: str, content: str, level: str, meta: Dict[str, Any]) -> None:
    url = str(config.get("url") or config.get("webhookUrl") or "").strip()
    payload = {
        "title": title,
        "content": content,
        "level": level,
        "meta": meta or {},
        "event": (meta or {}).get("event") or "notification",
        "generatedAt": (meta or {}).get("generatedAt"),
    }
    if isinstance(config.get("payload"), dict):
        payload.update(config["payload"])
    _http_json_post(url, payload)


def _resolve_wecom_url(config: Dict[str, Any]) -> str:
    url = str(config.get("url") or config.get("webhookUrl") or "").strip()
    if url:
        return url
    key = str(config.get("key") or config.get("webhookKey") or "").strip()
    if key:
        return f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={key}"
    raise ValueError("企业微信 Webhook 未配置")


def _send_wecom(config: Dict[str, Any], title: str, content: str) -> None:
    url = _resolve_wecom_url(config)
    text = f"**{title}**\n{content}"
    status, body = _http_json_post(
        url,
        {"msgtype": "markdown", "markdown": {"content": text[:4000]}},
        wecom=True,
    )
    result = _safe_json(body)
    if int(result.get("errcode") or 0) != 0:
        raise ValueError(str(result.get("errmsg") or f"企业微信通知失败 (HTTP {status})"))


def _send_dingtalk(config: Dict[str, Any], title: str, content: str) -> None:
    url = str(config.get("url") or config.get("webhookUrl") or "").strip()
    if not url:
        access_token = str(config.get("accessToken") or config.get("token") or "").strip()
        if not access_token:
            raise ValueError("钉钉 Webhook 未配置")
        url = f"https://oapi.dingtalk.com/robot/send?access_token={access_token}"

    secret = str(config.get("secret") or "").strip()
    if secret:
        timestamp = str(int(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
        sign = urllib.parse.quote_plus(
            base64.b64encode(
                hmac.new(secret.encode("utf-8"), string_to_sign, digestmod=hashlib.sha256).digest()
            )
        )
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}timestamp={timestamp}&sign={sign}"

    payload = {
        "msgtype": "markdown",
        "markdown": {
            "title": str(title or "DNS Panel")[:64],
            "text": f"### {title}\n\n{content}",
        },
    }
    status, body = _http_json_post(url, payload)
    result = _safe_json(body)
    if int(result.get("errcode") or 0) != 0:
        raise ValueError(str(result.get("errmsg") or f"钉钉通知失败 (HTTP {status})"))


def _send_feishu(config: Dict[str, Any], title: str, content: str) -> None:
    url = str(config.get("url") or config.get("webhookUrl") or "").strip()
    if not url:
        raise ValueError("飞书 Webhook 未配置")
    payload = {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": str(title or "DNS Panel")[:100]},
                "template": "blue",
            },
            "elements": [
                {"tag": "div", "text": {"tag": "plain_text", "content": str(content or "")[:4000]}},
            ],
        },
    }
    # fallback simple text if card rejected by older bots
    try:
        status, body = _http_json_post(url, payload)
        result = _safe_json(body)
        code = result.get("code", result.get("StatusCode", 0))
        if code not in (0, "0", None) and int(code or 0) != 0:
            raise ValueError(str(result.get("msg") or result.get("StatusMessage") or "飞书通知失败"))
        return
    except Exception:
        status, body = _http_json_post(
            url,
            {
                "msg_type": "text",
                "content": {"text": f"{title}\n{content}"[:4000]},
            },
        )
        result = _safe_json(body)
        code = result.get("code", result.get("StatusCode", 0))
        if code not in (0, "0", None) and int(code or 0) != 0:
            raise ValueError(str(result.get("msg") or result.get("StatusMessage") or f"飞书通知失败 (HTTP {status})"))


def _send_telegram(config: Dict[str, Any], title: str, content: str) -> None:
    token = str(config.get("botToken") or config.get("token") or "").strip()
    chat_id = str(config.get("chatId") or config.get("chat_id") or "").strip()
    if not token or not chat_id:
        raise ValueError("Telegram botToken 或 chatId 未配置")
    text = f"*{title}*\n{content}"[:4000]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    status, body = _http_json_post(
        url,
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        },
    )
    result = _safe_json(body)
    if not result.get("ok", True):
        raise ValueError(str(result.get("description") or f"Telegram 通知失败 (HTTP {status})"))


def _send_inapp(config: Dict[str, Any], title: str, content: str, level: str, meta: Dict[str, Any]) -> None:
    callback: Optional[Callable[..., Any]] = config.get("callback")
    if callable(callback):
        callback(title=title, content=content, level=level, meta=meta, config=config)
        return

    # Persist into inapp_notifications if db helpers are available via config.
    store = config.get("store")
    if callable(store):
        store(
            {
                "userId": config.get("userId"),
                "level": level,
                "title": title,
                "message": content,
                "status": "unread",
                "meta": meta or {},
            }
        )
        return

    user_id = config.get("userId")
    if user_id is None:
        raise ValueError("站内通知缺少 userId 或 callback")
    try:
        from app import conn, now_iso  # lazy to avoid circular import at module load
    except Exception as exc:
        raise ValueError(f"站内通知不可用: {exc}") from exc

    with conn() as c:
        c.execute(
            """
            INSERT INTO inapp_notifications (userId, level, title, message, status, meta, createdAt)
            VALUES (?, ?, ?, ?, 'unread', ?, ?)
            """,
            (
                int(user_id),
                str(level or "info")[:32],
                str(title or "")[:200],
                str(content or "")[:4000],
                json.dumps(meta or {}, ensure_ascii=False),
                now_iso(),
            ),
        )
        c.commit()


# ── public API ───────────────────────────────────────────────────────


def send_notification(
    channels: list[dict],
    title: str,
    content: str,
    level: str = "info",
    meta: dict | None = None,
) -> list[dict]:
    """Send a notification to multiple channels.

    Each channel: {"type": "email"|"webhook"|..., "config": {...}}
    Returns per-channel results: {channel, success, error?}.
    """
    results: List[Dict[str, Any]] = []
    meta_dict = meta if isinstance(meta, dict) else {}
    title_s = str(title or "DNS Panel 通知")
    content_s = str(content or "")
    level_s = str(level or "info")

    if not isinstance(channels, list):
        return [{"channel": "unknown", "success": False, "error": "channels 必须是数组"}]

    for item in channels:
        if not isinstance(item, dict):
            results.append({"channel": "unknown", "success": False, "error": "无效的渠道配置"})
            continue
        channel_type = str(item.get("type") or "").strip().lower()
        config = item.get("config") if isinstance(item.get("config"), dict) else {}
        if channel_type not in SUPPORTED_CHANNEL_TYPES:
            results.append({"channel": channel_type or "unknown", "success": False, "error": f"不支持的通知渠道: {channel_type}"})
            continue
        try:
            if channel_type == "email":
                _send_email(config, title_s, content_s)
            elif channel_type == "webhook":
                _send_webhook(config, title_s, content_s, level_s, meta_dict)
            elif channel_type == "wecom":
                _send_wecom(config, title_s, content_s)
            elif channel_type == "dingtalk":
                _send_dingtalk(config, title_s, content_s)
            elif channel_type == "feishu":
                _send_feishu(config, title_s, content_s)
            elif channel_type == "telegram":
                _send_telegram(config, title_s, content_s)
            elif channel_type == "inapp":
                _send_inapp(config, title_s, content_s, level_s, meta_dict)
            results.append({"channel": channel_type, "success": True})
        except Exception as exc:
            results.append({"channel": channel_type, "success": False, "error": str(exc)[:500]})
    return results


def _load_notification_settings_channels(user_id: int) -> List[Dict[str, Any]]:
    """Load per-user channel configs from notification_settings table."""
    try:
        from app import conn, decrypt_text  # lazy
    except Exception:
        return []
    try:
        with conn() as c:
            row = c.execute(
                "SELECT channels, enabled FROM notification_settings WHERE userId = ? LIMIT 1",
                (int(user_id),),
            ).fetchone()
        if not row or not bool(row["enabled"] if row["enabled"] is not None else 1):
            return []
        raw = row["channels"]
        if isinstance(raw, str) and ":" in raw and not raw.lstrip().startswith(("[", "{")):
            try:
                raw = decrypt_text(raw) or "[]"
            except Exception:
                pass
        data = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(data, list):
            return []
        out: List[Dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            ctype = str(item.get("type") or "").strip().lower()
            if ctype not in SUPPORTED_CHANNEL_TYPES:
                continue
            cfg = item.get("config") if isinstance(item.get("config"), dict) else {}
            if item.get("enabled") is False:
                continue
            out.append({"type": ctype, "config": dict(cfg)})
        return out
    except Exception:
        return []


def _load_ssl_notification_channels(user_id: int, user_row: Any) -> List[Dict[str, Any]]:
    """Build channels from SSL notification settings (system_settings)."""
    try:
        from app import decrypt_text, get_system_setting  # lazy
    except Exception:
        return []

    raw = get_system_setting(f"sslNotificationSettings:{int(user_id)}", "")
    if not raw:
        return []
    try:
        settings = json.loads(decrypt_text(raw) if raw else "{}")
    except Exception:
        try:
            settings = json.loads(raw)
        except Exception:
            return []
    if not isinstance(settings, dict) or not bool(settings.get("enabled")):
        return []

    channels: List[Dict[str, Any]] = []
    if bool(settings.get("emailEnabled")):
        password = ""
        smtp_pass = _row_get(user_row, "smtpPass")
        if smtp_pass:
            try:
                password = decrypt_text(smtp_pass)
            except Exception:
                password = str(smtp_pass)
        channels.append(
            {
                "type": "email",
                "config": {
                    "smtpHost": _row_get(user_row, "smtpHost"),
                    "smtpPort": _row_get(user_row, "smtpPort"),
                    "smtpSecure": _row_get(user_row, "smtpSecure"),
                    "smtpUser": _row_get(user_row, "smtpUser"),
                    "smtpPass": password,
                    "smtpFrom": _row_get(user_row, "smtpFrom"),
                    "to": settings.get("emailTo") or _row_get(user_row, "email") or "",
                },
            }
        )
    if bool(settings.get("webhookEnabled")) and str(settings.get("webhookUrl") or "").strip():
        channels.append(
            {
                "type": "webhook",
                "config": {"url": str(settings.get("webhookUrl") or "").strip()},
            }
        )
    if bool(settings.get("wecomEnabled")) and str(settings.get("wecomWebhookUrl") or "").strip():
        channels.append(
            {
                "type": "wecom",
                "config": {"url": str(settings.get("wecomWebhookUrl") or "").strip()},
            }
        )
    return channels


def _domain_expiry_channels(user_row: Any) -> List[Dict[str, Any]]:
    """Build channels from per-user domain-expiry notification settings."""
    channels: List[Dict[str, Any]] = []
    try:
        from app import decrypt_text  # lazy
    except Exception:
        decrypt_text = None  # type: ignore

    webhook_url = str(_row_get(user_row, "domainExpiryNotifyWebhookUrl") or "").strip()
    if bool(_row_get(user_row, "domainExpiryNotifyEnabled")) and webhook_url:
        channels.append({"type": "webhook", "config": {"url": webhook_url}})

    if bool(_row_get(user_row, "domainExpiryNotifyEmailEnabled")):
        password = ""
        smtp_pass = _row_get(user_row, "smtpPass")
        if smtp_pass and decrypt_text:
            try:
                password = decrypt_text(smtp_pass)
            except Exception:
                password = str(smtp_pass)
        elif smtp_pass:
            password = str(smtp_pass)
        channels.append(
            {
                "type": "email",
                "config": {
                    "smtpHost": _row_get(user_row, "smtpHost"),
                    "smtpPort": _row_get(user_row, "smtpPort"),
                    "smtpSecure": _row_get(user_row, "smtpSecure"),
                    "smtpUser": _row_get(user_row, "smtpUser"),
                    "smtpPass": password,
                    "smtpFrom": _row_get(user_row, "smtpFrom"),
                    "to": _row_get(user_row, "domainExpiryNotifyEmailTo")
                    or _row_get(user_row, "email")
                    or "",
                },
            }
        )
    return channels


def _dedupe_channels(channels: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for item in channels:
        ctype = str(item.get("type") or "")
        cfg = item.get("config") if isinstance(item.get("config"), dict) else {}
        # Identity key: type + primary endpoint field
        identity = (
            ctype,
            str(cfg.get("url") or cfg.get("webhookUrl") or ""),
            str(cfg.get("to") or cfg.get("emailTo") or ""),
            str(cfg.get("chatId") or ""),
            str(cfg.get("key") or ""),
            str(cfg.get("botToken") or cfg.get("token") or "")[:16],
            str(cfg.get("userId") or ""),
        )
        if identity in seen:
            continue
        seen.add(identity)
        out.append(item)
    return out


def build_user_channels(
    user_row_or_dict: Any,
    event: str = "",
    *,
    include_inapp: bool = True,
    inapp_callback: Optional[Callable[..., Any]] = None,
) -> List[Dict[str, Any]]:
    """Assemble notification channels for a user based on event context."""
    user_row = user_row_or_dict
    try:
        uid = int(_row_get(user_row, "id") or _row_get(user_row, "userId") or 0)
    except Exception:
        uid = 0

    event_name = str(event or "").strip().lower()
    channels: List[Dict[str, Any]] = []

    # Domain-expiry related events → user domain-expiry settings
    if event_name.startswith("domain_expiry") or event_name in {"expiry_warning", "domain_expiry_warning"}:
        channels.extend(_domain_expiry_channels(user_row))

    # SSL related events → SSL notification settings
    if event_name.startswith("ssl") or event_name in {"ssl_failure", "ssl_renewal_failed", "ssl_issue_failed", "ssl_deploy_failed"}:
        if uid > 0:
            channels.extend(_load_ssl_notification_channels(uid, user_row))

    # Always merge global per-user notification_settings channels
    if uid > 0:
        channels.extend(_load_notification_settings_channels(uid))

    # Fallback: if event is generic, still include domain-expiry + ssl channels
    if not event_name or event_name in {"notification", "alert", "sync_failure", "status_issue"}:
        if not any(c.get("type") == "email" for c in channels):
            # opportunistic: domain-expiry email path if configured
            for ch in _domain_expiry_channels(user_row):
                if ch not in channels:
                    channels.append(ch)
        if uid > 0 and event_name in {"sync_failure", "status_issue", "alert"}:
            # also pick SSL webhook/wecom if enabled as general hooks
            for ch in _load_ssl_notification_channels(uid, user_row):
                if ch.get("type") in {"webhook", "wecom"}:
                    channels.append(ch)

    if include_inapp and uid > 0:
        inapp_cfg: Dict[str, Any] = {"userId": uid}
        if callable(inapp_callback):
            inapp_cfg["callback"] = inapp_callback
        channels.append({"type": "inapp", "config": inapp_cfg})

    return _dedupe_channels(channels)


def notify_user(
    user_row_or_dict: Any,
    event: str,
    title: str,
    content: str,
    level: str = "info",
    meta: dict | None = None,
    *,
    include_inapp: bool = True,
    inapp_callback: Optional[Callable[..., Any]] = None,
    extra_channels: Optional[List[Dict[str, Any]]] = None,
) -> list[dict]:
    """Build channels from user/system/SSL settings and send.

    Returns per-channel delivery results.
    """
    channels = build_user_channels(
        user_row_or_dict,
        event,
        include_inapp=include_inapp,
        inapp_callback=inapp_callback,
    )
    if extra_channels:
        channels = _dedupe_channels(channels + list(extra_channels))

    meta_dict = dict(meta) if isinstance(meta, dict) else {}
    meta_dict.setdefault("event", event)
    try:
        from app import now_iso  # lazy

        meta_dict.setdefault("generatedAt", now_iso())
    except Exception:
        pass

    if not channels:
        return []
    return send_notification(channels, title, content, level=level, meta=meta_dict)


def append_dashboard_alert_event(
    uid: int,
    *,
    title: str,
    message: str,
    level: str = "medium",
    event_type: str | None = None,
) -> Dict[str, Any]:
    """Write an open alert into dashboard alert-events state (cache-backed)."""
    try:
        from app import MAX_EVENTS, make_id, now_iso, read_state, with_default_list, write_state
    except Exception as exc:
        raise RuntimeError(f"无法写入仪表盘告警: {exc}") from exc

    event = {
        "id": make_id("alert"),
        "level": level,
        "status": "open",
        "title": title,
        "message": message,
        "type": event_type,
        "createdAt": now_iso(),
    }
    items = with_default_list(read_state(uid, "alert-events", []))
    items.insert(0, event)
    write_state(uid, "alert-events", items[:MAX_EVENTS])
    return event


class NotificationService:
    """OO wrapper around the module-level helpers."""

    send = staticmethod(send_notification)
    notify_user = staticmethod(notify_user)
    build_user_channels = staticmethod(build_user_channels)
    append_dashboard_alert_event = staticmethod(append_dashboard_alert_event)
