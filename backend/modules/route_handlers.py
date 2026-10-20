#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List

from concurrent.futures import ThreadPoolExecutor
import csv
import time
import io
import ipaddress
import json
import socket
from datetime import datetime, timezone
import urllib.parse
import urllib.request
import urllib.error

from modules.cache import (
    cache_get, cache_set, cache_delete, cache_delete_pattern,
    zones_key, records_key, lines_key, providers_key,
    esa_sites_key, esa_records_key,
    acceleration_sites_key, acceleration_domains_key,
    ssl_certs_key, ssl_cert_detail_key, ssl_certs_all_key,
    dashboard_summary_key,
)
from modules import acme_api
from modules.acceleration_registry import AccelerationPluginError
from modules.aliyun_esa_api import (
    AliyunEsaError,
    apply_certificate as esa_apply_certificate,
    list_certificates_by_record as esa_list_certificates_by_record,
    list_records as esa_list_records,
    list_sites as esa_list_sites,
)
from modules.cloudflare_api import CloudflareApi
from modules.tencent_ssl_api import (
    TencentSslApi, TencentSslApiError, parse_certificate_datetime,
    certificate_days_remaining, certificate_is_expired,
)
from modules.qiniu_cdn_api import QiniuCdnApi, QiniuApiError
from modules.tencent_cdn_api import TencentPlatformApi
from modules.upyun_console_api import UpyunConsoleApi, UpyunConsoleError, upyun_validity_ms_to_iso
from modules.acme_api import AcmeService, AcmeApiError
from modules import dns_extras
from modules.notification import (
    send_notification,
    notify_user,
    sanitize_notification_channels,
    validate_webhook_url,
)

def attach_route_methods(handler_cls: type, env: Dict[str, Any]) -> None:
    method_names = [
        '_auth_routes',
        '_logs_routes',
        '_domain_expiry_routes',
        '_dns_credentials_routes',
        '_acceleration_routes',
        '_dns_records_routes',
        '_hostnames_routes',
        '_tunnels_routes',
        '_aliyun_esa_routes',
        '_dashboard',
        '_ssl_routes',
        '_api_tokens_routes',
        '_notifications_routes',
    ]
    for name in method_names:
        fn = globals().get(name)
        if callable(fn):
            fn.__globals__.update(env)
            setattr(handler_cls, name, fn)



def _is_registration_open() -> bool:
    raw = str(get_system_setting("registration_open", "0") or "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _append_dns_record_history(
    *,
    user_id: int,
    credential_id: int | None,
    zone_id: str | None,
    zone_name: str | None,
    record_id: str | None,
    record_name: str | None,
    record_type: str | None,
    action: str,
    old_value: Any = None,
    new_value: Any = None,
) -> None:
    """Best-effort insert into dns_record_history; no-op if table is missing."""
    try:
        if not table_exists("dns_record_history"):
            return
        old_s = None
        new_s = None
        if old_value is not None:
            old_s = old_value if isinstance(old_value, str) else json.dumps(old_value, ensure_ascii=False)
        if new_value is not None:
            new_s = new_value if isinstance(new_value, str) else json.dumps(new_value, ensure_ascii=False)
        with conn() as c:
            c.execute(
                """
                INSERT INTO dns_record_history (
                    userId, credentialId, zoneId, zoneName, recordId, recordName,
                    recordType, action, oldValue, newValue, createdAt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    int(user_id),
                    int(credential_id) if credential_id is not None else None,
                    str(zone_id) if zone_id is not None else None,
                    str(zone_name) if zone_name is not None else None,
                    str(record_id) if record_id is not None else None,
                    str(record_name) if record_name is not None else None,
                    str(record_type) if record_type is not None else None,
                    str(action or "").strip().upper() or "UPDATE",
                    old_s,
                    new_s,
                ),
            )
            c.commit()
    except Exception:
        pass

def _auth_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/auth") :] or "/"
    body = self._json_body(b)
    setup_complete = has_any_users()

    if self.command == "GET" and sub == "/setup-status":
        self._ok(setup_status_dict(), "获取初始化状态成功")
        return

    if self.command == "POST" and sub == "/setup":
        if setup_complete:
            self._err("系统已初始化，请直接登录", 409)
            return

        username = str(body.get("username") or "").strip()
        email_raw = str(body.get("email") or "").strip()
        email = email_raw if email_raw else None
        password = str(body.get("password") or "")

        if len(username) < 3:
            self._err("用户名至少 3 个字符", 400)
            return
        if not password_is_strong(password):
            self._err("密码必须至少 8 位，且包含大小写字母和数字", 400)
            return
        if email and not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            self._err("邮箱格式不正确", 400)
            return

        with conn() as c:
            existing = c.execute("SELECT id FROM users LIMIT 1").fetchone()
            if existing:
                self._err("系统已初始化，请直接登录", 409)
                return

            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
            c.execute(
                """
                INSERT INTO users (username, email, password, role, createdAt, updatedAt)
                VALUES (?, ?, ?, 'admin', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (username, email, hashed),
            )
            user_id = int(c.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])
            row = c.execute(
                """
                SELECT id, username, email, role, cfAccountId, twoFactorEnabled,
                       domainExpiryDisplayMode, domainExpiryThresholdDays,
                       domainExpiryNotifyEnabled, domainExpiryNotifyWebhookUrl,
                       domainExpiryNotifyEmailEnabled, domainExpiryNotifyEmailTo,
                       smtpHost, smtpPort, smtpSecure, smtpUser, smtpFrom, smtpPass,
                       createdAt, updatedAt
                FROM users WHERE id = ? LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            c.commit()

        set_system_setting("setup_complete", "1")
        set_system_setting("registration_open", "0")
        token = sign_access_token({"id": row["id"], "username": row["username"], "email": row["email"]})
        try:
            create_log(
                user_id=row["id"],
                action="CREATE",
                resource_type="USER",
                status="SUCCESS",
                record_name=row["username"],
                ip_address=self._client_ip(),
                new_value=json.dumps({"setup": True, "role": "admin"}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok({"token": token, "user": user_public_dict(row)}, "初始化完成", 201)
        return

    if self.command == "POST" and sub == "/register":
        if not setup_complete:
            self._err("系统尚未初始化，请先完成安装向导", 403)
            return
        if str(get_system_setting("registration_open", "0") or "0") != "1":
            self._err("公开注册已关闭", 403)
            return
        username = str(body.get("username") or "").strip()
        email_raw = str(body.get("email") or "").strip()
        email = email_raw if email_raw else None
        password = str(body.get("password") or "")
        if len(username) < 3:
            self._err("用户名至少 3 个字符", 400)
            return
        if not password_is_strong(password):
            self._err("密码必须至少 8 位，且包含大小写字母和数字", 400)
            return
        if email and not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            self._err("邮箱格式不正确", 400)
            return
        with conn() as c:
            exists = c.execute("SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1", (username, email or "")).fetchone()
            if exists:
                self._err("用户名或邮箱已存在", 409)
                return
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
            c.execute(
                """
                INSERT INTO users (username, email, password, role, createdAt, updatedAt)
                VALUES (?, ?, ?, 'user', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (username, email, hashed),
            )
            user_id = int(c.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])
            row = c.execute(
                """
                SELECT id, username, email, role, cfAccountId, twoFactorEnabled,
                       domainExpiryDisplayMode, domainExpiryThresholdDays,
                       domainExpiryNotifyEnabled, domainExpiryNotifyWebhookUrl,
                       domainExpiryNotifyEmailEnabled, domainExpiryNotifyEmailTo,
                       smtpHost, smtpPort, smtpSecure, smtpUser, smtpFrom, smtpPass,
                       createdAt, updatedAt
                FROM users WHERE id = ? LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            c.commit()
        self._ok({"user": user_public_dict(row)}, "注册成功", 201)
        return

    if self.command == "GET" and sub == "/registration-status":
        open_flag = str(get_system_setting("registration_open", "0") or "0") == "1"
        self._json(200, {"registrationOpen": open_flag, "open": open_flag, "setupComplete": setup_complete})
        return

    if self.command == "POST" and sub == "/login":
        if not setup_complete:
            self._err("系统尚未初始化，请先完成安装向导", 403)
            return

        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "")

        if not username or not password:
            self._err("缺少用户名或密码", 400)
            return

        with conn() as c:
            row = c.execute(
                """
                SELECT id, username, email, role, password, twoFactorEnabled,
                       domainExpiryDisplayMode, domainExpiryThresholdDays,
                       domainExpiryNotifyEnabled, domainExpiryNotifyWebhookUrl,
                       domainExpiryNotifyEmailEnabled, domainExpiryNotifyEmailTo,
                       smtpHost, smtpPort, smtpSecure, smtpUser, smtpFrom, smtpPass
                FROM users
                WHERE username = ? OR email = ?
                LIMIT 1
                """,
                (username, username),
            ).fetchone()

        if not row:
            self._err("用户名或密码错误", 401)
            return

        try:
            ok = bcrypt.checkpw(password.encode("utf-8"), str(row["password"]).encode("utf-8"))
        except Exception:
            ok = False
        if not ok:
            self._err("用户名或密码错误", 401)
            return

        if bool(row["twoFactorEnabled"]):
            temp = sign_access_token(
                {"id": row["id"], "username": row["username"], "type": "2fa_pending"},
                TEMP_2FA_EXPIRES_SECONDS,
            )
            self._ok({"requires2FA": True, "tempToken": temp}, "请输入两步验证码")
            return

        token = sign_access_token({"id": row["id"], "username": row["username"], "email": row["email"]})
        user = {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"] or "admin",
            "domainExpiryDisplayMode": row["domainExpiryDisplayMode"],
            "domainExpiryThresholdDays": row["domainExpiryThresholdDays"],
            "domainExpiryNotifyEnabled": bool(row["domainExpiryNotifyEnabled"]),
            "domainExpiryNotifyWebhookUrl": row["domainExpiryNotifyWebhookUrl"],
            "domainExpiryNotifyEmailEnabled": bool(row["domainExpiryNotifyEmailEnabled"]),
            "domainExpiryNotifyEmailTo": row["domainExpiryNotifyEmailTo"],
            "smtpHost": row["smtpHost"],
            "smtpPort": row["smtpPort"],
            "smtpSecure": bool(row["smtpSecure"]) if row["smtpSecure"] is not None else None,
            "smtpUser": row["smtpUser"],
            "smtpFrom": row["smtpFrom"],
            "smtpPassConfigured": bool(row["smtpPass"]),
        }
        self._ok({"token": token, "user": user}, "登录成功")
        return

    if self.command == "POST" and sub == "/2fa/verify":
        temp_token = str(body.get("tempToken") or "").strip()
        code = str(body.get("code") or "").strip()
        if not temp_token or not code:
            self._err("缺少验证参数", 400)
            return
        try:
            p = verify_jwt(temp_token)
        except Exception:
            self._err("验证已过期，请重新登录", 401)
            return
        if str(p.get("type") or "") != "2fa_pending":
            self._err("验证已过期，请重新登录", 401)
            return
        uid2 = int(p.get("id") or 0)
        if uid2 <= 0:
            self._err("验证已过期，请重新登录", 401)
            return

        with conn() as c:
            row = c.execute(
                """
                SELECT id, username, email, role, twoFactorSecret, twoFactorEnabled,
                       domainExpiryDisplayMode, domainExpiryThresholdDays,
                       domainExpiryNotifyEnabled, domainExpiryNotifyWebhookUrl,
                       domainExpiryNotifyEmailEnabled, domainExpiryNotifyEmailTo,
                       smtpHost, smtpPort, smtpSecure, smtpUser, smtpFrom, smtpPass
                FROM users WHERE id = ? LIMIT 1
                """,
                (uid2,),
            ).fetchone()
        if not row:
            self._err("用户不存在", 401)
            return
        if not bool(row["twoFactorEnabled"]) or not row["twoFactorSecret"]:
            self._err("2FA 未启用", 401)
            return
        secret = decrypt_text(row["twoFactorSecret"])
        if not verify_totp(secret, code, window=5):
            self._err("验证码错误", 401)
            return
        token = sign_access_token({"id": row["id"], "username": row["username"], "email": row["email"]})
        user = {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"] or "admin",
            "domainExpiryDisplayMode": row["domainExpiryDisplayMode"],
            "domainExpiryThresholdDays": row["domainExpiryThresholdDays"],
            "domainExpiryNotifyEnabled": bool(row["domainExpiryNotifyEnabled"]),
            "domainExpiryNotifyWebhookUrl": row["domainExpiryNotifyWebhookUrl"],
            "domainExpiryNotifyEmailEnabled": bool(row["domainExpiryNotifyEmailEnabled"]),
            "domainExpiryNotifyEmailTo": row["domainExpiryNotifyEmailTo"],
            "smtpHost": row["smtpHost"],
            "smtpPort": row["smtpPort"],
            "smtpSecure": bool(row["smtpSecure"]) if row["smtpSecure"] is not None else None,
            "smtpUser": row["smtpUser"],
            "smtpFrom": row["smtpFrom"],
            "smtpPassConfigured": bool(row["smtpPass"]),
        }
        self._ok({"token": token, "user": user}, "登录成功")
        return

    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return
    ip = self._client_ip()

    if self.command == "GET" and sub == "/me":
        with conn() as c:
            row = c.execute(
                """
                SELECT id, username, email, role, cfAccountId, twoFactorEnabled,
                       domainExpiryDisplayMode, domainExpiryThresholdDays,
                       domainExpiryNotifyEnabled, domainExpiryNotifyWebhookUrl,
                       domainExpiryNotifyEmailEnabled, domainExpiryNotifyEmailTo,
                       smtpHost, smtpPort, smtpSecure, smtpUser, smtpFrom, smtpPass,
                       createdAt, updatedAt
                FROM users WHERE id = ? LIMIT 1
                """,
                (uid,),
            ).fetchone()
        if not row:
            self._err("用户不存在", 400)
            return
        self._ok({"user": user_public_dict(row)}, "获取用户信息成功")
        return

    # GET /api/auth/system-settings — get global settings (authed)
    if self.command == "GET" and sub == "/system-settings":
        if not is_admin_user_id(uid):
            self._err("需要管理员权限", 403)
            return
        self._ok(system_settings_payload())
        return

    # PUT /api/auth/system-settings — update global settings (authed)
    if self.command == "PUT" and sub == "/system-settings":
        if not is_admin_user_id(uid):
            self._err("需要管理员权限", 403)
            return
        if "logRetentionDays" in body:
            retention = p_int(body.get("logRetentionDays"), get_log_retention_days(), 36500)
            set_system_setting("log_retention_days", str(retention))
            cleanup_logs_older_than(retention)
        if "retryMaxAttempts" in body:
            set_system_setting("retry_max_attempts", str(p_int(body.get("retryMaxAttempts"), get_retry_max_attempts(), 10)))
        if "retryIntervalSeconds" in body:
            set_system_setting("retry_interval_seconds", str(p_int(body.get("retryIntervalSeconds"), get_retry_interval_seconds(), 300)))
        if "retryTimeoutSeconds" in body:
            set_system_setting("retry_timeout_seconds", str(p_int(body.get("retryTimeoutSeconds"), get_retry_timeout_seconds(), 300)))
        if "backupSnapshotDir" in body:
            set_system_setting("backup_snapshot_dir", str(body.get("backupSnapshotDir") or "").strip() or "backups")
        if "backupFilePrefix" in body:
            set_system_setting("backup_file_prefix", sanitize_backup_file_prefix(str(body.get("backupFilePrefix") or "")))
        if "backupWriteServerCopy" in body:
            set_system_setting("backup_write_server_copy", "1" if bool(body.get("backupWriteServerCopy")) else "0")
        if "registrationOpen" in body:
            set_system_setting("registration_open", "1" if bool(body.get("registrationOpen")) else "0")
        self._ok(None, "系统设置已更新")
        return

    if self.command == "POST" and sub == "/backup/export":
        if not is_admin_user_id(uid):
            self._err("需要管理员权限", 403)
            return
        scopes_raw = body.get("scopes")
        scopes = scopes_raw if isinstance(scopes_raw, list) else ["dns", "ssl"]
        try:
            backup = export_backup_payload(uid, [str(scope) for scope in scopes])
        except ValueError as e:
            self._err(str(e), 400)
            return
        try:
            create_log(
                user_id=uid,
                action="EXPORT",
                resource_type="BACKUP",
                status="SUCCESS",
                record_name="manual_backup_export",
                ip_address=ip,
                new_value=json.dumps({"scopes": backup["scopes"]}, ensure_ascii=False),
            )
        except Exception:
            pass
        filename = build_backup_filename()
        snapshot_path = None
        snapshot_error = None
        if should_write_backup_server_copy():
            try:
                snapshot_path = write_backup_snapshot_file(backup, filename)
            except Exception as exc:
                snapshot_error = str(exc)
        payload = {"backup": backup, "filename": filename}
        if snapshot_path:
            payload["snapshotPath"] = snapshot_path
        if snapshot_error:
            payload["snapshotError"] = snapshot_error
        self._ok(payload, "备份已生成")
        return

    if self.command == "POST" and sub == "/backup/restore":
        if not is_admin_user_id(uid):
            self._err("需要管理员权限", 403)
            return
        scopes_raw = body.get("scopes")
        scopes = scopes_raw if isinstance(scopes_raw, list) else ["dns", "ssl"]
        overwrite = bool(body.get("overwrite", True))
        payload = body.get("payload")
        try:
            restored = restore_backup_payload(
                uid,
                payload if isinstance(payload, dict) else {},
                [str(scope) for scope in scopes],
                overwrite,
            )
        except ValueError as e:
            self._err(str(e), 400)
            return
        try:
            create_log(
                user_id=uid,
                action="RESTORE",
                resource_type="BACKUP",
                status="SUCCESS",
                record_name="manual_backup_restore",
                ip_address=ip,
                new_value=json.dumps(
                    {"scopes": [str(scope) for scope in scopes], "overwrite": overwrite, "restored": restored},
                    ensure_ascii=False,
                ),
            )
        except Exception:
            pass
        self._ok({"restored": restored}, "恢复完成")
        return

    if self.command == "GET" and sub == "/2fa/status":
        with conn() as c:
            row = c.execute("SELECT twoFactorEnabled, twoFactorSecret FROM users WHERE id = ? LIMIT 1", (uid,)).fetchone()
        if not row:
            self._err("用户不存在", 400)
            return
        self._ok({
            "enabled": bool(row["twoFactorEnabled"]),
            "hasSecret": bool(row["twoFactorSecret"]),
        }, "获取 2FA 状态成功")
        return

    if self.command == "POST" and sub == "/2fa/setup":
        with conn() as c:
            row = c.execute("SELECT username, twoFactorEnabled FROM users WHERE id = ? LIMIT 1", (uid,)).fetchone()
            if not row:
                self._err("用户不存在", 400)
                return
            if bool(row["twoFactorEnabled"]):
                self._err("2FA 已启用，请先禁用后再重新设置", 400)
                return
            secret = generate_base32_secret(20)
            c.execute(
                "UPDATE users SET twoFactorSecret = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?",
                (encrypt_text(secret), uid),
            )
            c.commit()
        otpauth = make_otpauth_url(secret, str(row["username"] or "user"), "DNS Panel")
        qr = make_qr_data_url(otpauth)
        try:
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="USER",
                status="SUCCESS",
                record_name=str(auth_user.get("username") or ""),
                ip_address=ip,
                new_value=json.dumps({"action": "2fa_setup"}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok({"secret": secret, "qrCodeDataUrl": qr}, "2FA 密钥生成成功")
        return

    if self.command == "POST" and sub == "/2fa/enable":
        code = str(body.get("code") or "").strip()
        password = str(body.get("password") or "")
        if not code:
            self._err("请输入验证码", 400)
            return
        if not password:
            self._err("请输入密码", 400)
            return
        with conn() as c:
            row = c.execute(
                "SELECT username, password, twoFactorSecret, twoFactorEnabled FROM users WHERE id = ? LIMIT 1",
                (uid,),
            ).fetchone()
            if not row:
                self._err("用户不存在", 400)
                return
            if bool(row["twoFactorEnabled"]):
                self._err("2FA 已启用", 400)
                return
            if not row["twoFactorSecret"]:
                self._err("请先生成 2FA 密钥", 400)
                return
            if not bcrypt.checkpw(password.encode("utf-8"), str(row["password"]).encode("utf-8")):
                self._err("密码错误", 400)
                return
            secret = decrypt_text(row["twoFactorSecret"])
            if not verify_totp(secret, code, window=5):
                self._err("验证码错误，请确认服务器时间与手机时间一致后重试", 400)
                return
            c.execute("UPDATE users SET twoFactorEnabled = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ?", (uid,))
            c.commit()
        try:
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="USER",
                status="SUCCESS",
                record_name=str(auth_user.get("username") or ""),
                ip_address=ip,
                new_value=json.dumps({"twoFactorEnabled": True}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok(None, "2FA 已启用")
        return

    if self.command == "POST" and sub == "/2fa/disable":
        password = str(body.get("password") or "")
        if not password:
            self._err("请输入密码", 400)
            return
        with conn() as c:
            row = c.execute(
                "SELECT username, password, twoFactorEnabled FROM users WHERE id = ? LIMIT 1",
                (uid,),
            ).fetchone()
            if not row:
                self._err("用户不存在", 400)
                return
            if not bool(row["twoFactorEnabled"]):
                self._err("2FA 未启用", 400)
                return
            if not bcrypt.checkpw(password.encode("utf-8"), str(row["password"]).encode("utf-8")):
                self._err("密码错误", 400)
                return
            c.execute(
                "UPDATE users SET twoFactorEnabled = 0, updatedAt = CURRENT_TIMESTAMP WHERE id = ?",
                (uid,),
            )
            c.commit()
        try:
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="USER",
                status="SUCCESS",
                record_name=str(auth_user.get("username") or ""),
                ip_address=ip,
                new_value=json.dumps({"twoFactorEnabled": False}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok(None, "2FA 已禁用")
        return

    if self.command == "PUT" and sub == "/password":
        old_password = str(body.get("oldPassword") or "")
        new_password = str(body.get("newPassword") or "")
        if not old_password or not new_password:
            self._err("缺少必需参数", 400)
            return
        if not password_is_strong(new_password):
            self._err("密码必须至少 8 位，且包含大小写字母和数字", 400)
            return

        with conn() as c:
            row = c.execute("SELECT id, username, password FROM users WHERE id = ? LIMIT 1", (uid,)).fetchone()
            if not row:
                self._err("用户不存在", 400)
                return
            if not bcrypt.checkpw(old_password.encode("utf-8"), str(row["password"]).encode("utf-8")):
                self._err("原密码错误", 400)
                return
            new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
            c.execute("UPDATE users SET password = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?", (new_hash, uid))
            c.commit()

        try:
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="USER",
                status="SUCCESS",
                record_name=str(auth_user.get("username") or ""),
                ip_address=ip,
                new_value=json.dumps({"passwordUpdated": True}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok(None, "密码修改成功")
        return

    if self.command == "PUT" and sub == "/cf-token":
        cf_api_token = str(body.get("cfApiToken") or "").strip()
        if not cf_api_token:
            self._err("缺少 API Token", 400)
            return
        enc = encrypt_text(cf_api_token)
        with conn() as c:
            c.execute("UPDATE users SET cfApiToken = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?", (enc, uid))
            c.commit()
        try:
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="USER",
                status="SUCCESS",
                record_name=str(auth_user.get("username") or ""),
                ip_address=ip,
                new_value=json.dumps({"cfTokenUpdated": True}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok(None, "API Token 更新成功")
        return

    if self.command == "PUT" and sub == "/domain-expiry-settings":
        display_mode = body.get("displayMode")
        threshold_days = body.get("thresholdDays")
        notify_enabled = body.get("notifyEnabled")
        webhook_url = body.get("webhookUrl")
        notify_email_enabled = body.get("notifyEmailEnabled")
        email_to = body.get("emailTo")
        smtp_host = body.get("smtpHost")
        smtp_port = body.get("smtpPort")
        smtp_secure = body.get("smtpSecure")
        smtp_user = body.get("smtpUser")
        smtp_pass = body.get("smtpPass")
        smtp_from = body.get("smtpFrom")

        if display_mode is not None and display_mode not in ("date", "days"):
            self._err("displayMode 仅支持 date 或 days", 400)
            return

        updates: Dict[str, Any] = {}
        if display_mode is not None:
            updates["domainExpiryDisplayMode"] = display_mode
        if threshold_days is not None:
            try:
                td = int(threshold_days)
            except Exception:
                self._err("阈值天数无效，应为 1-365 的整数", 400)
                return
            if td < 1 or td > 365:
                self._err("阈值天数无效，应为 1-365 的整数", 400)
                return
            updates["domainExpiryThresholdDays"] = td
        if notify_enabled is not None:
            updates["domainExpiryNotifyEnabled"] = 1 if bool(notify_enabled) else 0
        if webhook_url is not None:
            val = str(webhook_url).strip()
            updates["domainExpiryNotifyWebhookUrl"] = val if val else None
        if notify_email_enabled is not None:
            updates["domainExpiryNotifyEmailEnabled"] = 1 if bool(notify_email_enabled) else 0
        if email_to is not None:
            val = str(email_to).strip()
            if val and not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", val):
                self._err("收件邮箱格式不正确", 400)
                return
            updates["domainExpiryNotifyEmailTo"] = val if val else None

        if smtp_host is not None:
            val = str(smtp_host).strip()
            updates["smtpHost"] = val if val else None
            if not val:
                updates["smtpPort"] = None
                updates["smtpSecure"] = None
                updates["smtpUser"] = None
                updates["smtpPass"] = None
                updates["smtpFrom"] = None
        if smtp_port is not None:
            if smtp_port is None:
                updates["smtpPort"] = None
            else:
                try:
                    p = int(smtp_port)
                except Exception:
                    self._err("SMTP 端口无效，应为 1-65535 的整数", 400)
                    return
                if p < 1 or p > 65535:
                    self._err("SMTP 端口无效，应为 1-65535 的整数", 400)
                    return
                updates["smtpPort"] = p
        if smtp_secure is not None:
            updates["smtpSecure"] = 1 if bool(smtp_secure) else 0
        if smtp_user is not None:
            val = str(smtp_user).strip()
            updates["smtpUser"] = val if val else None
            if not val:
                updates["smtpPass"] = None
        if smtp_pass is not None:
            val = str(smtp_pass).strip()
            updates["smtpPass"] = encrypt_text(val) if val else None
        if smtp_from is not None:
            val = str(smtp_from).strip()
            updates["smtpFrom"] = val if val else None

        if not updates:
            with conn() as c:
                row = c.execute(
                    """
                    SELECT id, username, email, role, cfAccountId, twoFactorEnabled,
                           domainExpiryDisplayMode, domainExpiryThresholdDays,
                           domainExpiryNotifyEnabled, domainExpiryNotifyWebhookUrl,
                           domainExpiryNotifyEmailEnabled, domainExpiryNotifyEmailTo,
                           smtpHost, smtpPort, smtpSecure, smtpUser, smtpFrom, smtpPass,
                           createdAt, updatedAt
                    FROM users WHERE id = ? LIMIT 1
                    """,
                    (uid,),
                ).fetchone()
            if not row:
                self._err("用户不存在", 400)
                return
            self._ok({"user": user_public_dict(row)}, "设置已保存")
            return

        sets = ", ".join([f"{k} = ?" for k in updates.keys()] + ["updatedAt = CURRENT_TIMESTAMP"])
        values = list(updates.values()) + [uid]
        with conn() as c:
            c.execute(f"UPDATE users SET {sets} WHERE id = ?", values)
            row = c.execute(
                """
                SELECT id, username, email, role, cfAccountId, twoFactorEnabled,
                       domainExpiryDisplayMode, domainExpiryThresholdDays,
                       domainExpiryNotifyEnabled, domainExpiryNotifyWebhookUrl,
                       domainExpiryNotifyEmailEnabled, domainExpiryNotifyEmailTo,
                       smtpHost, smtpPort, smtpSecure, smtpUser, smtpFrom, smtpPass,
                       createdAt, updatedAt
                FROM users WHERE id = ? LIMIT 1
                """,
                (uid,),
            ).fetchone()
            c.commit()

        if not row:
            self._err("用户不存在", 400)
            return

        try:
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="USER",
                status="SUCCESS",
                record_name=str(auth_user.get("username") or ""),
                ip_address=ip,
                new_value=json.dumps({"action": "domain_expiry_settings"}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok({"user": user_public_dict(row)}, "设置已保存")
        return


def _logs_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/logs") :] or "/"
    body = self._json_body(b)
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return
    ip = self._client_ip()

    if self.command == "POST" and sub == "/access":
        page_path = str(body.get("path") or "").strip()
        if not page_path:
            self._err("缺少 path 参数", 400)
            return
        page_name = str(body.get("name") or "").strip() or page_path
        title = str(body.get("title") or "").strip() or None
        create_log(
            user_id=uid,
            action="ACCESS",
            resource_type="PAGE",
            status="SUCCESS",
            domain=page_path,
            record_name=page_name,
            new_value=json.dumps({"path": page_path, "name": page_name, "title": title}, ensure_ascii=False),
            ip_address=ip,
        )
        self._ok(None, "访问日志记录成功")
        return

    if self.command == "GET" and sub == "/":
        cleanup_logs_older_than(get_log_retention_days())
        page = p_int(first_or_none(q, "page") or "1", 1, 100000)
        limit = p_int(first_or_none(q, "limit") or "50", 50, 500)
        start_date = first_or_none(q, "startDate")
        end_date = first_or_none(q, "endDate")
        action = first_or_none(q, "action")
        resource_type = first_or_none(q, "resourceType")
        domain = first_or_none(q, "domain")
        status = first_or_none(q, "status")
        offset = (page - 1) * limit

        wheres = ["userId = ?"]
        params: List[Any] = [uid]
        if start_date:
            dt = parse_dt(start_date)
            if dt:
                wheres.append("datetime(timestamp) >= datetime(?)")
                params.append(dt.isoformat().replace("+00:00", "Z"))
        if end_date:
            dt = parse_dt(end_date)
            if dt:
                wheres.append("datetime(timestamp) <= datetime(?)")
                params.append(dt.isoformat().replace("+00:00", "Z"))
        if action:
            wheres.append("action = ?")
            params.append(action)
        if resource_type:
            wheres.append("resourceType = ?")
            params.append(resource_type)
        if domain:
            wheres.append("domain LIKE ?")
            params.append(f"%{domain}%")
        if status:
            wheres.append("status = ?")
            params.append(status)

        where_sql = " AND ".join(wheres)
        with conn() as c:
            total = c.execute(f"SELECT COUNT(*) c FROM logs WHERE {where_sql}", params).fetchone()["c"]
            rows = c.execute(
                f"""
                SELECT id, userId, timestamp, action, resourceType, domain, recordName,
                       recordType, oldValue, newValue, status, errorMessage, ipAddress
                FROM logs
                WHERE {where_sql}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            ).fetchall()

        data = []
        for r in rows:
            ts = parse_dt(r["timestamp"])
            data.append(
                {
                    "id": r["id"],
                    "userId": r["userId"],
                    "timestamp": ts.isoformat().replace("+00:00", "Z") if ts else str(r["timestamp"]),
                    "action": r["action"],
                    "resourceType": r["resourceType"],
                    "domain": r["domain"],
                    "recordName": r["recordName"],
                    "recordType": r["recordType"],
                    "oldValue": r["oldValue"],
                    "newValue": r["newValue"],
                    "status": r["status"],
                    "errorMessage": r["errorMessage"],
                    "ipAddress": r["ipAddress"],
                }
            )

        self._paged(data, int(total), page, limit, "获取日志成功")
        return

    if self.command == "DELETE" and sub == "/clear":
        with conn() as c:
            count = c.execute("SELECT COUNT(*) c FROM logs WHERE userId = ?", (uid,)).fetchone()["c"]
            c.execute("DELETE FROM logs WHERE userId = ?", (uid,))
            c.commit()
        try:
            create_log(
                user_id=uid,
                action="DELETE",
                resource_type="USER",
                record_name="clear_logs",
                status="SUCCESS",
                ip_address=ip,
                new_value=json.dumps({"deleted": int(count)}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok({"count": int(count)}, f"已清空 {int(count)} 条日志")
        return

    if self.command == "DELETE" and sub == "/cleanup":
        retention = p_int(first_or_none(q, "retentionDays") or str(get_log_retention_days()), get_log_retention_days(), 36500)
        count = cleanup_logs_older_than(retention)
        try:
            create_log(
                user_id=uid,
                action="DELETE",
                resource_type="USER",
                record_name="cleanup_logs",
                status="SUCCESS",
                ip_address=ip,
                new_value=json.dumps({"retentionDays": str(retention), "deleted": int(count)}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok({"count": int(count)}, f"已清理 {int(count)} 条过期日志")
        return

    self._err("接口不存在", 404)


def _domain_expiry_days_remaining(expires_at: Any) -> int | None:
    exp = parse_dt(expires_at)
    if not exp:
        return None
    seconds = (exp - now()).total_seconds()
    if seconds < 0:
        return None
    return int((seconds + 86399) // 86400)


def _split_email_recipients(value: Any) -> List[str]:
    recipients: List[str] = []
    seen = set()
    for item in re.split(r"[,;\s]+", str(value or "").strip()):
        email = item.strip()
        if not email or "@" not in email or email.lower() in seen:
            continue
        seen.add(email.lower())
        recipients.append(email)
    return recipients


def _domain_expiry_payload(user_row: Any, due_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    domains = []
    for item in due_results:
        expires_at = str(item.get("expiresAt") or "")
        domains.append(
            {
                "domain": item["domain"],
                "expiresAt": expires_at,
                "daysRemaining": item.get("daysRemaining"),
                "source": item.get("source") or "unknown",
                "checkedAt": item.get("checkedAt") or now_iso(),
            }
        )
    threshold = int(user_row["domainExpiryThresholdDays"] or 7)
    return {
        "event": "domain_expiry_warning",
        "thresholdDays": threshold,
        "count": len(domains),
        "domains": domains,
        "generatedAt": now_iso(),
    }


def _send_domain_expiry_webhook(url: str, payload: Dict[str, Any]) -> None:
    target = validate_webhook_url(url)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        target,
        method="POST",
        data=data,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "dns-panel-domain-expiry/1.0",
        },
    )
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
            raise ValueError("Webhook URL 不允许 HTTP 重定向")

    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=10) as resp:
            if int(getattr(resp, "status", 200)) < 200 or int(getattr(resp, "status", 200)) >= 300:
                raise ValueError(f"Webhook 返回 HTTP {getattr(resp, 'status', 0)}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
        raise ValueError(f"Webhook 返回 HTTP {exc.code}: {raw[:200]}")


def _send_domain_expiry_email(user_row: Any, payload: Dict[str, Any]) -> None:
    import smtplib
    from email.message import EmailMessage

    host = str(user_row["smtpHost"] or "").strip()
    port = int(user_row["smtpPort"] or (465 if bool(user_row["smtpSecure"]) else 587))
    secure = bool(user_row["smtpSecure"])
    username = str(user_row["smtpUser"] or "").strip()
    password = decrypt_text(user_row["smtpPass"]) if user_row["smtpPass"] else ""
    sender = str(user_row["smtpFrom"] or username or "").strip()
    recipients = _split_email_recipients(user_row["domainExpiryNotifyEmailTo"])
    if not host:
        raise ValueError("SMTP 服务器未配置")
    if not sender:
        raise ValueError("发件人未配置")
    if not recipients:
        raise ValueError("收件邮箱未配置")

    domains = payload.get("domains") if isinstance(payload.get("domains"), list) else []
    lines = [
        f"DNS Panel 检测到 {len(domains)} 个域名即将到期。",
        "",
    ]
    for item in domains:
        if not isinstance(item, dict):
            continue
        lines.append(f"- {item.get('domain')}：{item.get('expiresAt')}（剩余 {item.get('daysRemaining')} 天）")
    lines.extend(["", f"检查时间：{payload.get('generatedAt')}"])

    msg = EmailMessage()
    msg["Subject"] = f"DNS Panel 域名到期提醒（{len(domains)} 个）"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content("\n".join(lines))

    if secure or port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)
        return

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if port == 587:
            smtp.starttls()
        if username:
            smtp.login(username, password)
        smtp.send_message(msg)


def _upsert_domain_expiry_tracking(uid: int, item: Dict[str, Any], days_remaining: int) -> None:
    domain = norm_domain(item.get("domain"))
    expires_at = str(item.get("expiresAt") or "").strip()
    if not domain or not expires_at:
        return
    with conn() as c:
        c.execute(
            """
            INSERT INTO domain_expiry_notifications (
              userId, domain, expiresAt, daysRemaining, channels, status,
              createdAt, updatedAt
            )
            VALUES (?, ?, ?, ?, ?, 'tracked', ?, ?)
            ON CONFLICT(userId, domain, expiresAt) DO UPDATE SET
              daysRemaining = excluded.daysRemaining,
              updatedAt = excluded.updatedAt
            """,
            (
                uid,
                domain,
                expires_at,
                days_remaining,
                json.dumps([], ensure_ascii=False),
                now_iso(),
                now_iso(),
            ),
        )
        c.commit()


def _delete_stale_domain_expiry_tracking(uid: int, item: Dict[str, Any]) -> None:
    domain = norm_domain(item.get("domain"))
    expires_at = str(item.get("expiresAt") or "").strip()
    if not domain or not expires_at:
        return
    with conn() as c:
        c.execute(
            """
            DELETE FROM domain_expiry_notifications
            WHERE userId = ? AND domain = ? AND expiresAt != ?
            """,
            (uid, domain, expires_at),
        )
        c.commit()


def _select_domain_expiry_tracking(uid: int, item: Dict[str, Any]) -> Any:
    domain = norm_domain(item.get("domain"))
    expires_at = str(item.get("expiresAt") or "").strip()
    if not domain or not expires_at:
        return None
    with conn() as c:
        return c.execute(
            """
            SELECT id, status, lastNotifiedAt
            FROM domain_expiry_notifications
            WHERE userId = ? AND domain = ? AND expiresAt = ?
            LIMIT 1
            """,
            (uid, domain, expires_at),
        ).fetchone()


def _mark_domain_expiry_delivery(uid: int, due_results: List[Dict[str, Any]], status: str, deliveries: List[Dict[str, Any]]) -> None:
    channels = json.dumps(deliveries, ensure_ascii=False)
    errors = "; ".join(str(item.get("error") or "") for item in deliveries if item.get("error")) or None
    notified_at = now_iso() if status in {"sent", "partial"} else None
    with conn() as c:
        for item in due_results:
            domain = norm_domain(item.get("domain"))
            expires_at = str(item.get("expiresAt") or "").strip()
            if not domain or not expires_at:
                continue
            c.execute(
                """
                UPDATE domain_expiry_notifications
                SET status = ?, channels = ?, errorMessage = ?, lastNotifiedAt = COALESCE(?, lastNotifiedAt),
                    updatedAt = ?
                WHERE userId = ? AND domain = ? AND expiresAt = ?
                """,
                (status, channels, errors, notified_at, now_iso(), uid, domain, expires_at),
            )
        c.commit()


# Alert windows (days remaining buckets). A domain is alerted when remaining
# days falls into one of these buckets, with 24h dedup per domain+bucket.
DOMAIN_EXPIRY_ALERT_WINDOWS = (30, 15, 7, 3, 1)


def _domain_expiry_threshold_bucket(days_remaining: int) -> int | None:
    """Map remaining days to the tightest matching alert window bucket."""
    matched = None
    for window in DOMAIN_EXPIRY_ALERT_WINDOWS:
        if days_remaining <= window:
            matched = window
    return matched


def _domain_expiry_notified_recently(last_notified_at: Any, hours: int = 24) -> bool:
    if not last_notified_at:
        return False
    dt = parse_dt(last_notified_at)
    if not dt:
        return False
    return (now() - dt).total_seconds() < max(1, hours) * 3600


def _fire_expiry_warning_alert_rules(uid: int, due: List[Dict[str, Any]]) -> int:
    """Fire dashboard alert-rules of type expiry_warning (inapp events only).

    External channels (email/webhook/...) are delivered once by
    `_process_domain_expiry_notifications` via NotificationService, so this
    helper intentionally only writes dashboard alert-events to avoid duplicates.
    Returns the number of rules that fired.
    """
    if not due:
        return 0
    try:
        from modules.notification import append_dashboard_alert_event
    except Exception:
        append_dashboard_alert_event = None  # type: ignore

    rules = with_default_list(read_state(uid, "alert-rules", []))
    if not rules:
        rules = dflt_rules()
        write_state(uid, "alert-rules", rules)

    min_days = min(int(item.get("daysRemaining") or 9999) for item in due)
    fired = 0
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("enabled", True):
            continue
        if str(rule.get("type") or "") != "expiry_warning":
            continue
        threshold = rule.get("threshold")
        try:
            thr = int(threshold) if threshold is not None else 7
        except Exception:
            thr = 7
        matching = [d for d in due if int(d.get("daysRemaining") or 9999) <= thr]
        if not matching:
            continue
        targets = matching
        title = str(rule.get("name") or "到期预警告警")
        lines = [f"{item.get('domain')}（剩余 {item.get('daysRemaining')} 天）" for item in targets[:20]]
        message = f"检测到 {len(targets)} 个域名即将到期：\n" + "\n".join(lines)

        channels = [str(x).strip() for x in (rule.get("channels") if isinstance(rule.get("channels"), list) else ["inapp"])]
        # Write inapp dashboard event when rule includes inapp (default) or has no channels.
        if "inapp" in channels or not channels:
            try:
                if append_dashboard_alert_event:
                    append_dashboard_alert_event(
                        uid,
                        title=title,
                        message=message,
                        level="high" if min_days <= 3 else "medium",
                        event_type="expiry_warning",
                    )
                else:
                    ev = with_default_list(read_state(uid, "alert-events", []))
                    ev.insert(
                        0,
                        {
                            "id": make_id("expiry-alert"),
                            "level": "high" if min_days <= 3 else "medium",
                            "status": "open",
                            "title": title,
                            "message": message,
                            "type": "expiry_warning",
                            "createdAt": now_iso(),
                        },
                    )
                    write_state(uid, "alert-events", ev[:MAX_EVENTS])
                fired += 1
            except Exception:
                pass
        else:
            # Rule exists and matched but only external channels — still count as fired
            # so caller can mark lastNotifiedAt; external send is done elsewhere.
            fired += 1
    return fired


def _process_domain_expiry_notifications(uid: int, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    with conn() as c:
        user_row = c.execute(
            """
            SELECT id, username, email,
                   domainExpiryThresholdDays, domainExpiryNotifyEnabled,
                   domainExpiryNotifyWebhookUrl, domainExpiryNotifyEmailEnabled,
                   domainExpiryNotifyEmailTo, smtpHost, smtpPort, smtpSecure,
                   smtpUser, smtpPass, smtpFrom
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (uid,),
        ).fetchone()
    if not user_row:
        return {"tracked": 0, "notified": 0}

    threshold = int(user_row["domainExpiryThresholdDays"] or 7)
    # Always track up to the widest alert window (30d) or user threshold, whichever is larger.
    track_window = max(30, threshold, max(DOMAIN_EXPIRY_ALERT_WINDOWS))
    tracked = 0
    due: List[Dict[str, Any]] = []

    for item in results:
        if not isinstance(item, dict):
            continue
        expires_at = str(item.get("expiresAt") or "").strip()
        if not expires_at:
            continue
        days = _domain_expiry_days_remaining(expires_at)
        if days is None:
            continue
        normalized = {
            **item,
            "domain": norm_domain(item.get("domain")),
            "expiresAt": expires_at,
            "daysRemaining": days,
        }
        _delete_stale_domain_expiry_tracking(uid, normalized)
        if days <= track_window:
            _upsert_domain_expiry_tracking(uid, normalized, days)
            tracked += 1

        bucket = _domain_expiry_threshold_bucket(days)
        # Also honour the user-configured threshold as an additional trigger.
        should_alert = bucket is not None or days <= threshold
        if not should_alert:
            continue

        row = _select_domain_expiry_tracking(uid, normalized)
        # Dedup: skip if last notified within 24h for the same domain+threshold bucket.
        if row and _domain_expiry_notified_recently(row["lastNotifiedAt"], hours=24):
            continue
        # Legacy: status sent/partial without recent timestamp still re-notify after 24h only.
        if row and str(row["status"] or "") in {"sent", "partial"} and row["lastNotifiedAt"] and _domain_expiry_notified_recently(row["lastNotifiedAt"], hours=24):
            continue
        normalized["alertBucket"] = bucket if bucket is not None else threshold
        due.append(normalized)

    cache_delete_pattern(dashboard_summary_key(uid))

    if not due:
        return {"tracked": tracked, "notified": 0}

    # Fire dashboard alert rules (inapp events only; external channels sent below)
    alert_fired = 0
    try:
        alert_fired = int(_fire_expiry_warning_alert_rules(uid, due) or 0)
    except Exception:
        alert_fired = 0

    # Deliver via unified notification service (domain-expiry channels + optional extras)
    deliveries: List[Dict[str, Any]] = []
    if alert_fired > 0:
        deliveries.append({"channel": "inapp", "status": "success", "success": True})
    try:
        from modules.notification import notify_user

        payload = _domain_expiry_payload(user_row, due)
        lines = [
            f"DNS Panel 检测到 {len(due)} 个域名即将到期。",
            "",
        ]
        for item in due[:50]:
            lines.append(
                f"- {item.get('domain')}：{item.get('expiresAt')}（剩余 {item.get('daysRemaining')} 天）"
            )
        lines.extend(["", f"检查时间：{payload.get('generatedAt')}"])
        content = "\n".join(lines)
        title = f"DNS Panel 域名到期提醒（{len(due)} 个）"

        # inapp/alert-events already handled by _fire_expiry_warning_alert_rules
        raw_results = notify_user(
            user_row,
            "domain_expiry_warning",
            title,
            content,
            level="warning",
            meta=payload,
            include_inapp=False,
        )
        for item in raw_results or []:
            if not isinstance(item, dict):
                continue
            deliveries.append(
                {
                    "channel": item.get("channel"),
                    "status": "success" if item.get("success") else "failed",
                    "success": bool(item.get("success")),
                    "error": item.get("error"),
                }
            )
    except Exception as exc:
        # Fallback to legacy per-channel senders so existing configs keep working.
        webhook_url = str(user_row["domainExpiryNotifyWebhookUrl"] or "").strip()
        if bool(user_row["domainExpiryNotifyEnabled"]) and webhook_url:
            try:
                _send_domain_expiry_webhook(webhook_url, _domain_expiry_payload(user_row, due))
                deliveries.append({"channel": "webhook", "status": "success", "success": True})
            except Exception as wexc:
                deliveries.append({"channel": "webhook", "status": "failed", "success": False, "error": str(wexc)})
        if bool(user_row["domainExpiryNotifyEmailEnabled"]):
            try:
                _send_domain_expiry_email(user_row, _domain_expiry_payload(user_row, due))
                deliveries.append({"channel": "email", "status": "success", "success": True})
            except Exception as eexc:
                deliveries.append({"channel": "email", "status": "failed", "success": False, "error": str(eexc)})
        if not deliveries:
            deliveries.append({"channel": "notification", "status": "failed", "success": False, "error": str(exc)})

    if not deliveries:
        return {"tracked": tracked, "notified": 0, "due": len(due)}

    success_count = sum(1 for item in deliveries if item.get("status") == "success" or item.get("success"))
    if success_count == len(deliveries):
        delivery_status = "sent"
    elif success_count > 0:
        delivery_status = "partial"
    else:
        delivery_status = "failed"
    _mark_domain_expiry_delivery(uid, due, delivery_status, deliveries)

    try:
        create_log(
            user_id=uid,
            action="NOTIFY",
            resource_type="DOMAIN_EXPIRY",
            status="SUCCESS" if success_count > 0 else "FAILED",
            record_name="domain_expiry_warning",
            new_value=json.dumps(
                {
                    "count": len(due),
                    "channels": deliveries,
                    "thresholdDays": threshold,
                },
                ensure_ascii=False,
            ),
            error_message="; ".join(str(item.get("error") or "") for item in deliveries if item.get("error")) or None,
        )
    except Exception:
        pass
    return {"tracked": tracked, "notified": len(due), "deliveryStatus": delivery_status}


def append_inapp_via_dashboard(uid: int, kwargs: Dict[str, Any]) -> None:
    """Bridge inapp channel → dashboard alert-events + inapp_notifications table."""
    title = str(kwargs.get("title") or "通知")
    content = str(kwargs.get("content") or "")
    level = str(kwargs.get("level") or "info")
    meta = kwargs.get("meta") if isinstance(kwargs.get("meta"), dict) else {}
    try:
        from modules.notification import append_dashboard_alert_event

        append_dashboard_alert_event(
            uid,
            title=title,
            message=content,
            level="high" if level in {"error", "critical", "high"} else ("medium" if level in {"warning", "warn"} else "low"),
            event_type=str(meta.get("event") or "notification"),
        )
    except Exception:
        try:
            ev = with_default_list(read_state(uid, "alert-events", []))
            ev.insert(
                0,
                {
                    "id": make_id("inapp"),
                    "level": "medium",
                    "status": "open",
                    "title": title,
                    "message": content,
                    "createdAt": now_iso(),
                },
            )
            write_state(uid, "alert-events", ev[:MAX_EVENTS])
        except Exception:
            pass
    try:
        with conn() as c:
            c.execute(
                """
                INSERT INTO inapp_notifications (userId, level, title, message, status, meta, createdAt)
                VALUES (?, ?, ?, ?, 'unread', ?, ?)
                """,
                (
                    uid,
                    level[:32],
                    title[:200],
                    content[:4000],
                    json.dumps(meta, ensure_ascii=False),
                    now_iso(),
                ),
            )
            c.commit()
    except Exception:
        pass


def _domain_expiry_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/domain-expiry") :] or "/"
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)

    if self.command == "POST" and sub == "/lookup":
        body = self._json_body(b)
        domains_input = body.get("domains")
        if not isinstance(domains_input, list) or len(domains_input) == 0:
            self._err("缺少参数: domains (string[])", 400)
            return
        if len(domains_input) > 500:
            self._err("domains 数量过多，最多 500 条", 400)
            return

        unique: List[str] = []
        seen = set()
        for item in domains_input:
            d = norm_domain(item)
            if not d or d in seen:
                continue
            seen.add(d)
            unique.append(d)
        # RDAP lookups are network-bound (up to 20s each); fan out in parallel
        # so N domains finish in ~max(latency) instead of sum(latency).
        if unique:
            workers = min(len(unique), 12)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(self._lookup_domain_expiry_single, unique))
        else:
            results = []
        notify_summary: Dict[str, Any] = {}
        try:
            if uid > 0:
                notify_summary = _process_domain_expiry_notifications(uid, results) or {}
        except Exception:
            pass
        self._ok({"results": results, "notify": notify_summary}, "获取域名到期信息成功")
        return

    if self.command == "POST" and sub == "/scan":
        if uid <= 0:
            self._err("认证失败", 401)
            return
        try:
            summary = _scan_user_domain_expiry(self, uid)
        except Exception as exc:
            self._err(f"域名到期扫描失败: {exc}", 500)
            return
        self._ok(summary, "域名到期扫描完成")
        return

    if self.command == "GET" and sub == "/tracked":
        if uid <= 0:
            self._err("认证失败", 401)
            return
        page = p_int((q.get("page") or ["1"])[0], 1, 100000)
        limit = p_int((q.get("limit") or ["50"])[0], 50, 200)
        with conn() as c:
            total = c.execute(
                "SELECT COUNT(*) AS c FROM domain_expiry_notifications WHERE userId = ?",
                (uid,),
            ).fetchone()["c"]
            rows = c.execute(
                """
                SELECT id, domain, expiresAt, daysRemaining, channels, status,
                       errorMessage, lastNotifiedAt, createdAt, updatedAt
                FROM domain_expiry_notifications
                WHERE userId = ?
                ORDER BY datetime(expiresAt) ASC, domain ASC
                LIMIT ? OFFSET ?
                """,
                (uid, limit, (page - 1) * limit),
            ).fetchall()
        items = []
        for row in rows:
            channels_raw = row["channels"]
            try:
                channels = json.loads(channels_raw) if channels_raw else []
            except Exception:
                channels = []
            items.append(
                {
                    "id": row["id"],
                    "domain": row["domain"],
                    "expiresAt": row["expiresAt"],
                    "daysRemaining": row["daysRemaining"],
                    "channels": channels,
                    "status": row["status"],
                    "errorMessage": row["errorMessage"],
                    "lastNotifiedAt": row["lastNotifiedAt"],
                    "createdAt": row["createdAt"],
                    "updatedAt": row["updatedAt"],
                }
            )
        self._ok({"items": items, "total": int(total or 0), "page": page, "limit": limit}, "获取跟踪域名成功")
        return

    self._err("接口不存在", 404)


def _collect_user_zone_domains(handler: Any, uid: int) -> List[str]:
    """List zone apex domains from all DNS record-management credentials for a user."""
    domains: List[str] = []
    seen = set()
    with conn() as c:
        rows = c.execute(
            f"""
            SELECT *
            FROM dns_credentials
            WHERE userId = ? AND provider IN ({SUPPORTED_DNS_RECORD_PROVIDER_SQL})
            ORDER BY provider ASC, isDefault DESC, createdAt ASC, id ASC
            """,
            (uid, *SUPPORTED_DNS_RECORD_PROVIDER_TYPES),
        ).fetchall()
    for row in rows:
        cred_id = int(row["id"])
        provider = str(row["provider"] or "").strip().lower()
        try:
            ctx = handler._dns_context(uid, {"credentialId": [str(cred_id)]})
            page = 1
            page_size = 100
            while page <= 20:
                if provider == "cloudflare":
                    result = ctx["cf"].list_zones(page, page_size, None)
                    zones_raw = result.get("zones") if isinstance(result, dict) else []
                    zones = [handler._map_cf_zone(z) for z in zones_raw if isinstance(z, dict)]
                elif provider in ("dnspod", "dnspod_token"):
                    result = ctx["dnspod"].list_zones(page, page_size, None)
                    zones_raw = result.get("zones") if isinstance(result, dict) else []
                    zones = [handler._map_dnspod_zone(z) for z in zones_raw if isinstance(z, dict)]
                else:
                    break
                if not zones:
                    break
                for zone in zones:
                    name = norm_domain(zone.get("name") if isinstance(zone, dict) else "")
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    domains.append(name)
                total = int(result.get("total") or 0) if isinstance(result, dict) else len(zones)
                if page * page_size >= total or len(zones) < page_size:
                    break
                page += 1
        except Exception:
            continue
    return domains


def _scan_user_domain_expiry(handler: Any, uid: int) -> Dict[str, Any]:
    """Collect domains for a user, RDAP-lookup, track and notify."""
    domains = _collect_user_zone_domains(handler, uid)
    results: List[Dict[str, Any]] = []
    if domains:
        workers = min(len(domains), 12)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(handler._lookup_domain_expiry_single, domains))
    notify_summary: Dict[str, Any] = {}
    try:
        notify_summary = _process_domain_expiry_notifications(uid, results) or {}
    except Exception as exc:
        notify_summary = {"error": str(exc)}
    return {
        "scanned": len(domains),
        "domains": domains,
        "results": results,
        "notify": notify_summary,
    }


def _dns_credentials_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/dns-credentials") :] or "/"
    body = self._json_body(b)
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return
    ip = self._client_ip()

    def _provider_types_for_category(category: str | None) -> tuple[str, ...]:
        normalized = str(category or "dns").strip().lower() or "dns"
        if normalized == "all":
            return SUPPORTED_PROVIDER_TYPES
        if normalized == "dns":
            return SUPPORTED_DNS_PROVIDER_TYPES
        if normalized == "ssl":
            return SUPPORTED_SSL_PROVIDER_TYPES
        if normalized == "acceleration":
            return SUPPORTED_ACCELERATION_PROVIDER_TYPES
        if normalized == "cert_upload":
            return SUPPORTED_CERT_UPLOAD_PROVIDER_TYPES
        raise ValueError("无效的 category 参数，仅支持 dns / ssl / acceleration / cert_upload / all")

    def _provider_sql(provider_types: tuple[str, ...]) -> str:
        return ", ".join("?" for _ in provider_types)

    def _provider_category(provider: str) -> str:
        caps = get_provider_capabilities(provider) or {}
        return str(caps.get("category") or "dns").strip().lower() or "dns"

    def _validate_credential_secrets(provider: str, raw_secrets: Any) -> Dict[str, str]:
        if not isinstance(raw_secrets, dict):
            raise ValueError("缺少必需参数: secrets")
        clean: Dict[str, str] = {}
        for key, value in raw_secrets.items():
            if key is None:
                continue
            text = str(value or "").strip()
            if text:
                clean[str(key)] = text

        if provider == "dnspod":
            has_tc3 = bool(clean.get("secretId") and clean.get("secretKey"))
            has_tc3_partial = bool(clean.get("secretId") or clean.get("secretKey"))
            has_token = bool(
                (clean.get("tokenId") and clean.get("token"))
                or (not clean.get("tokenId") and clean.get("token") and "," in str(clean.get("token") or ""))
            )
            has_token_partial = bool(clean.get("tokenId") or clean.get("token"))
            if not has_tc3 and not has_token:
                raise ValueError("DNSPod 凭证需提供 SecretId/SecretKey 或 TokenId/Token")
            if has_tc3_partial and not has_tc3:
                raise ValueError("SecretId/SecretKey 需要同时填写")
            if has_token_partial and not has_token:
                raise ValueError("DNSPod Token 请填写 TokenId + Token，或在 Token 中使用 ID,Token 组合格式")
            return clean

        caps = get_provider_capabilities(provider)
        if not caps:
            raise ValueError(f"不支持的提供商: {provider}")
        fields = caps.get("authFields") if isinstance(caps.get("authFields"), list) else []
        required_fields = [
            str(field.get("name") or field.get("key") or "").strip()
            for field in fields
            if isinstance(field, dict) and bool(field.get("required"))
        ]
        missing = [key for key in required_fields if not clean.get(key)]
        if missing:
            raise ValueError(f"缺少字段: {', '.join(missing)}")
        return clean

    def _serialize_credential_row(r: Any) -> Dict[str, Any]:
        provider = str(r["provider"] or "")
        created_at = r["createdAt"]
        updated_at = r["updatedAt"]
        if created_at and not isinstance(created_at, str):
            created_at = created_at.isoformat().replace("+00:00", "Z") if hasattr(created_at, "isoformat") else str(created_at)
        if updated_at and not isinstance(updated_at, str):
            updated_at = updated_at.isoformat().replace("+00:00", "Z") if hasattr(updated_at, "isoformat") else str(updated_at)
        return {
            "id": r["id"],
            "name": r["name"],
            "provider": provider,
            "providerName": get_provider_name(provider),
            "accountId": r["accountId"],
            "isDefault": bool(r["isDefault"]),
            "createdAt": created_at,
            "updatedAt": updated_at,
        }

    if self.command == "GET" and sub == "/providers":
        data = {"providers": get_all_provider_capabilities()}
        self._ok(data, "获取提供商列表成功")
        return

    if self.command == "GET" and sub == "/":
        try:
            provider_types = _provider_types_for_category(first_or_none(q, "category") or "dns")
        except ValueError as exc:
            self._err(str(exc), 400)
            return
        if not provider_types:
            self._ok({"credentials": []}, "获取凭证列表成功")
            return
        provider_sql = _provider_sql(provider_types)
        with conn() as c:
            rows = c.execute(
                f"""
                SELECT id, name, provider, accountId, isDefault, createdAt, updatedAt
                FROM dns_credentials
                WHERE userId = ? AND provider IN ({provider_sql})
                ORDER BY isDefault DESC, createdAt ASC, id ASC
                """,
                (uid, *provider_types),
            ).fetchall()
        self._ok({"credentials": [_serialize_credential_row(r) for r in rows]}, "获取凭证列表成功")
        return

    m = re.fullmatch(r"/([^/]+)/secrets", sub)
    if self.command == "GET" and m:
        cid = self._parse_credential_id(m.group(1))
        if cid is None:
            self._err("无效凭证ID", 400)
            return
        with conn() as c:
            row = c.execute(
                "SELECT id, secrets FROM dns_credentials WHERE id = ? AND userId = ? LIMIT 1",
                (cid, uid),
            ).fetchone()
        if not row:
            self._err("凭证不存在", 404)
            return
        try:
            plain = decrypt_text(row["secrets"])
            obj = safe_json_loads(plain)
            secrets = obj if isinstance(obj, dict) else {}
        except Exception as e:
            self._err(f"凭证密钥解析失败: {e}", 500)
            return
        clean: Dict[str, str] = {}
        for k, v in secrets.items():
            if k is None or v is None:
                continue
            clean[str(k)] = str(v)
        self._ok({"secrets": clean}, "获取凭证密钥成功")
        return

    if self.command == "POST" and sub == "/":
        name = str(body.get("name") or "").strip()
        provider = str(body.get("provider") or "").strip()
        secrets = body.get("secrets")
        account_id = body.get("accountId")

        if not name or not provider or not isinstance(secrets, dict):
            self._err("缺少必需参数: name, provider, secrets", 400)
            return
        caps = get_provider_capabilities(provider)
        if not caps:
            self._err(f"不支持的提供商: {provider}", 400)
            return
        try:
            secrets = _validate_credential_secrets(provider, secrets)
        except ValueError as exc:
            self._err(str(exc), 400)
            return

        provider_types = _provider_types_for_category(str(caps.get("category") or "dns"))
        resolved_account_id = str(account_id).strip() if account_id else None
        if provider == "cloudflare" and not resolved_account_id:
            token = str(secrets.get("apiToken") or "").strip()
            if token:
                try:
                    resolved_account_id = CloudflareApi(token).get_default_account_id() or None
                except Exception:
                    resolved_account_id = None

        secrets_enc = encrypt_text(json.dumps(secrets, ensure_ascii=False))
        with conn() as c:
            count = 0
            if provider_types:
                provider_sql = _provider_sql(provider_types)
                count = c.execute(
                    f"SELECT COUNT(*) c FROM dns_credentials WHERE userId = ? AND provider IN ({provider_sql})",
                    (uid, *provider_types),
                ).fetchone()["c"]
            is_default = 1 if int(count) == 0 else 0
            c.execute(
                """
                INSERT INTO dns_credentials (userId, name, provider, secrets, accountId, isDefault, createdAt, updatedAt)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (uid, name, provider, secrets_enc, resolved_account_id, is_default),
            )
            cid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
            row = c.execute(
                """
                SELECT id, name, provider, accountId, isDefault, createdAt, updatedAt
                FROM dns_credentials WHERE id = ? LIMIT 1
                """,
                (cid,),
            ).fetchone()
            c.commit()

        try:
            create_log(
                user_id=uid,
                action="CREATE",
                resource_type="CREDENTIAL",
                domain=provider,
                record_name=name,
                status="SUCCESS",
                ip_address=ip,
                new_value=json.dumps(
                    {
                        "id": row["id"],
                        "name": row["name"],
                        "provider": row["provider"],
                        "accountId": row["accountId"],
                        "isDefault": bool(row["isDefault"]),
                        "secretsUpdated": True,
                        "secretsKeys": sorted([str(k) for k in secrets.keys()]),
                    },
                    ensure_ascii=False,
                ),
            )
        except Exception:
            pass

        self._ok({"credential": _serialize_credential_row(row)}, "凭证创建成功", 201)
        return

    m = re.fullmatch(r"/([^/]+)", sub)
    if self.command == "PUT" and m:
        cid = self._parse_credential_id(m.group(1))
        if cid is None:
            self._err("无效凭证ID", 400)
            return
        with conn() as c:
            existing = c.execute(
                "SELECT id, name, provider, accountId, isDefault FROM dns_credentials WHERE id = ? AND userId = ? LIMIT 1",
                (cid, uid),
            ).fetchone()
            if not existing:
                self._err("凭证不存在", 404)
                return
            provider_types = _provider_types_for_category(_provider_category(str(existing["provider"] or "")))

            updates: Dict[str, Any] = {}
            if "name" in body and body.get("name") is not None:
                nv = str(body.get("name") or "").strip()
                if nv:
                    updates["name"] = nv
            if "accountId" in body:
                av = body.get("accountId")
                updates["accountId"] = str(av).strip() if av is not None and str(av).strip() else None
            if "secrets" in body and isinstance(body.get("secrets"), dict):
                try:
                    validated = _validate_credential_secrets(str(existing["provider"] or "").strip(), body.get("secrets"))
                except ValueError as exc:
                    self._err(str(exc), 400)
                    return
                updates["secrets"] = encrypt_text(json.dumps(validated, ensure_ascii=False))
            if body.get("isDefault") is True and provider_types:
                provider_sql = _provider_sql(provider_types)
                c.execute(
                    f"""
                    UPDATE dns_credentials
                    SET isDefault = 0, updatedAt = CURRENT_TIMESTAMP
                    WHERE userId = ? AND provider IN ({provider_sql})
                    """,
                    (uid, *provider_types),
                )
                updates["isDefault"] = 1

            if updates:
                sets = ", ".join([f"{k} = ?" for k in updates.keys()] + ["updatedAt = CURRENT_TIMESTAMP"])
                vals = list(updates.values()) + [cid, uid]
                c.execute(f"UPDATE dns_credentials SET {sets} WHERE id = ? AND userId = ?", vals)

            row = c.execute(
                """
                SELECT id, name, provider, accountId, isDefault, createdAt, updatedAt
                FROM dns_credentials WHERE id = ? AND userId = ? LIMIT 1
                """,
                (cid, uid),
            ).fetchone()
            c.commit()

        cache_delete_pattern(f"dns:*:cred:{cid}:*")
        cache_delete_pattern(f"esa:*:cred:{cid}:*")
        cache_delete_pattern(f"acceleration:*:cred:{cid}:*")
        cache_delete_pattern(f"ssl:*:cred:{cid}:*")
        cache_delete_pattern(f"ssl:*:{cid}:*")
        self._ok({"credential": _serialize_credential_row(row)}, "凭证更新成功")
        return

    if self.command == "DELETE" and m:
        cid = self._parse_credential_id(m.group(1))
        if cid is None:
            self._err("无效凭证ID", 400)
            return
        with conn() as c:
            existing = c.execute(
                "SELECT id, name, provider, accountId, isDefault FROM dns_credentials WHERE id = ? AND userId = ? LIMIT 1",
                (cid, uid),
            ).fetchone()
            if not existing:
                self._err("凭证不存在", 404)
                return
            provider_types = _provider_types_for_category(_provider_category(str(existing["provider"] or "")))
            c.execute("DELETE FROM dns_credentials WHERE id = ? AND userId = ?", (cid, uid))
            if bool(existing["isDefault"]) and provider_types:
                provider_sql = _provider_sql(provider_types)
                first = c.execute(
                    f"""
                    SELECT id
                    FROM dns_credentials
                    WHERE userId = ? AND provider IN ({provider_sql})
                    ORDER BY createdAt ASC, id ASC
                    LIMIT 1
                    """,
                    (uid, *provider_types),
                ).fetchone()
                if first:
                    c.execute("UPDATE dns_credentials SET isDefault = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ?", (first["id"],))
            c.commit()

        cache_delete_pattern(f"dns:*:cred:{cid}:*")
        cache_delete_pattern(f"esa:*:cred:{cid}:*")
        cache_delete_pattern(f"acceleration:*:cred:{cid}:*")
        cache_delete_pattern(f"ssl:*:cred:{cid}:*")
        cache_delete_pattern(f"ssl:*:{cid}:*")
        self._ok(None, "凭证删除成功")
        return

    m = re.fullmatch(r"/([^/]+)/verify", sub)
    if self.command == "POST" and m:
        cid = self._parse_credential_id(m.group(1))
        if cid is None:
            self._err("无效凭证ID", 400)
            return
        with conn() as c:
            row = c.execute(
                "SELECT id, name, provider, secrets, accountId FROM dns_credentials WHERE id = ? AND userId = ? LIMIT 1",
                (cid, uid),
            ).fetchone()
        if not row:
            self._err("凭证不存在", 404)
            return

        provider = str(row["provider"] or "").strip()
        valid = False
        err_msg = None
        verify_details: Dict[str, Any] = {}
        try:
            secrets = self._json_loads_safe(decrypt_text(row["secrets"]))
            if provider in SUPPORTED_DNS_RECORD_PROVIDER_SET:
                dns_api = build_dns_provider_api(provider, secrets)
                valid = bool(dns_api.verify_credentials())
                if valid:
                    zone_result = dns_api.list_zones(1, 100)
                    visible_zones = [
                        str(item.get("name") or "").strip()
                        for item in (zone_result.get("zones") or [])
                        if str(item.get("name") or "").strip()
                    ]
                    zone_count = int(zone_result.get("total") or len(visible_zones))
                    verify_details = {"zoneCount": zone_count, "visibleZones": visible_zones}
                    if provider == "cloudflare":
                        if zone_count == 0:
                            verify_details["warning"] = "Token 验证成功，但没有任何可见域名。请检查 Zone Resources 授权范围。"
                        elif zone_count == 1:
                            verify_details["warning"] = "当前 Token 仅能看到 1 个域名，可能只授权了单个 Zone。请在 Cloudflare API Token 的 Zone Resources 中选择 Include → All zones，或勾选全部需要管理的域名。"
                    cache_delete_pattern(f"dns:*:cred:{cid}:*")
            elif provider in SUPPORTED_ACCELERATION_PROVIDER_SET:
                validate_acceleration_credentials(provider, secrets)
                valid = True
            else:
                caps = get_provider_capabilities(provider)
                if caps is None:
                    raise ValueError(f"不支持的提供商: {provider}")
                fields = caps.get("authFields") if isinstance(caps.get("authFields"), list) else []
                required_fields = [
                    str(f.get("name") or f.get("key") or "").strip()
                    for f in fields
                    if isinstance(f, dict) and bool(f.get("required"))
                ]
                missing = [k for k in required_fields if not str(secrets.get(k) or "").strip()]
                if missing:
                    raise ValueError(f"缺少字段: {', '.join(missing)}")
                valid = True
        except Exception as e:
            valid = False
            err_msg = str(e)

        try:
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="CREDENTIAL",
                domain=provider,
                record_name=str(row["name"] or str(cid)),
                status="SUCCESS" if valid else "FAILED",
                ip_address=ip,
                new_value=json.dumps({"id": cid, "provider": provider, "valid": valid, "zoneCount": verify_details.get("zoneCount")}, ensure_ascii=False),
                error_message=None if valid else (err_msg or "凭证无效"),
            )
        except Exception:
            pass
        if valid:
            self._ok({"valid": True, **verify_details}, "凭证验证成功")
        else:
            self._ok({"valid": False, "error": err_msg} if err_msg else {"valid": False}, "凭证验证失败")
        return

    self._err("接口不存在", 404)


def _acceleration_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/accelerations") :] or "/"
    body = self._json_body(b)
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return

    def resolve_provider(*values: Any) -> str:
        for value in values:
            text = str(value or "").strip().lower()
            if text:
                return text
        return "edgeone"

    def auth_ctx(credential_id_value: Any = None, provider_value: Any = None) -> Dict[str, Any]:
        credential_value = credential_id_value
        if credential_value is None:
            credential_value = body.get("credentialId")
        if credential_value is None:
            credential_value = first_or_none(q, "credentialId")
        cid = self._parse_credential_id(credential_value)
        explicit_provider = ""
        for value in (provider_value, body.get("provider"), first_or_none(q, "provider")):
            text = str(value or "").strip().lower()
            if text:
                explicit_provider = text
                break
        # When only a credentialId is supplied, let _acceleration_auth resolve
        # the provider FROM the credential row. Defaulting to "edgeone" here
        # would filter out credentials of any other acceleration provider.
        return self._acceleration_auth(uid, cid, explicit_provider or None)

    def invalidate(auth: Dict[str, Any], site_id: str | None = None) -> None:
        try:
            cred_id = int(auth["credential"]["id"] or 0)
        except Exception:
            cred_id = 0
        provider = str(auth.get("provider") or "").strip().lower()
        if cred_id > 0:
            cache_delete_pattern(f"acceleration:*:cred:{cred_id}:*")
            cache_delete_pattern(f"acceleration:domains:cred:{cred_id}:*")
            cache_delete_pattern(f"acceleration:domain-status:cred:{cred_id}:*")
            if site_id:
                cache_delete_pattern(f"acceleration:domains:cred:{cred_id}:p:{provider}:s:{site_id}:*")

    def domain_status_cache_key(cred_id: Any, site_id: str, domain: str) -> str:
        return _accel_domain_status_cache_key(uid, cred_id, site_id, domain)

    def parse_dns_credential_id(source: Any = None) -> int | None:
        value = source
        if value is None:
            value = body.get("dnsCredentialId")
        if value is None:
            value = first_or_none(q, "dnsCredentialId")
        return self._parse_credential_id(value)

    def collect_dns_apis(dns_credential_id: int | None, auto_match_dns: bool) -> tuple[list[tuple[Any, str, Any, list[Dict[str, Any]]]], list[Dict[str, Any]]]:
        collected: list[tuple[Any, str, Any, list[Dict[str, Any]]]] = []
        errors: list[Dict[str, Any]] = []
        seen_credential_ids: set[int] = set()

        def add_row(row: Any, report_errors: bool = False) -> None:
            if not row:
                return
            try:
                current_id = int(row["id"] or 0)
            except Exception:
                current_id = 0
            if current_id > 0 and current_id in seen_credential_ids:
                return
            dns_provider = str(row["provider"] or "").strip().lower()
            if dns_provider not in SUPPORTED_DNS_RECORD_PROVIDER_SET:
                if report_errors:
                    errors.append({
                        "credentialId": current_id or None,
                        "credentialName": str(row["name"] or ""),
                        "provider": dns_provider,
                        "error": "所选 DNS 凭证不支持自动配置（当前提供商未启用记录管理）",
                    })
                return
            try:
                secrets = self._credential_secrets(row)
                api_obj = build_dns_provider_api(dns_provider, secrets)
                zones = api_obj.list_zones(1, 200).get("zones", [])
                collected.append((api_obj, dns_provider, row, zones if isinstance(zones, list) else []))
                if current_id > 0:
                    seen_credential_ids.add(current_id)
            except Exception as exc:
                if report_errors:
                    errors.append({
                        "credentialId": current_id or None,
                        "credentialName": str(row["name"] or ""),
                        "provider": dns_provider,
                        "error": str(exc),
                    })

        if dns_credential_id:
            row = self._get_credential_row(uid, dns_credential_id)
            if row:
                add_row(row, report_errors=True)
            else:
                errors.append({"credentialId": dns_credential_id, "error": "所选 DNS 凭证不存在或无权访问"})

        if auto_match_dns and not collected:
            with conn() as c:
                rows = c.execute(
                    f"""
                    SELECT id, name, provider, secrets
                    FROM dns_credentials
                    WHERE userId = ? AND provider IN ({SUPPORTED_DNS_RECORD_PROVIDER_SQL})
                    ORDER BY isDefault DESC, createdAt ASC, id ASC
                    """,
                    (uid, *SUPPORTED_DNS_RECORD_PROVIDER_TYPES),
                ).fetchall()
            for row in rows:
                add_row(row, report_errors=False)

        return collected, errors

    def match_dns_zone(check_domain: str, dns_apis: list[tuple[Any, str, Any, list[Dict[str, Any]]]]) -> tuple[Any, str | None, Any, Dict[str, Any] | None]:
        target = str(check_domain or "").strip().lower().rstrip(".")
        best: tuple[Any, str | None, Any, Dict[str, Any] | None] = (None, None, None, None)
        best_length = -1
        if not target:
            return best
        for api_obj, dns_provider, row, zones in dns_apis:
            for zone in zones:
                zone_name = str(zone.get("name") or "").strip().lower().rstrip(".")
                if not zone_name:
                    continue
                if target == zone_name or target.endswith("." + zone_name):
                    if len(zone_name) > best_length:
                        best = (api_obj, dns_provider, row, zone)
                        best_length = len(zone_name)
        return best

    def normalize_record_compare(record_type: str, value: Any) -> str:
        text = str(value or "").strip().strip('"')
        if str(record_type or "").strip().upper() == "CNAME":
            return text.rstrip(".").lower()
        return text

    def find_existing_dns_record(api_obj: Any, dns_provider: str, zone_id: str, fqdn_name: str, record_type: str, value: str) -> Dict[str, Any] | None:
        try:
            result = api_obj.list_records(zone_id, 1, 200, {"name": fqdn_name, "type": record_type})
        except Exception:
            return None
        records = result.get("records") if isinstance(result, dict) else []
        expected_name = str(fqdn_name or "").strip().rstrip(".").lower()
        expected_value = normalize_record_compare(record_type, value)
        for item in (records or []):
            current_type = str(item.get("type") or item.get("recordType") or "").strip().upper()
            if current_type != str(record_type or "").strip().upper():
                continue
            current_name = str(item.get("name") or "").strip().rstrip(".").lower()
            current_value = normalize_record_compare(
                record_type,
                item.get("value") if item.get("value") is not None else item.get("content"),
            )
            if current_name == expected_name and current_value == expected_value:
                return item
        return None

    def ensure_dns_record(
        api_obj: Any,
        dns_provider: str,
        zone: Dict[str, Any],
        fqdn_name: str,
        record_type: str,
        value: str,
        ttl: int = 600,
    ) -> Dict[str, Any]:
        zone_id = str(zone.get("id") or "").strip()
        if not zone_id:
            raise ValueError("DNS 区域缺少 ID")
        existing = find_existing_dns_record(api_obj, dns_provider, zone_id, fqdn_name, record_type, value)
        if existing:
            return {"existing": True, "record": existing}
        payload = {
            "type": str(record_type or "").strip().upper(),
            "name": str(fqdn_name or "").strip(),
            "value": str(value or "").strip(),
            "ttl": int(ttl) if int(ttl) > 0 else 600,
            "line": "default",
        }
        if str(record_type or "").strip().upper() == "CNAME":
            payload["proxied"] = False
        record = api_obj.create_record(zone_id, payload)
        return {"existing": False, "record": record}

    def update_existing_dns_record(
        api_obj: Any,
        dns_provider: str,
        zone_id: str,
        record_id: str,
        record_type: str,
        value: str,
        ttl: int = 600,
    ) -> Dict[str, Any]:
        """Update a record's value in place (used when EdgeOne reassigns a
        CNAME target; recreating would briefly break resolution)."""
        rid = str(record_id or "").strip()
        if not rid:
            raise ValueError("缺少记录 ID")
        payload = {
            "value": str(value or "").strip(),
            "ttl": int(ttl) if int(ttl) > 0 else 600,
        }
        record = api_obj.update_record(zone_id, rid, payload)
        return {"record": record, "recordId": rid, "value": str(value or "").strip()}

    def normalize_fqdn(value: Any) -> str:
        return str(value or "").strip().rstrip(".").lower()

    def normalize_dns_record_item(dns_provider: str, item: Any) -> Dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        return {
            "id": str(item.get("id") or item.get("recordId") or "").strip(),
            "type": str(item.get("type") or item.get("recordType") or "").strip().upper(),
            "name": str(item.get("name") or item.get("recordName") or "").strip(),
            "value": str(item.get("value") or item.get("content") or "").strip(),
            "ttl": item.get("ttl"),
            "status": str(item.get("status") or "").strip(),
            "proxied": item.get("proxied"),
        }

    def list_dns_records_for_name(api_obj: Any, dns_provider: str, zone_id: str, fqdn_name: str) -> List[Dict[str, Any]]:
        try:
            result = api_obj.list_records(zone_id, 1, 200, {"name": fqdn_name})
        except Exception:
            result = {"records": []}
        rows = result.get("records") if isinstance(result, dict) else []
        normalized_target = normalize_fqdn(fqdn_name)
        items: List[Dict[str, Any]] = []
        for row in (rows or []):
            normalized = normalize_dns_record_item(dns_provider, row)
            if not normalized:
                continue
            if normalize_fqdn(normalized.get("name")) != normalized_target:
                continue
            items.append(normalized)
        return items

    def analyze_dns_record_conflicts(
        api_obj: Any,
        dns_provider: str,
        dns_row: Any,
        zone: Dict[str, Any],
        fqdn_name: str,
        record_type: str,
        expected_value: str,
    ) -> Dict[str, Any]:
        zone_id = str(zone.get("id") or "").strip()
        target_type = str(record_type or "").strip().upper()
        expected_compare = normalize_record_compare(target_type, expected_value)
        exact_match: Dict[str, Any] | None = None
        records = list_dns_records_for_name(api_obj, dns_provider, zone_id, fqdn_name)
        conflicts: List[Dict[str, Any]] = []
        for item in records:
            current_type = str(item.get("type") or "").strip().upper()
            current_value = normalize_record_compare(current_type, item.get("value"))
            if current_type == target_type and current_value == expected_compare:
                exact_match = item
                continue
            reason = ""
            if target_type == "CNAME":
                if current_type == "CNAME":
                    reason = "同名 CNAME 已指向其他目标"
                else:
                    reason = "同名存在其他记录，CNAME 无法共存"
            elif current_type == target_type and current_value != expected_compare:
                reason = "同类型记录值不同"
            if reason:
                conflicts.append({
                    "id": item.get("id"),
                    "type": current_type,
                    "name": item.get("name"),
                    "value": item.get("value"),
                    "ttl": item.get("ttl"),
                    "status": item.get("status"),
                    "proxied": item.get("proxied"),
                    "reason": reason,
                })
        return {
            "configured": exact_match is not None,
            "currentValue": str(exact_match.get("value") or "") if isinstance(exact_match, dict) else "",
            "records": records,
            "conflicts": conflicts,
            "provider": dns_provider,
            "credentialId": int(dns_row["id"] or 0) if dns_row else None,
            "credentialName": str(dns_row["name"] or "") if dns_row else "",
            "zone": str(zone.get("name") or ""),
            "zoneId": zone_id,
        }

    def query_public_cname_resolution(domain_name: str, expected_value: str) -> Dict[str, Any]:
        target_domain = normalize_fqdn(domain_name)
        expected_compare = normalize_record_compare("CNAME", expected_value)
        if not target_domain:
            return {
                "checked": False,
                "resolver": "",
                "answers": [],
                "currentValue": "",
                "isResolved": False,
                "error": "缺少域名",
            }
        resolvers = [
            (
                "google",
                f"https://dns.google/resolve?name={urllib.parse.quote(target_domain)}&type=CNAME",
                {},
            ),
            (
                "cloudflare",
                f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(target_domain)}&type=CNAME",
                {"accept": "application/dns-json"},
            ),
        ]
        errors: List[str] = []
        for resolver_name, url, headers in resolvers:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=8) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
                payload = json.loads(raw) if raw else {}
                answers_raw = payload.get("Answer") if isinstance(payload.get("Answer"), list) else []
                answers: List[str] = []
                for answer in answers_raw:
                    if not isinstance(answer, dict):
                        continue
                    try:
                        answer_type = int(answer.get("type") or answer.get("Type") or 0)
                    except Exception:
                        answer_type = 0
                    if answer_type != 5:
                        continue
                    data = str(answer.get("data") or answer.get("Data") or "").strip()
                    if data:
                        answers.append(data.rstrip("."))
                normalized_answers = [normalize_record_compare("CNAME", item) for item in answers]
                return {
                    "checked": True,
                    "resolver": resolver_name,
                    "answers": answers,
                    "currentValue": answers[0] if answers else "",
                    "isResolved": expected_compare in normalized_answers,
                    "status": payload.get("Status"),
                    "error": None if answers or str(payload.get("Status") or "0") == "0" else f"DNS 查询状态: {payload.get('Status')}",
                }
            except Exception as exc:
                errors.append(f"{resolver_name}: {exc}")
        return {
            "checked": False,
            "resolver": "",
            "answers": [],
            "currentValue": "",
            "isResolved": False,
            "error": "；".join(errors) if errors else "公开 DNS 查询失败",
        }

    def run_site_auto_verify_dns() -> None:
        auth = auth_ctx()
        api = auth.get("api")
        zone_name = str(body.get("zoneName") or body.get("siteName") or "").strip()
        site_id = str(body.get("siteId") or body.get("remoteSiteId") or "").strip() or None
        if api is None or not (hasattr(api, "create_ownership_verification") or hasattr(api, "identify_zone")):
            self._err("当前加速插件不支持自动验证", 400)
            return
        if not zone_name:
            self._err("缺少参数: zoneName", 400)
            return
        dns_credential_id = parse_dns_credential_id()
        auto_match_dns = bool(body.get("autoMatchDns", dns_credential_id is None))
        verification_payload = (
            api.create_ownership_verification(zone_name, site_id)
            if hasattr(api, "create_ownership_verification")
            else api.identify_zone(zone_name)
        )
        verification = verification_payload.get("verification") if isinstance(verification_payload, dict) else {}
        record_name = str((verification or {}).get("recordName") or "").strip()
        record_value = str((verification or {}).get("recordValue") or "").strip()
        record_type = str((verification or {}).get("recordType") or "TXT").strip() or "TXT"
        response_payload: Dict[str, Any] = {
            "zoneName": zone_name,
            "siteId": site_id,
            "verification": verification or {},
            "dnsRecordsAdded": [],
            "dnsRecordsSkipped": [],
            "dnsErrors": [],
        }
        if not record_name or not record_value:
            self._ok(response_payload, "未获取到可自动添加的验证记录")
            return
        dns_apis, dns_errors = collect_dns_apis(dns_credential_id, auto_match_dns)
        response_payload["dnsErrors"].extend(dns_errors)
        if not dns_apis:
            self._ok(response_payload, "未找到可用的 DNS 凭证，请手动添加 TXT 记录")
            return
        dns_api, dns_provider, dns_row, target_zone = match_dns_zone(zone_name, dns_apis)
        if not target_zone:
            response_payload["dnsErrors"].append({"key": record_name, "error": f"未找到域名 {zone_name} 对应的 DNS 区域"})
            self._ok(response_payload, "未找到匹配的 DNS 区域，请手动添加 TXT 记录")
            return
        try:
            record_result = ensure_dns_record(dns_api, str(dns_provider or ""), target_zone, record_name, record_type, record_value, int(body.get("ttl") or 600))
            record_payload = {
                "credentialId": int(dns_row["id"] or 0) if dns_row else None,
                "credentialName": str(dns_row["name"] or "") if dns_row else "",
                "provider": dns_provider,
                "zone": target_zone.get("name"),
                "zoneId": target_zone.get("id"),
                "type": record_type,
                "name": record_name,
                "value": record_value,
                "existing": bool(record_result.get("existing")),
            }
            if bool(record_result.get("existing")):
                response_payload["dnsRecordsSkipped"].append(record_payload)
            else:
                response_payload["dnsRecordsAdded"].append(record_payload)
        except Exception as exc:
            response_payload["dnsErrors"].append({"key": record_name, "error": str(exc)})
            self._ok(response_payload, "TXT 记录自动添加失败，请改为手动配置")
            return

        if bool(body.get("autoVerify", body.get("verifyAfter", True))):
            verify_code = str((verification or {}).get("verificationCode") or record_value).strip()
            try:
                verify_result = auth["plugin"].verify_site(zone_name, site_id, {"verificationCode": verify_code})
                response_payload["verifySubmitted"] = True
                response_payload["verifyResult"] = verify_result
                invalidate(auth, site_id)
            except Exception as exc:
                response_payload["verifySubmitted"] = False
                response_payload["verifyError"] = str(exc)
        self._ok(response_payload, "TXT 验证记录已自动处理")
        return

    try:
        if self.command == "GET" and sub == "/providers":
            providers = [item for item in get_all_provider_capabilities() if str(item.get("category") or "").strip().lower() == "acceleration"]
            self._ok({"providers": providers}, "获取加速插件列表成功")
            return

        if self.command == "GET" and sub == "/sites":
            auth = auth_ctx()
            keyword = str(first_or_none(q, "keyword") or "").strip().lower()
            ck = acceleration_sites_key(int(auth["credential"]["id"]), auth["provider"], keyword=keyword)
            cached = cache_get(ck)
            if cached is not None:
                self._ok(cached, "获取加速站点列表成功")
                return
            sites = auth["plugin"].list_sites()
            if keyword:
                sites = [
                    item for item in sites
                    if keyword in str(item.get("zoneName") or item.get("siteName") or "").strip().lower()
                    or keyword in str(item.get("siteId") or "").strip().lower()
                ]
            data = {"sites": sites, "total": len(sites)}
            cache_set(ck, data, 60)
            self._ok(data, "获取加速站点列表成功")
            return

        if self.command == "POST" and sub == "/sites":
            auth = auth_ctx()
            zone_name = str(body.get("zoneName") or body.get("siteName") or "").strip()
            if not zone_name:
                self._err("缺少参数: zoneName", 400)
                return
            site = auth["plugin"].ensure_site(zone_name, body)
            invalidate(auth, str(site.get("siteId") or site.get("zoneId") or ""))
            self._ok({"site": site}, "创建/获取加速站点成功")
            return

        if self.command == "POST" and sub == "/sites/identify":
            auth = auth_ctx()
            api = auth.get("api")
            zone_name = str(body.get("zoneName") or body.get("siteName") or "").strip()
            if api is None or not (hasattr(api, "create_ownership_verification") or hasattr(api, "identify_zone")):
                self._err("当前加速插件不支持站点识别", 400)
                return
            if not zone_name:
                self._err("缺少参数: zoneName", 400)
                return
            if hasattr(api, "create_ownership_verification"):
                data = api.create_ownership_verification(zone_name, str(body.get("siteId") or "").strip() or None)
            else:
                data = api.identify_zone(zone_name)
            self._ok(data, "获取站点验证信息成功")
            return

        if self.command == "POST" and sub in {"/sites/auto-verify-dns", "/create-verify-record"}:
            run_site_auto_verify_dns()
            return

        if self.command == "POST" and sub == "/sites/verify":
            auth = auth_ctx()
            zone_name = str(body.get("zoneName") or body.get("siteName") or "").strip()
            site_id = str(body.get("siteId") or "").strip() or None
            if not zone_name:
                self._err("缺少参数: zoneName", 400)
                return
            data = auth["plugin"].verify_site(
                zone_name,
                site_id,
                {"verificationCode": body.get("verificationCode") or body.get("code")},
            )
            invalidate(auth, site_id)
            self._ok(data, "站点验证完成")
            return

        m = re.fullmatch(r"/sites/([^/]+)/status", sub)
        if m and self.command in ("POST", "PUT"):
            auth = auth_ctx()
            site_id = urllib.parse.unquote(m.group(1))
            zone_name = str(body.get("zoneName") or body.get("siteName") or "").strip()
            enabled = bool(body.get("enabled"))
            data = auth["plugin"].set_site_status(zone_name, site_id, enabled, body)
            invalidate(auth, site_id)
            self._ok(data, "更新加速站点状态成功")
            return

        m = re.fullmatch(r"/sites/([^/]+)", sub)
        if m and self.command == "GET":
            auth = auth_ctx()
            site_id = urllib.parse.unquote(m.group(1))
            zone_name = str(first_or_none(q, "zoneName") or "").strip()
            site = auth["plugin"].get_site(zone_name, site_id, {})
            self._ok({"site": site}, "获取加速站点详情成功")
            return

        if m and self.command == "DELETE":
            auth = auth_ctx()
            site_id = urllib.parse.unquote(m.group(1))
            zone_name = str(first_or_none(q, "zoneName") or body.get("zoneName") or "").strip()
            data = auth["plugin"].delete_site(zone_name, site_id, {})
            invalidate(auth, site_id)
            self._ok(data, "删除加速站点成功")
            return

        if self.command == "GET" and sub == "/domains":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "list_acceleration_domains"):
                self._err("当前加速插件不支持域名列表", 400)
                return
            site_id = str(first_or_none(q, "siteId") or "").strip()
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            keyword = str(first_or_none(q, "domainName") or first_or_none(q, "keyword") or "").strip()
            ck = acceleration_domains_key(int(auth["credential"]["id"]), auth["provider"], site_id, keyword=keyword)
            cached = cache_get(ck)
            if cached is not None:
                self._ok(cached, "获取加速域名列表成功")
                return
            data = api.list_acceleration_domains(site_id, keyword or None)
            items = data.get("items") if isinstance(data, dict) else []
            payload = {"domains": items or [], "total": len(items or []), "siteId": site_id, "requestId": data.get("requestId") if isinstance(data, dict) else None}
            cache_set(ck, payload, 30)
            self._ok(payload, "获取加速域名列表成功")
            return

        if self.command == "POST" and sub == "/domains":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "create_acceleration_domain"):
                self._err("当前加速插件不支持创建加速域名", 400)
                return
            site_id = str(body.get("siteId") or "").strip()
            domain_name = str(body.get("domainName") or "").strip()
            if not site_id or not domain_name:
                self._err("缺少参数: siteId, domainName", 400)
                return
            if bool(body.get("upsert")):
                domain = api.upsert_acceleration_domain(site_id, domain_name, body)
            else:
                domain = api.create_acceleration_domain(site_id, domain_name, body)
            invalidate(auth, site_id)
            msg = "创建加速域名成功"
            stripped = domain.get("strippedParams") if isinstance(domain, dict) else None
            if stripped:
                msg += f"；注意：后端不支持参数 {', '.join(stripped)}，已自动降级（配置可能未完全生效）"
            self._ok({"domain": domain}, msg)
            return

        if self.command == "POST" and sub == "/domains/auto-cname":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "get_acceleration_domain"):
                self._err("当前加速插件不支持自动配置 CNAME", 400)
                return
            site_id = str(body.get("siteId") or "").strip()
            domain_name = str(body.get("domainName") or "").strip()
            if not site_id or not domain_name:
                self._err("缺少参数: siteId, domainName", 400)
                return
            dns_credential_id = parse_dns_credential_id()
            auto_match_dns = bool(body.get("autoMatchDns", dns_credential_id is None))
            domain = api.get_acceleration_domain(site_id, domain_name)
            if not domain:
                self._err("加速域名不存在", 404)
                return
            cname_target = str(domain.get("cnameTarget") or "").strip()
            response_payload: Dict[str, Any] = {
                "domain": domain,
                "dnsRecordsAdded": [],
                "dnsErrors": [],
                "dnsConflicts": [],
            }
            if not cname_target:
                self._ok(response_payload, "当前域名尚未分配 CNAME，请稍后重试")
                return
            dns_apis, dns_errors = collect_dns_apis(dns_credential_id, auto_match_dns)
            response_payload["dnsErrors"].extend(dns_errors)
            public_resolution = query_public_cname_resolution(domain_name, cname_target)
            response_payload["publicResolution"] = public_resolution
            if not dns_apis:
                self._ok(response_payload, "未找到可用的 DNS 凭证，请手动添加 CNAME 记录")
                return
            dns_api, dns_provider, dns_row, target_zone = match_dns_zone(domain_name, dns_apis)
            if not target_zone:
                response_payload["dnsErrors"].append({"key": domain_name, "error": f"未找到域名 {domain_name} 对应的 DNS 区域"})
                self._ok(response_payload, "未找到匹配的 DNS 区域，请手动添加 CNAME 记录")
                return
            dns_check = analyze_dns_record_conflicts(
                dns_api,
                str(dns_provider or ""),
                dns_row,
                target_zone,
                domain_name,
                "CNAME",
                cname_target,
            )
            dns_check["expectedValue"] = cname_target
            dns_check["zoneMatched"] = True
            dns_check["publicResolution"] = public_resolution
            dns_check["errors"] = list(response_payload.get("dnsErrors") or [])
            response_payload["dnsCheck"] = dns_check
            response_payload["dnsConflicts"] = dns_check.get("conflicts") or []
            conflicts = dns_check.get("conflicts") or []
            # A same-name CNAME pointing at a DIFFERENT target is the common
            # "EdgeOne reassigned the CNAME" case — auto-update it in place
            # rather than refusing. Only non-CNAME record types are true
            # un-resolvable conflicts (CNAME cannot coexist with them).
            blocking = [c for c in conflicts if str(c.get("type") or "").upper() != "CNAME"]
            if blocking:
                self._ok(response_payload, "检测到 DNS 冲突，未自动写入 CNAME")
                return
            if conflicts and not dns_check.get("configured"):
                # Update the stale CNAME to the new target.
                stale = conflicts[0]
                try:
                    update_result = update_existing_dns_record(
                        dns_api, str(dns_provider or ""), str(target_zone.get("id") or ""),
                        str(stale.get("id") or ""), "CNAME", cname_target, int(body.get("ttl") or 600),
                    )
                    response_payload["dnsRecordsAdded"].append({
                        "credentialId": int(dns_row["id"] or 0) if dns_row else None,
                        "credentialName": str(dns_row["name"] or "") if dns_row else "",
                        "provider": dns_provider,
                        "zone": target_zone.get("name"),
                        "zoneId": target_zone.get("id"),
                        "type": "CNAME",
                        "name": domain_name,
                        "value": cname_target,
                        "updated": True,
                        "previousValue": stale.get("value"),
                        "result": update_result,
                    })
                    refreshed = analyze_dns_record_conflicts(
                        dns_api, str(dns_provider or ""), dns_row, target_zone,
                        domain_name, "CNAME", cname_target,
                    )
                    refreshed["expectedValue"] = cname_target
                    refreshed["zoneMatched"] = True
                    refreshed["publicResolution"] = public_resolution
                    refreshed["errors"] = list(response_payload.get("dnsErrors") or [])
                    response_payload["dnsCheck"] = refreshed
                    response_payload["dnsConflicts"] = refreshed.get("conflicts") or []
                    self._ok(response_payload, "CNAME 已更新为最新加速目标")
                    return
                except Exception as exc:
                    response_payload["dnsErrors"].append({"key": domain_name, "error": f"更新 CNAME 失败: {exc}"})
                    self._ok(response_payload, "旧 CNAME 更新失败，请手动修改")
                    return
            if dns_check.get("configured"):
                response_payload["dnsRecordsAdded"].append({
                    "credentialId": dns_check.get("credentialId"),
                    "credentialName": dns_check.get("credentialName"),
                    "provider": dns_check.get("provider"),
                    "zone": dns_check.get("zone"),
                    "zoneId": dns_check.get("zoneId"),
                    "type": "CNAME",
                    "name": domain_name,
                    "value": cname_target,
                    "existing": True,
                })
                self._ok(response_payload, "当前 CNAME 已存在，无需重复写入")
                return
            try:
                record_result = ensure_dns_record(dns_api, str(dns_provider or ""), target_zone, domain_name, "CNAME", cname_target, int(body.get("ttl") or 600))
                response_payload["dnsRecordsAdded"].append({
                    "credentialId": int(dns_row["id"] or 0) if dns_row else None,
                    "credentialName": str(dns_row["name"] or "") if dns_row else "",
                    "provider": dns_provider,
                    "zone": target_zone.get("name"),
                    "zoneId": target_zone.get("id"),
                    "type": "CNAME",
                    "name": domain_name,
                    "value": cname_target,
                    "existing": bool(record_result.get("existing")),
                })
                response_payload["dnsCheck"] = analyze_dns_record_conflicts(
                    dns_api,
                    str(dns_provider or ""),
                    dns_row,
                    target_zone,
                    domain_name,
                    "CNAME",
                    cname_target,
                )
                if isinstance(response_payload.get("dnsCheck"), dict):
                    response_payload["dnsCheck"]["expectedValue"] = cname_target
                    response_payload["dnsCheck"]["zoneMatched"] = True
                    response_payload["dnsCheck"]["publicResolution"] = public_resolution
                    response_payload["dnsCheck"]["errors"] = list(response_payload.get("dnsErrors") or [])
            except Exception as exc:
                response_payload["dnsErrors"].append({"key": domain_name, "error": str(exc)})
            self._ok(response_payload, "CNAME 记录自动配置完成")
            return

        if self.command == "POST" and sub == "/domains/status":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "describe_domain_status"):
                self._err("当前加速插件不支持状态查询", 400)
                return
            site_id = str(body.get("siteId") or "").strip()
            domain_name = str(body.get("domainName") or "").strip()
            if not site_id or not domain_name:
                self._err("缺少参数: siteId, domainName", 400)
                return
            data = api.describe_domain_status(site_id, domain_name)
            if hasattr(api, "get_acceleration_domain"):
                try:
                    domain = api.get_acceleration_domain(site_id, domain_name)
                except Exception:
                    domain = None
                if domain:
                    data["domain"] = domain
                    domain_status = str(domain.get("status") or domain.get("domainStatus") or "").strip().lower()
                    paused = bool(domain.get("paused"))
                    ui_state = "deploying"
                    if paused:
                        ui_state = "paused"
                    elif domain_status in ("deploying", "pending", "processing"):
                        ui_state = "deploying"
                    elif domain_status in ("active", "online", "deployed"):
                        ui_state = "deploying" if not str(domain.get("cnameTarget") or "").strip() else "active"
                    else:
                        cname_target_check = str(domain.get("cnameTarget") or "").strip()
                        if not cname_target_check:
                            ui_state = "cname_pending"
                    certificate_state = acceleration_cert_state({
                        "accelerationDomain": domain_name,
                        "accelerationCredentialId": auth["credential"]["id"],
                        "accelerationSiteId": site_id,
                        "accelerationProvider": auth.get("provider") or "edgeone",
                        "recordName": domain_name,
                    })
                    data["certificate"] = certificate_state
                    data["certId"] = certificate_state.get("certId") or ""
                    data["accelCertificateId"] = certificate_state.get("accelCertificateId") or ""
                    data["accelDaysRemaining"] = certificate_state.get("accelDaysRemaining")
                    data["accelExpireTime"] = certificate_state.get("accelExpireTime") or ""
                    data["accelIssuer"] = certificate_state.get("accelIssuer") or ""
                    data["bindable"] = bool(certificate_state.get("bindable"))
                    cached_status_key = domain_status_cache_key(auth['credential']['id'], site_id, domain_name)
                    cache_set(cached_status_key, ui_state, 30)
                    cname_target = str(domain.get("cnameTarget") or "").strip()
                    if cname_target:
                        dns_credential_id = parse_dns_credential_id()
                        auto_match_dns = bool(body.get("autoMatchDns", dns_credential_id is None))
                        dns_check: Dict[str, Any] = {
                            "expectedValue": cname_target,
                            "zoneMatched": False,
                            "configured": False,
                            "currentValue": "",
                            "provider": None,
                            "credentialId": None,
                            "credentialName": "",
                            "zone": "",
                            "zoneId": "",
                            "records": [],
                            "conflicts": [],
                            "errors": [],
                            "publicResolution": query_public_cname_resolution(domain_name, cname_target),
                        }
                        dns_apis, dns_errors = collect_dns_apis(dns_credential_id, auto_match_dns)
                        dns_check["errors"].extend(dns_errors)
                        if dns_apis:
                            dns_api, dns_provider, dns_row, target_zone = match_dns_zone(domain_name, dns_apis)
                            if target_zone:
                                dns_check["zoneMatched"] = True
                                dns_check.update(
                                    analyze_dns_record_conflicts(
                                        dns_api,
                                        str(dns_provider or ""),
                                        dns_row,
                                        target_zone,
                                        domain_name,
                                        "CNAME",
                                        cname_target,
                                    )
                                )
                            else:
                                dns_check["errors"].append({"error": f"未找到域名 {domain_name} 对应的 DNS 区域"})
                        data["dnsCheck"] = dns_check
            self._ok(data, "获取加速域名状态成功")
            return

        m = re.fullmatch(r"/domains/([^/]+)/status", sub)
        if m and self.command in ("POST", "PUT"):
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "modify_acceleration_domain_statuses"):
                self._err("当前加速插件不支持状态修改", 400)
                return
            domain_name = urllib.parse.unquote(m.group(1))
            site_id = str(body.get("siteId") or "").strip()
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            data = api.modify_acceleration_domain_statuses(site_id, [domain_name], bool(body.get("enabled")))
            invalidate(auth, site_id)
            # Do NOT cache an optimistic "active": right after enabling, CNAME
            # may be unconfigured and EdgeOne still deploys — showing 已加速
            # would contradict the real status the next read returns.
            new_ui_state = "paused" if not bool(body.get("enabled")) else "deploying"
            cached_status_key = domain_status_cache_key(auth['credential']['id'], site_id, domain_name)
            cache_set(cached_status_key, new_ui_state, 30)
            self._ok(data, "更新加速域名状态成功")
            return

        m = re.fullmatch(r"/domains/([^/]+)/finalize", sub)
        if m and self.command == "POST":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "upsert_acceleration_domain"):
                self._err("当前加速插件不支持 finalize 操作", 400)
                return
            domain_name = urllib.parse.unquote(m.group(1))
            site_id = str(body.get("siteId") or "").strip()
            if not site_id or not domain_name:
                self._err("缺少参数: siteId, domainName", 400)
                return
            try:
                domain = api.upsert_acceleration_domain(site_id, domain_name, body)
            except Exception as exc:
                self._err(str(exc), 400)
                return
            invalidate(auth, site_id)
            dns_credential_id = parse_dns_credential_id()
            auto_match_dns = bool(body.get("autoMatchDns", dns_credential_id is None))
            cname_target = str((domain or {}).get("cnameTarget") or "").strip()
            response_payload: Dict[str, Any] = {
                "domain": domain,
                "dnsRecordsAdded": [],
                "dnsErrors": [],
                "dnsConflicts": [],
            }
            if not cname_target:
                self._ok(response_payload, "加速域名已保存，但尚未分配 CNAME，请稍后再试")
                return
            dns_apis, dns_errors = collect_dns_apis(dns_credential_id, auto_match_dns)
            response_payload["dnsErrors"].extend(dns_errors)
            public_resolution = query_public_cname_resolution(domain_name, cname_target)
            response_payload["publicResolution"] = public_resolution
            if not dns_apis:
                self._ok(response_payload, "加速域名已保存，未找到可用的 DNS 凭证，请手动添加 CNAME")
                return
            dns_api, dns_provider, dns_row, target_zone = match_dns_zone(domain_name, dns_apis)
            if not target_zone:
                response_payload["dnsErrors"].append({"key": domain_name, "error": f"未找到域名 {domain_name} 对应的 DNS 区域"})
                self._ok(response_payload, "加速域名已保存，未找到匹配的 DNS 区域")
                return
            dns_check = analyze_dns_record_conflicts(
                dns_api, str(dns_provider or ""), dns_row, target_zone, domain_name, "CNAME", cname_target,
            )
            dns_check["expectedValue"] = cname_target
            dns_check["zoneMatched"] = True
            dns_check["publicResolution"] = public_resolution
            dns_check["errors"] = list(response_payload.get("dnsErrors") or [])
            response_payload["dnsCheck"] = dns_check
            response_payload["dnsConflicts"] = dns_check.get("conflicts") or []
            conflicts = dns_check.get("conflicts") or []
            # Same stale-CNAME handling as /domains/auto-cname: same-name CNAME
            # with an outdated target gets updated in place; only non-CNAME
            # collisions remain hard conflicts.
            blocking = [c for c in conflicts if str(c.get("type") or "").upper() != "CNAME"]
            if blocking:
                self._ok(response_payload, "加速域名已保存；检测到 DNS 冲突，未自动写入 CNAME")
                return
            if conflicts and not dns_check.get("configured"):
                stale = conflicts[0]
                try:
                    update_existing_dns_record(
                        dns_api, str(dns_provider or ""), str(target_zone.get("id") or ""),
                        str(stale.get("id") or ""), "CNAME", cname_target, int(body.get("ttl") or 600),
                    )
                    response_payload["dnsRecordsAdded"].append({
                        "credentialId": int(dns_row["id"] or 0) if dns_row else None,
                        "credentialName": str(dns_row["name"] or "") if dns_row else "",
                        "provider": dns_provider,
                        "zone": target_zone.get("name"),
                        "zoneId": target_zone.get("id"),
                        "type": "CNAME",
                        "name": domain_name,
                        "value": cname_target,
                        "updated": True,
                        "previousValue": stale.get("value"),
                    })
                    refreshed = analyze_dns_record_conflicts(
                        dns_api, str(dns_provider or ""), dns_row, target_zone, domain_name, "CNAME", cname_target,
                    )
                    refreshed["expectedValue"] = cname_target
                    refreshed["zoneMatched"] = True
                    refreshed["publicResolution"] = public_resolution
                    refreshed["errors"] = list(response_payload.get("dnsErrors") or [])
                    response_payload["dnsCheck"] = refreshed
                    response_payload["dnsConflicts"] = refreshed.get("conflicts") or []
                    self._ok(response_payload, "加速域名已保存；CNAME 已更新为最新加速目标")
                    return
                except Exception as exc:
                    response_payload["dnsErrors"].append({"key": domain_name, "error": f"更新 CNAME 失败: {exc}"})
                    self._ok(response_payload, "加速域名已保存；旧 CNAME 更新失败，请手动修改")
                    return
            if dns_check.get("configured"):
                response_payload["dnsRecordsAdded"].append({
                    "credentialId": dns_check.get("credentialId"),
                    "credentialName": dns_check.get("credentialName"),
                    "provider": dns_check.get("provider"),
                    "zone": dns_check.get("zone"),
                    "zoneId": dns_check.get("zoneId"),
                    "type": "CNAME",
                    "name": domain_name,
                    "value": cname_target,
                    "existing": True,
                })
                self._ok(response_payload, "加速域名已保存；当前 CNAME 已存在，无需重复写入")
                return
            try:
                record_result = ensure_dns_record(dns_api, str(dns_provider or ""), target_zone, domain_name, "CNAME", cname_target, int(body.get("ttl") or 600))
                response_payload["dnsRecordsAdded"].append({
                    "credentialId": int(dns_row["id"] or 0) if dns_row else None,
                    "credentialName": str(dns_row["name"] or "") if dns_row else "",
                    "provider": dns_provider,
                    "zone": target_zone.get("name"),
                    "zoneId": target_zone.get("id"),
                    "type": "CNAME",
                    "name": domain_name,
                    "value": cname_target,
                    "existing": bool(record_result.get("existing")),
                })
                response_payload["dnsCheck"] = analyze_dns_record_conflicts(
                    dns_api, str(dns_provider or ""), dns_row, target_zone, domain_name, "CNAME", cname_target,
                )
                if isinstance(response_payload.get("dnsCheck"), dict):
                    response_payload["dnsCheck"]["expectedValue"] = cname_target
                    response_payload["dnsCheck"]["zoneMatched"] = True
                    response_payload["dnsCheck"]["publicResolution"] = public_resolution
                    response_payload["dnsCheck"]["errors"] = list(response_payload.get("dnsErrors") or [])
            except Exception as exc:
                response_payload["dnsErrors"].append({"key": domain_name, "error": str(exc)})
            self._ok(response_payload, "加速域名已保存且 CNAME 自动配置完成")
            return

        m = re.fullmatch(r"/domains/([^/]+)", sub)
        if m and self.command == "GET":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "get_acceleration_domain"):
                self._err("当前加速插件不支持域名详情", 400)
                return
            site_id = str(first_or_none(q, "siteId") or "").strip()
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            domain_name = urllib.parse.unquote(m.group(1))
            domain = api.get_acceleration_domain(site_id, domain_name)
            if not domain:
                self._err("加速域名不存在", 404)
                return
            self._ok({"domain": domain}, "获取加速域名详情成功")
            return

        if m and self.command == "PUT":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "modify_acceleration_domain"):
                self._err("当前加速插件不支持更新加速域名", 400)
                return
            site_id = str(body.get("siteId") or "").strip()
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            domain_name = urllib.parse.unquote(m.group(1))
            domain = api.modify_acceleration_domain(site_id, domain_name, body)
            invalidate(auth, site_id)
            self._ok({"domain": domain}, "更新加速域名成功")
            return

        if m and self.command == "DELETE":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "delete_acceleration_domains"):
                self._err("当前加速插件不支持删除加速域名", 400)
                return
            site_id = str(first_or_none(q, "siteId") or body.get("siteId") or "").strip()
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            domain_name = urllib.parse.unquote(m.group(1))
            data = api.delete_acceleration_domains(site_id, [domain_name])
            # Clean up local acceleration-state rows pointing at the deleted
            # cloud domain, otherwise the DNS page keeps showing a stale
            # "已加速" badge / leaves the CNAME pointing at a dead domain.
            cleaned_states = 0
            try:
                accel_cred_id = int(auth["credential"]["id"] or 0)
                with conn() as c:
                    cur = c.execute(
                        """DELETE FROM dns_record_acceleration_states
                           WHERE userId = ? AND accelerationCredentialId = ? AND accelerationSiteId = ?
                             AND LOWER(TRIM(accelerationDomain)) = ?""",
                        (uid, accel_cred_id, site_id, domain_name.strip().lower()),
                    )
                    cleaned_states = int(cur.rowcount or 0)
                    c.commit()
            except Exception:
                cleaned_states = 0
            invalidate(auth, site_id)
            msg = "删除加速域名成功"
            if cleaned_states:
                msg += f"，已清理 {cleaned_states} 条本地加速状态"
            self._ok({**data, "cleanedStates": cleaned_states}, msg)
            return

        if self.command == "POST" and sub == "/certificates/create":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "create_certificate"):
                self._err("当前加速插件不支持证书申请", 400)
                return
            site_id = str(body.get("siteId") or "").strip()
            domain_name = str(body.get("domainName") or "").strip()
            alt_names = body.get("alternativeNames") if isinstance(body.get("alternativeNames"), list) else []
            data = api.create_certificate(site_id, domain_name, alt_names)
            apply_msg = "已申请 EdgeOne 免费证书，请在证书列表中查看签发状态"
            check_items = (data or {}).get("check", {}).get("items") if isinstance(data, dict) else None
            if check_items:
                pending = [x for x in check_items if str(x.get("status") or "").lower() not in ("success", "verified", "active", "finished", "completed", "passed")]
                if pending:
                    apply_msg += "；部分域名需要先按提示添加 DNS 验证记录"
            # Persist the request so the background worker keeps polling the
            # verification state and auto-adds DNS records — previously the
            # flow only checked once and stopped if the user closed the page.
            try:
                domain_names = [domain_name] + [str(x) for x in (alt_names or [])]
                domain_names = [str(x).strip() for x in domain_names if str(x).strip()]
                with conn() as c:
                    c.execute(
                        """INSERT INTO acceleration_cert_requests
                           (userId, provider, credentialId, siteId, domainNames, status, attempts, verification, createdAt, updatedAt)
                           VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)""",
                        (
                            uid, str(auth.get("provider") or "edgeone"),
                            int(auth["credential"]["id"] or 0), site_id,
                            json.dumps(domain_names, ensure_ascii=False),
                            json.dumps({"items": check_items or []}, ensure_ascii=False),
                            now_iso(), now_iso(),
                        ),
                    )
                    c.commit()
                apply_msg += "；后台将自动轮询验证状态并尝试补全 DNS 验证记录"
            except Exception:
                pass
            self._ok(data, apply_msg)
            return

        # POST /api/accelerations/certificates/process-pending — worker entry:
        # poll pending free-cert applications, auto-add verification records
        # when possible, and complete/expire them. Internal-token only.
        if self.command == "POST" and sub == "/certificates/process-pending":
            if not u.get("_internal"):
                self._err("该接口仅供内部任务执行器调用", 403)
                return
            results: List[Dict[str, Any]] = []
            with conn() as c:
                rows = c.execute(
                    """SELECT * FROM acceleration_cert_requests
                       WHERE userId = ? AND status IN ('pending', 'verifying') AND attempts < 40
                       ORDER BY createdAt ASC LIMIT 5""",
                    (uid,),
                ).fetchall()
            for row in rows:
                request_id = int(row["id"])
                attempt = int(row["attempts"] or 0) + 1
                try:
                    provider = str(row["provider"] or "edgeone").strip().lower()
                    accel_ctx = self._acceleration_auth(uid, int(row["credentialId"]), provider)
                    accel_api = accel_ctx.get("api")
                    domain_names = json.loads(row["domainNames"] or "[]")
                    if not isinstance(domain_names, list) or not domain_names:
                        raise ValueError("请求缺少域名")
                    if accel_api is None or not hasattr(accel_api, "check_free_certificate_verification"):
                        # Non-EdgeOne providers manage certificates themselves;
                        # fail fast instead of retrying 40 times.
                        raise AccelerationPluginError("当前加速插件不支持免费证书验证轮询", 400)
                    check = accel_api.check_free_certificate_verification(str(row["siteId"]), domain_names)
                    items = check.get("items") or []
                    pending_items = [
                        x for x in items
                        if str(x.get("status") or "").lower() not in ("success", "verified", "active", "finished", "completed", "passed")
                    ]
                    added_records = 0
                    # Best-effort: add DNS verification TXT records via the
                    # user's DNS credentials (same matching as auto-CNAME).
                    if pending_items:
                        dns_cred_id = parse_dns_credential_id(None)
                        dns_apis, dns_errors = collect_dns_apis(dns_cred_id, True)
                        for item in pending_items:
                            rec_name = str(item.get("recordName") or "").strip()
                            rec_value = str(item.get("recordValue") or "").strip()
                            if not rec_name or not rec_value:
                                continue
                            dv_api, dv_prov, dns_row, target_zone = match_dns_zone(rec_name, dns_apis)
                            if not target_zone:
                                continue
                            try:
                                ensure_dns_record(dv_api, str(dv_prov or ""), target_zone, rec_name, "TXT", rec_value, 600)
                                added_records += 1
                            except Exception:
                                pass
                    done = not pending_items and bool(items)
                    status = "completed" if done else "verifying"
                    with conn() as c:
                        c.execute(
                            """UPDATE acceleration_cert_requests SET status = ?, attempts = ?, lastError = NULL,
                                 verification = ?, updatedAt = ?, completedAt = ?
                               WHERE id = ?""",
                            (
                                status, attempt,
                                json.dumps({"items": items}, ensure_ascii=False),
                                now_iso(), now_iso() if done else None,
                                request_id,
                            ),
                        )
                        c.commit()
                    results.append({"id": request_id, "status": status, "pending": len(pending_items), "recordsAdded": added_records})
                except Exception as ex:
                    # An "unsupported by this plugin" error is terminal — never
                    # burn 40 retries on it.
                    terminal = isinstance(ex, AccelerationPluginError) and int(getattr(ex, "status", 0) or 0) not in (429, 500, 502, 503, 504)
                    final = terminal or attempt >= 40
                    with conn() as c:
                        c.execute(
                            """UPDATE acceleration_cert_requests SET status = ?, attempts = ?, lastError = ?, updatedAt = ?
                               WHERE id = ?""",
                            ("failed" if final else "pending", attempt, str(ex)[:500], now_iso(), request_id),
                        )
                        c.commit()
                    results.append({"id": request_id, "status": "failed" if final else "retrying", "error": str(ex)[:200]})
            self._ok({"processed": len(results), "results": results}, f"处理 {len(results)} 个证书申请")
            return

        if self.command == "POST" and sub == "/certificates/bind":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "modify_hosts_certificate"):
                self._err("当前加速插件不支持证书绑定", 400)
                return
            site_id = str(body.get("siteId") or "").strip()
            hosts = body.get("hosts") if isinstance(body.get("hosts"), list) else []
            cert_type = str(body.get("certType") or "managed").strip() or "managed"
            cert_id = str(body.get("certId") or "").strip()
            cert_info = body.get("certInfo") if isinstance(body.get("certInfo"), dict) else None

            # A panel-issued CertId is NOT always usable at EdgeOne: for Let's
            # Encrypt certs remoteCertId is the domain name, and a Tencent cert
            # from a different account is account-scoped. Passing either straight
            # to ModifyHostsCertificate fails with "FailedOperation". Resolve a
            # real EdgeOne-usable CertId by uploading/reusing the PEM when the
            # id matches one of this user's panel certificates.
            if cert_id:
                panel_cert = None
                try:
                    with conn() as c:
                        panel_cert = c.execute(
                            """SELECT * FROM ssl_certificates
                               WHERE userId = ? AND remoteCertId = ? LIMIT 1""",
                            (uid, cert_id),
                        ).fetchone()
                except Exception:
                    panel_cert = None
                if panel_cert is not None:
                    accel_cred_id = int(auth["credential"]["id"] or 0)
                    accel_secrets = self._credential_secrets(auth["credential"])
                    try:
                        resolved = _edge_cert_id_for_ssl_cert(self, uid, panel_cert, accel_secrets, accel_cred_id)
                        if resolved:
                            cert_id = resolved
                    except TencentSslApiError as exc:
                        self._err(f"证书无法绑定到 EdgeOne：{exc}", int(getattr(exc, "status", 400) or 400))
                        return
                    except Exception as exc:
                        self._err(f"证书无法绑定到 EdgeOne：{exc}", 400)
                        return

            data = api.modify_hosts_certificate(site_id, hosts, cert_type, cert_id or None, cert_info)
            self._ok(data, "绑定加速证书成功")
            return

        if self.command == "GET" and sub == "/certificates":
            auth = auth_ctx()
            api = auth.get("api")
            if api is None or not hasattr(api, "describe_host_certificates"):
                self._err("当前加速插件不支持证书查询", 400)
                return
            site_id = str(first_or_none(q, "siteId") or "").strip()
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            hosts = [str(x).strip() for x in (q.get("hosts") or []) if str(x).strip()]
            data = api.describe_host_certificates(site_id, hosts)
            if isinstance(data, dict) and "items" in data and "certificates" not in data:
                data["certificates"] = data.get("items") or []
            self._ok(data, "获取加速证书列表成功")
            return

        self._err("接口不存在", 404)
    except Exception as e:
        self._err(str(e), int(getattr(e, "status", 400) or 400))


def _dns_records_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/dns-records") :] or "/"
    body = self._json_body(b)
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return
    ip = self._client_ip()

    # Routes that do not require a DNS credential up-front
    needs_dns_ctx = True
    if self.command == "GET" and sub == "/history":
        needs_dns_ctx = False
    elif self.command == "POST" and re.fullmatch(r"/history/(\d+)/rollback", sub):
        # Resolve provider API from the history row's credentialId (or query) later.
        needs_dns_ctx = False
    elif self.command == "GET" and sub == "/templates":
        needs_dns_ctx = False
    elif self.command == "POST" and sub == "/templates":
        needs_dns_ctx = False
    elif self.command == "DELETE" and re.fullmatch(r"/templates/(\d+)", sub):
        needs_dns_ctx = False
    elif self.command == "POST" and sub == "/templates/apply":
        needs_dns_ctx = True
    elif self.command == "POST" and sub == "/propagate-check":
        needs_dns_ctx = False

    if not needs_dns_ctx:
        # Provide safe defaults for helpers referenced in extras that may read these
        provider = ""
        api = None
        is_cf = False
        cf = None
        dnspod = None
        dns_credential_id = 0
        ctx = {"credential": {"id": 0}, "provider": "", "api": None}
    else:
        try:
            ctx = self._dns_context(uid, q)
        except Exception as e:
            self._err(str(e), 400)
            return
        provider = ctx["provider"]
        api = ctx["api"]
        is_cf = provider == "cloudflare"
        cf = ctx.get("cf")
        dnspod = ctx.get("dnspod")
        dns_credential_id = int(ctx["credential"]["id"] or 0)

    def map_zone(zone: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(zone, dict):
            return {"id": "", "name": "", "status": "active", "recordCount": None, "updatedAt": None}
        out = {
            "id": str(zone.get("id") or ""),
            "name": str(zone.get("name") or ""),
            "status": str(zone.get("status") or "active"),
            "recordCount": zone.get("recordCount"),
            "updatedAt": zone.get("updatedAt"),
        }
        if isinstance(zone.get("nameServers"), list):
            out["nameServers"] = [str(x) for x in zone.get("nameServers") if str(x or "").strip()]
        return out

    def map_record(zone_id: str, zone_name: str, row: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(row) if isinstance(row, dict) else {}
        out["zoneId"] = zone_id
        out["zoneName"] = zone_name
        out["meta"] = {"raw": row}
        if out.get("proxied") is None and provider != "cloudflare":
            out["proxied"] = False
        return out

    def supports_status_flag() -> bool:
        return bool(getattr(api, "supports_status", False))

    def api_error_status(exc: Exception) -> int:
        if isinstance(exc, (DnsProviderApiError, CloudflareApiError, DnspodApiError)):
            return int(getattr(exc, "status", 400) or 400)
        return 400

    def normalize_host(value: Any) -> str:
        return self._norm_hostname(value)

    def parse_json_dict(raw_value: Any) -> Dict[str, Any]:
        if isinstance(raw_value, dict):
            return dict(raw_value)
        if raw_value is None:
            return {}
        try:
            parsed = json.loads(str(raw_value or ""))
        except Exception:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}

    def state_table_ready() -> bool:
        return table_exists("dns_record_acceleration_states")

    def load_acceleration_state(zone_id: str, record_id: str, record_name: str | None = None) -> Any:
        if not state_table_ready():
            return None
        with conn() as c:
            row = c.execute(
                """
                SELECT *
                FROM dns_record_acceleration_states
                WHERE userId = ? AND dnsCredentialId = ? AND zoneId = ? AND recordId = ?
                LIMIT 1
                """,
                (uid, dns_credential_id, zone_id, record_id),
            ).fetchone()
            if row:
                return row
            normalized_name = normalize_host(record_name)
            if not normalized_name:
                return None
            rows = c.execute(
                """
                SELECT *
                FROM dns_record_acceleration_states
                WHERE userId = ? AND dnsCredentialId = ? AND zoneId = ? AND LOWER(TRIM(recordName)) = ?
                ORDER BY updatedAt DESC, id DESC
                LIMIT 2
                """,
                (uid, dns_credential_id, zone_id, normalized_name),
            ).fetchall()
        return rows[0] if len(rows) == 1 else None

    def list_acceleration_states(zone_id: str) -> Dict[str, Any]:
        if not state_table_ready():
            return {}
        with conn() as c:
            rows = c.execute(
                """
                SELECT *
                FROM dns_record_acceleration_states
                WHERE userId = ? AND dnsCredentialId = ? AND zoneId = ?
                """,
                (uid, dns_credential_id, zone_id),
            ).fetchall()
        return {str(row["recordId"] or ""): row for row in rows if str(row["recordId"] or "").strip()}

    def acceleration_cert_state(state_row: Any) -> Dict[str, Any]:
        """Edge certificate state of one accelerated host.

        Reads the binding this panel tracks in acceleration_cert_bindings and
        compares it with the certificate that SHOULD serve the host (see
        _effective_cert_for_host). This is what lets the plugin (and the UI) tell
        "the edge is still on an expired certificate" from "nothing to do".
        """
        empty = {
            "panelSupported": True,
            "certId": "",
            "panelDomain": "",
            "panelFingerprint": "",
            "panelExpireTime": "",
            "panelIssuer": "",
            "accelCertificateId": "",
            "accelStatus": "",
            "accelIssuer": "",
            "accelEffectiveTime": "",
            "accelExpireTime": "",
            "accelFingerprint": "",
            "accelDaysRemaining": None,
            "bindable": False,
        }
        if not state_row:
            return empty
        accel_domain = _norm_host(state_row["accelerationDomain"])
        if not accel_domain:
            return empty
        accel_cred_id = state_row["accelerationCredentialId"]
        site_id = str(state_row["accelerationSiteId"] or "").strip()
        try:
            with conn() as c:
                binding = c.execute(
                    """SELECT * FROM acceleration_cert_bindings
                       WHERE userId = ? AND accelerationCredentialId = ? AND siteId = ? AND domainName = ?
                       LIMIT 1""",
                    (uid, int(accel_cred_id or 0), site_id, accel_domain),
                ).fetchone()
        except Exception:
            binding = None
        candidates = _ssl_candidate_rows(uid)
        # Hosts that may serve this accelerated domain, best match first: the
        # accelerated host itself, then the DNS record it was created from.
        probe_hosts: List[str] = [accel_domain]
        record_name = _norm_host(state_row["recordName"])
        if record_name and record_name not in probe_hosts:
            probe_hosts.append(record_name)
        chosen = None
        for probe in probe_hosts:
            chosen = _effective_cert_for_host(uid, probe, candidates)
            if chosen is not None:
                break
        current = None
        if binding is not None:
            bound_id = str(binding["certRemoteId"] or "")
            for row in candidates:
                if str(row["remoteCertId"] or "") == bound_id and str(row["provider"] or "") == str(binding["source"] or "tencent_ssl"):
                    current = row
                    break
        best = chosen or current
        if best is not None:
            empty["certId"] = str(best["remoteCertId"] or "")
            empty["panelDomain"] = str(best["domain"] or "")
            empty["panelFingerprint"] = str(best["fingerprintSha256"] or "") if "fingerprintSha256" in best.keys() else ""
            empty["panelExpireTime"] = str(best["notAfter"] or "")
            empty["panelIssuer"] = str(best["issuer"] or "")
            empty["bindable"] = not certificate_is_expired(best["notAfter"] or "", now())
        if binding is not None:
            empty["accelCertificateId"] = str(binding["edgeCertId"] or "")
            empty["accelStatus"] = str(binding["status"] or "")
            empty["accelExpireTime"] = str(binding["notAfter"] or "")
            empty["accelFingerprint"] = str(binding["fingerprint"] or "")
            empty["accelDaysRemaining"] = certificate_days_remaining(binding["notAfter"] or "", now())
        # Acceleration plugins expose the certificate attached to a host
        # themselves; when they do, their answer wins over our stored binding.
        try:
            accel_ctx = self._acceleration_auth(uid, int(accel_cred_id or 0))
            accel_api = accel_ctx.get("api")
            if accel_api is not None and hasattr(accel_api, "describe_host_certificates"):
                listed = accel_api.describe_host_certificates(site_id, [accel_domain])
                for item in (listed.get("items") or []):
                    if accel_domain not in [_norm_host(h) for h in (item.get("hosts") or [item.get("host")] or [])]:
                        continue
                    live_id = str(item.get("certificateId") or "").strip()
                    if live_id:
                        empty["accelCertificateId"] = live_id
                    expire = item.get("expireTime")
                    if expire:
                        empty["accelExpireTime"] = str(expire)
                        empty["accelDaysRemaining"] = certificate_days_remaining(expire, now())
                    if item.get("issuer"):
                        empty["accelIssuer"] = str(item.get("issuer"))
                    if item.get("effectiveTime"):
                        empty["accelEffectiveTime"] = str(item.get("effectiveTime"))
                    if item.get("status"):
                        empty["accelStatus"] = str(item.get("status"))
                    break
        except Exception:
            pass
        return empty

    def build_acceleration_state_payload(state_row: Any) -> Dict[str, Any]:
        original = parse_json_dict(state_row["originalRecord"] if state_row else None)
        target = str((state_row["accelerationTarget"] if state_row else None) or "").strip()
        enabled = bool(int(state_row["enabled"] or 0)) if state_row else False
        has_original = bool(original.get("type") and original.get("value"))
        ui_state = "deploying"
        if state_row:
            accel_domain = str((state_row["accelerationDomain"] if state_row else None) or "").strip()
            if not target or not accel_domain:
                ui_state = "deploying"
            else:
                cached_status_key = _accel_domain_status_cache_key(uid, state_row['accelerationCredentialId'], state_row['accelerationSiteId'], accel_domain)
                cached_ui = cache_get(cached_status_key)
                if cached_ui is not None and isinstance(cached_ui, str):
                    ui_state = cached_ui
        payload = {
            "enabled": enabled,
            "source": "state",
            "restorable": has_original,
            "uiState": ui_state,
            "provider": str((state_row["accelerationProvider"] if state_row else None) or "edgeone").strip() or "edgeone",
            "credentialId": int(state_row["accelerationCredentialId"]) if state_row and state_row["accelerationCredentialId"] is not None else None,
            "siteId": str((state_row["accelerationSiteId"] if state_row else None) or "").strip() or None,
            "domainName": str((state_row["accelerationDomain"] if state_row else None) or "").strip() or None,
            "target": target or None,
            "originalRecord": {
                "type": str(original.get("type") or "").strip() or None,
                "value": str(original.get("value") or "").strip() or None,
                "ttl": original.get("ttl"),
                "proxied": original.get("proxied"),
                "remark": original.get("remark"),
                "line": original.get("line"),
                "priority": original.get("priority"),
                "weight": original.get("weight"),
            },
        }
        # Certificate state is what the BaoTa plugin reports as 加速证书检测;
        # without it every accelerated host looked like "未纳入".
        try:
            payload["certificate"] = acceleration_cert_state(state_row)
            payload["accelDaysRemaining"] = payload["certificate"].get("accelDaysRemaining")
            payload["accelCertificateId"] = payload["certificate"].get("accelCertificateId")
        except Exception:
            payload["certificate"] = None
        return payload

    def attach_acceleration_state(record: Dict[str, Any], state_row: Any = None) -> Dict[str, Any]:
        if not isinstance(record, dict):
            return record
        row = state_row or load_acceleration_state(str(record.get("zoneId") or ""), str(record.get("id") or ""), str(record.get("name") or ""))
        if not row:
            return record
        next_record = dict(record)
        next_record["acceleration"] = build_acceleration_state_payload(row)
        return next_record

    def delete_acceleration_state(state_row: Any = None, zone_id: str | None = None, record_id: str | None = None) -> None:
        if not state_table_ready():
            return
        with conn() as c:
            if state_row is not None and state_row["id"] is not None:
                c.execute("DELETE FROM dns_record_acceleration_states WHERE id = ?", (int(state_row["id"]),))
            elif zone_id and record_id:
                c.execute(
                    """
                    DELETE FROM dns_record_acceleration_states
                    WHERE userId = ? AND dnsCredentialId = ? AND zoneId = ? AND recordId = ?
                    """,
                    (uid, dns_credential_id, zone_id, record_id),
                )
            c.commit()

    def cleanup_edgeone_side(state_row: Any) -> Dict[str, Any]:
        """Remove the cloud-side EdgeOne acceleration domain when its DNS
        record is being deleted. Without this the EdgeOne domain becomes an
        orphan (keeps serving/billing) after the DNS record disappears."""
        result = {"attempted": False, "deleted": False, "error": ""}
        try:
            accel_cred_id = state_row["accelerationCredentialId"] if state_row is not None else None
            accel_site_id = str((state_row["accelerationSiteId"] if state_row is not None else "") or "").strip()
            accel_domain = str((state_row["accelerationDomain"] if state_row is not None else "") or "").strip()
            if not accel_cred_id or not accel_site_id or not accel_domain:
                return result
            result["attempted"] = True
            accel_ctx = self._acceleration_auth(uid, int(accel_cred_id))
            accel_api = accel_ctx.get("api")
            if accel_api is not None and hasattr(accel_api, "delete_acceleration_domains"):
                accel_api.delete_acceleration_domains(accel_site_id, [accel_domain])
                result["deleted"] = True
                try:
                    cache_delete_pattern(f"acceleration:domain-status:cred:{int(accel_cred_id)}:*")
                except Exception:
                    pass
        except Exception as exc:
            result["error"] = str(exc)[:300]
        return result

    def persist_acceleration_state(
        state_row: Any | None,
        zone_id: str,
        zone_name: str,
        record: Dict[str, Any],
        acceleration_info: Dict[str, Any],
        original_record: Dict[str, Any],
    ) -> None:
        if not state_table_ready() or not isinstance(record, dict):
            return
        record_id = str(record.get("id") or "").strip()
        record_name = normalize_host(record.get("name"))
        if not record_id or not record_name:
            return
        params = (
            normalize_host(zone_name),
            record_id,
            record_name,
            str(acceleration_info.get("provider") or "edgeone").strip() or "edgeone",
            int(acceleration_info["credentialId"]) if acceleration_info.get("credentialId") is not None else None,
            str(acceleration_info.get("siteId") or "").strip() or None,
            normalize_host(acceleration_info.get("domainName")),
            normalize_host(acceleration_info.get("target")),
            json.dumps(original_record or {}, ensure_ascii=False),
            json.dumps(record or {}, ensure_ascii=False),
        )
        with conn() as c:
            if state_row is not None and state_row["id"] is not None:
                c.execute(
                    """
                    UPDATE dns_record_acceleration_states
                    SET zoneName = ?, recordId = ?, recordName = ?, accelerationProvider = ?,
                        accelerationCredentialId = ?, accelerationSiteId = ?, accelerationDomain = ?,
                        accelerationTarget = ?, originalRecord = ?, acceleratedRecord = ?,
                        enabled = 1, updatedAt = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (*params, int(state_row["id"])),
                )
            else:
                c.execute(
                    """
                    INSERT INTO dns_record_acceleration_states (
                      userId, dnsCredentialId, zoneId, zoneName, recordId, recordName,
                      accelerationProvider, accelerationCredentialId, accelerationSiteId,
                      accelerationDomain, accelerationTarget, originalRecord, acceleratedRecord,
                      enabled, createdAt, updatedAt
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (
                        uid,
                        dns_credential_id,
                        zone_id,
                        *params,
                    ),
                )
            c.commit()

    def sync_acceleration_state_after_manual_update(zone_id: str, mapped_record: Dict[str, Any]) -> None:
        state_row = load_acceleration_state(zone_id, str(mapped_record.get("id") or ""), str(mapped_record.get("name") or ""))
        if not state_row:
            return
        target = normalize_host(state_row["accelerationTarget"])
        current_type = str(mapped_record.get("type") or "").strip().upper()
        current_value = normalize_host(mapped_record.get("value"))
        if current_type == "CNAME" and target and current_value == target:
            original = parse_json_dict(state_row["originalRecord"])
            persist_acceleration_state(
                state_row,
                zone_id,
                str(mapped_record.get("zoneName") or ""),
                mapped_record,
                {
                    "provider": state_row["accelerationProvider"],
                    "credentialId": state_row["accelerationCredentialId"],
                    "siteId": state_row["accelerationSiteId"],
                    "domainName": state_row["accelerationDomain"],
                    "target": state_row["accelerationTarget"],
                },
                original,
            )
            return
        delete_acceleration_state(state_row=state_row)

    def list_records_for_name(zone_id: str, zone_name: str, fqdn_name: str) -> List[Dict[str, Any]]:
        try:
            result = api.list_records(zone_id, 1, 200, {"name": fqdn_name, "subDomain": fqdn_name})
            rows = result.get("records") if isinstance(result, dict) else []
            return [
                map_record(zone_id, zone_name, row)
                for row in rows
                if isinstance(row, dict) and normalize_host(row.get("name")) == normalize_host(fqdn_name)
            ]
        except Exception:
            return []

    def update_managed_record(zone_id: str, zone_name: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        record = api.update_record(
            zone_id,
            record_id,
            {
                "name": params.get("name"),
                "type": params.get("type"),
                "value": params.get("value"),
                "ttl": params.get("ttl"),
                "priority": params.get("priority"),
                "weight": params.get("weight"),
                "line": params.get("line"),
                "remark": params.get("remark"),
                "proxied": params.get("proxied"),
            },
        )
        return map_record(zone_id, zone_name, record)

    def build_edgeone_domain_config_from_record(fqdn_name: str, record: Dict[str, Any] | None) -> Dict[str, Any]:
        source_record = dict(record or {})
        record_type = str(source_record.get("type") or "").strip().upper()
        origin_value = str(source_record.get("value") or "").strip()
        normalized_domain = normalize_host(fqdn_name)
        if record_type not in {"A", "AAAA", "CNAME"}:
            raise ValueError("仅支持 A、AAAA、CNAME 记录自动创建 EdgeOne 加速域名")
        if not origin_value:
            raise ValueError(f"记录 {normalized_domain} 缺少源站地址，无法自动创建 EdgeOne 加速域名")
        if record_type == "CNAME" and normalize_host(origin_value) == normalized_domain:
            raise ValueError(f"记录 {normalized_domain} 当前指向自身，无法作为 EdgeOne 回源地址")
        return {
            "domainName": normalized_domain,
            "originType": "IP_DOMAIN",
            "originValue": origin_value,
            "hostHeader": normalized_domain,
            "originProtocol": "FOLLOW",
            "httpOriginPort": 80,
            "httpsOriginPort": 443,
            "ipv6Status": "follow",
        }

    def resolve_edgeone_acceleration_target(
        zone_name: str,
        fqdn_name: str,
        acceleration_credential_id: Any = None,
        source_record: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        provider_types = tuple(x for x in SUPPORTED_ACCELERATION_PROVIDER_TYPES if str(x or "").strip())
        if not provider_types:
            raise ValueError("当前未启用加速服务商")
        with conn() as c:
            if acceleration_credential_id is not None:
                rows = c.execute(
                    f"""
                    SELECT *
                    FROM dns_credentials
                    WHERE userId = ? AND id = ? AND provider IN ({SUPPORTED_ACCELERATION_PROVIDER_SQL})
                    ORDER BY isDefault DESC, createdAt ASC, id ASC
                    """,
                    (uid, int(acceleration_credential_id), *provider_types),
                ).fetchall()
            else:
                rows = c.execute(
                    f"""
                    SELECT *
                    FROM dns_credentials
                    WHERE userId = ? AND provider IN ({SUPPORTED_ACCELERATION_PROVIDER_SQL})
                    ORDER BY isDefault DESC, createdAt ASC, id ASC
                    """,
                    (uid, *provider_types),
                ).fetchall()
        if not rows:
            raise ValueError("未找到可用的 EdgeOne 加速凭证")

        normalized_zone = normalize_host(zone_name)
        normalized_domain = normalize_host(fqdn_name)
        found_site = False
        found_domain = False
        cname_pending = False
        first_error = ""
        pending_message = ""

        for row in rows:
            try:
                provider_name = str(row["provider"] or "").strip().lower()
                if provider_name not in provider_types:
                    continue
                plugin = build_acceleration_plugin(provider_name, self._credential_secrets(row))
                api = getattr(plugin, "api", None)
                site = None
                if api is not None and hasattr(api, "find_zone_by_name"):
                    site = api.find_zone_by_name(normalized_zone)
                elif hasattr(plugin, "discover_site"):
                    site = plugin.discover_site(normalized_zone)
                if not isinstance(site, dict):
                    continue
                found_site = True
                site_id = str(site.get("siteId") or site.get("zoneId") or "").strip()
                if not site_id or api is None or not hasattr(api, "get_acceleration_domain"):
                    continue
                domain = api.get_acceleration_domain(site_id, normalized_domain)
                if not isinstance(domain, dict):
                    if source_record is None or not hasattr(api, "upsert_acceleration_domain"):
                        continue
                    domain = api.upsert_acceleration_domain(
                        site_id,
                        normalized_domain,
                        build_edgeone_domain_config_from_record(normalized_domain, source_record),
                    )
                if not isinstance(domain, dict):
                    continue
                found_domain = True
                target = str(domain.get("cnameTarget") or "").strip()
                if not target:
                    cname_pending = True
                    pending_message = f"EdgeOne 已自动创建加速域名 {normalized_domain}，但当前还未分配 CNAME"
                    verify_name = str(domain.get("verifyRecordName") or "").strip()
                    verify_value = str(domain.get("verifyRecordValue") or "").strip()
                    verify_type = str(domain.get("verifyRecordType") or "TXT").strip() or "TXT"
                    if verify_name and verify_value:
                        pending_message = (
                            f"{pending_message}，请先完成验证记录：{verify_name} {verify_type} {verify_value}"
                        )
                    continue
                return {
                    "provider": provider_name,
                    "credentialId": int(row["id"] or 0),
                    "credentialName": str(row["name"] or ""),
                    "siteId": site_id,
                    "siteName": str(site.get("zoneName") or site.get("siteName") or normalized_zone),
                    "domainName": str(domain.get("domainName") or normalized_domain),
                    "target": target,
                    "domain": domain,
                }
            except Exception as exc:
                if not first_error:
                    first_error = str(exc)
                continue

        if found_domain or cname_pending:
            raise ValueError(pending_message or "当前 EdgeOne 加速域名尚未分配 CNAME，请稍后重试")
        if found_site:
            if first_error:
                raise ValueError(first_error)
            raise ValueError(f"请先在 EdgeOne 加速里创建域名 {normalized_domain}")
        if first_error:
            raise ValueError(first_error)
        raise ValueError(f"未找到域名 {normalized_zone} 对应的 EdgeOne 站点")

    if self.command == "GET" and sub == "/zones":
        page = p_int(first_or_none(q, "page") or "1", 1, 100000)
        page_size = p_int(first_or_none(q, "pageSize") or "20", 20, 100)
        keyword = first_or_none(q, "keyword")
        cred_id = ctx["credential"]["id"]
        ck = zones_key(cred_id, page=page, pageSize=page_size, keyword=keyword)
        cached = cache_get(ck)
        if cached is not None:
            self._ok(cached, "获取域名列表成功")
            return
        try:
            result = api.list_zones(page, page_size, keyword)
            zones_raw = result.get("zones") if isinstance(result, dict) else []
            zones = [map_zone(z) for z in zones_raw if isinstance(z, dict)]
            total = int(result.get("total")) if isinstance(result, dict) and result.get("total") is not None else len(zones)
            data = {"zones": zones, "total": total, "page": page, "pageSize": page_size}
            cache_set(ck, data, (get_provider_capabilities(provider) or {}).get("domainCacheTtl", 300))
            self._ok(data, "获取域名列表成功")
        except (DnsProviderApiError, CloudflareApiError, DnspodApiError) as e:
            self._err(str(e), getattr(e, "status", 400))
        return

    if self.command == "POST" and sub == "/zones":
        domains = self._parse_domains(body.get("domains") if "domains" in body else body.get("domain") if "domain" in body else body.get("text"))
        if not domains:
            self._err("缺少必需参数: domains", 400)
            return

        account_id = ""
        if provider == "cloudflare":
            account_id = str(ctx["credential"]["accountId"] or "").strip()
            if not account_id and cf is not None:
                try:
                    account_id = cf.get_default_account_id()
                except Exception:
                    account_id = ""
            if not account_id:
                self._err("缺少 Cloudflare Account ID，请在凭证中填写 accountId 或授予账户读取权限", 400)
                return

        results = []
        for domain in domains:
            try:
                create_kwargs = {}
                if provider == "cloudflare" and account_id:
                    create_kwargs["account_id"] = account_id
                existed = False
                existed_zone = None
                try:
                    existed_zone = api.get_zone_by_name(domain)
                except Exception:
                    existed_zone = None
                if existed_zone:
                    zone = existed_zone
                    existed = True
                else:
                    zone = api.create_zone(domain, **create_kwargs)
                name_servers = zone.get("nameServers") if isinstance(zone, dict) and isinstance(zone.get("nameServers"), list) else None
                results.append(
                    {
                        "domain": domain,
                        "success": True,
                        "existed": existed,
                        "zone": {"id": str(zone.get("id") or ""), "name": str(zone.get("name") or domain), "status": str(zone.get("status") or "active")},
                        "nameServers": name_servers,
                    }
                )
                create_log(
                    user_id=uid,
                    action="CREATE",
                    resource_type="ZONE",
                    domain=str(zone.get("name") or domain),
                    record_name="add_zone",
                    status="SUCCESS",
                    ip_address=ip,
                    new_value=json.dumps({"zoneId": zone.get("id"), "domain": zone.get("name") or domain, "status": zone.get("status"), "nameServers": name_servers, "existed": existed}, ensure_ascii=False),
                )
            except Exception as e:
                results.append({"domain": domain, "success": False, "error": str(e)})
                try:
                    create_log(
                        user_id=uid,
                        action="CREATE",
                        resource_type="ZONE",
                        domain=domain,
                        record_name="add_zone",
                        status="FAILED",
                        ip_address=ip,
                        error_message=str(e),
                        new_value=json.dumps({"domain": domain}, ensure_ascii=False),
                    )
                except Exception:
                    pass
        cache_delete_pattern(f"dns:zones:cred:{ctx['credential']['id']}:*")
        self._ok({"results": results}, "添加域名完成")
        return

    m = re.fullmatch(r"/zones/([^/]+)", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        try:
            zone = api.get_zone(zone_id)
            self._ok({"zone": map_zone(zone)}, "获取域名详情成功")
        except (DnsProviderApiError, CloudflareApiError, DnspodApiError) as e:
            self._err(str(e), getattr(e, "status", 400))
        return

    m = re.fullmatch(r"/zones/([^/]+)", sub)
    if self.command == "DELETE" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        zone_name = zone_id
        try:
            zone = api.get_zone(zone_id)
            zone_name = str(zone.get("name") or zone_id)
        except Exception:
            pass
        try:
            ok = api.delete_zone(zone_id)
            create_log(
                user_id=uid,
                action="DELETE",
                resource_type="ZONE",
                domain=zone_name,
                record_name="delete_zone",
                status="SUCCESS" if ok else "FAILED",
                ip_address=ip,
                new_value=json.dumps({"zoneId": zone_id, "domain": zone_name, "deleted": ok}, ensure_ascii=False),
            )
            cache_delete_pattern(f"dns:zones:cred:{ctx['credential']['id']}:*")
            self._ok({"deleted": ok}, "删除域名成功")
        except Exception as e:
            try:
                create_log(
                    user_id=uid,
                    action="DELETE",
                    resource_type="ZONE",
                    domain=zone_name,
                    record_name="delete_zone",
                    status="FAILED",
                    ip_address=ip,
                    error_message=str(e),
                )
            except Exception:
                pass
            code = e.status if isinstance(e, (DnsProviderApiError, CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/zones/([^/]+)/records", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        page = p_int(first_or_none(q, "page") or "1", 1, 100000)
        page_size = p_int(first_or_none(q, "pageSize") or "20", 20, 500)
        keyword = first_or_none(q, "keyword")
        sub_domain = first_or_none(q, "subDomain")
        rtype = first_or_none(q, "type")
        value = first_or_none(q, "value")
        cred_id = ctx["credential"]["id"]
        ck = records_key(cred_id, zone_id, page=page, pageSize=page_size, keyword=keyword, subDomain=sub_domain, type=rtype, value=value)
        cached = cache_get(ck)
        if cached is not None:
            self._ok(cached, "获取 DNS 记录成功")
            return
        try:
            zone = api.get_zone(zone_id)
            zone_name = str(zone.get("name") or zone_id)
            filters: Dict[str, Any] = {}
            if sub_domain:
                filters["name"] = sub_domain
                filters["subDomain"] = sub_domain
            if rtype:
                filters["type"] = rtype
            if value:
                filters["value"] = value
                filters["content"] = value
            if keyword:
                filters["keyword"] = keyword
            res = api.list_records(zone_id, page, page_size, filters)
            records_raw = res.get("records") if isinstance(res, dict) else []
            state_map = list_acceleration_states(zone_id)
            records = [
                attach_acceleration_state(map_record(zone_id, zone_name, r), state_map.get(str(r.get("id") or "")))
                for r in records_raw
                if isinstance(r, dict)
            ]
            if keyword:
                kw = keyword.lower()
                records = [r for r in records if kw in str(r.get("name") or "").lower() or kw in str(r.get("value") or "").lower()]
            caps = get_provider_capabilities(provider) or {}
            total = int(res.get("total")) if isinstance(res, dict) and res.get("total") is not None else len(records)
            data = {
                "records": records,
                "total": total,
                "page": page,
                "pageSize": page_size,
                "capabilities": {
                    "supportsWeight": bool(caps.get("supportsWeight")),
                    "supportsLine": bool(caps.get("supportsLine")),
                    "supportsStatus": bool(caps.get("supportsStatus")),
                    "supportsRemark": bool(caps.get("supportsRemark")),
                },
            }
            cache_set(ck, data, caps.get("recordCacheTtl", 120))
            self._ok(data, "获取 DNS 记录成功")
        except Exception as e:
            self._err(str(e), api_error_status(e))
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/batch-status", sub)
    if self.command == "PUT" and m:
        if not supports_status_flag():
            self._err("当前提供商不支持启用/禁用记录", 400)
            return
        zone_id = urllib.parse.unquote(m.group(1))
        record_ids = self._parse_record_ids(body.get("recordIds"), 200)
        enabled = body.get("enabled")
        if not record_ids:
            self._err("缺少参数: recordIds (string[])", 400)
            return
        if enabled is None:
            self._err("缺少参数: enabled (boolean)", 400)
            return
        results = []
        for rid in record_ids:
            try:
                api.set_record_status(zone_id, rid, bool(enabled))
                results.append({"recordId": rid, "success": True})
            except Exception as e:
                results.append({"recordId": rid, "success": False, "error": str(e)})
        success_count = len([x for x in results if x.get("success")])
        failed_count = len(results) - success_count
        cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
        self._ok({"successCount": success_count, "failedCount": failed_count, "results": results}, "批量状态更新完成（部分失败）" if failed_count else "批量状态更新成功")
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/([^/]+)/acceleration", sub)
    if self.command == "PUT" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        enabled = body.get("enabled")
        if enabled is None:
            self._err("缺少参数: enabled (boolean)", 400)
            return
        enabled = bool(enabled)
        acceleration_credential_id = body.get("accelerationCredentialId")
        if acceleration_credential_id in ("", None):
            acceleration_credential_id = first_or_none(q, "accelerationCredentialId")
        if acceleration_credential_id not in ("", None):
            try:
                acceleration_credential_id = int(acceleration_credential_id)
            except Exception:
                self._err("accelerationCredentialId 必须是数字", 400)
                return
        else:
            acceleration_credential_id = None
        restore_record_raw = body.get("restoreRecord") if isinstance(body.get("restoreRecord"), dict) else None
        restore_record_payload: Dict[str, Any] | None = None
        if restore_record_raw:
            restore_type = str(restore_record_raw.get("type") or "").strip().upper()
            restore_value = str(restore_record_raw.get("value") or "").strip()
            if restore_type and restore_value:
                restore_record_payload = {
                    "type": restore_type,
                    "value": restore_value,
                    "ttl": restore_record_raw.get("ttl"),
                    "line": restore_record_raw.get("line"),
                    "priority": restore_record_raw.get("priority"),
                    "weight": restore_record_raw.get("weight"),
                    "remark": restore_record_raw.get("remark"),
                    "proxied": restore_record_raw.get("proxied"),
                }
        try:
            zone = api.get_zone(zone_id)
            zone_name = str(zone.get("name") or zone_id)
            record_raw = api.get_record(zone_id, record_id)
            current_record = map_record(zone_id, zone_name, record_raw)

            fqdn_name = str(current_record.get("name") or "").strip()
            if not fqdn_name:
                self._err("记录名称不能为空", 400)
                return

            state_row = load_acceleration_state(zone_id, record_id, fqdn_name)

            if enabled:
                record_type = str(current_record.get("type") or "").strip().upper()
                if normalize_host(fqdn_name) == normalize_host(zone_name):
                    self._err("根域名暂不支持自动切换为 EdgeOne CNAME", 400)
                    return
                if record_type not in {"A", "AAAA", "CNAME"} and state_row is None:
                    self._err("仅支持 A、AAAA、CNAME 记录启用 EdgeOne 加速", 400)
                    return
                same_name_records = list_records_for_name(zone_id, zone_name, fqdn_name)
                conflicts = [r for r in same_name_records if str(r.get("id") or "") != record_id]
                if conflicts:
                    self._err("同名存在其他记录，无法自动切换为 CNAME，请先清理同名记录", 400)
                    return

                original_record = parse_json_dict(state_row["originalRecord"]) if state_row else {
                    "id": str(current_record.get("id") or ""),
                    "zoneId": str(current_record.get("zoneId") or zone_id),
                    "zoneName": str(current_record.get("zoneName") or zone_name),
                    "name": fqdn_name,
                    "type": current_record.get("type"),
                    "value": current_record.get("value"),
                    "ttl": current_record.get("ttl"),
                    "line": current_record.get("line"),
                    "weight": current_record.get("weight"),
                    "priority": current_record.get("priority"),
                    "status": current_record.get("status"),
                    "remark": current_record.get("remark"),
                    "proxied": current_record.get("proxied"),
                    "updatedAt": current_record.get("updatedAt"),
                }
                source_record = original_record or dict(current_record)
                acceleration_info = resolve_edgeone_acceleration_target(
                    zone_name,
                    fqdn_name,
                    acceleration_credential_id,
                    source_record,
                )
                mapped = update_managed_record(zone_id, zone_name, record_id, {
                    "name": fqdn_name,
                    "type": "CNAME",
                    "value": acceleration_info.get("target"),
                    "ttl": current_record.get("ttl"),
                    "proxied": False,
                    "line": current_record.get("line"),
                    "priority": None,
                    "weight": None,
                    "remark": current_record.get("remark"),
                })
                persist_acceleration_state(state_row, zone_id, zone_name, mapped, acceleration_info, original_record)
                state_row = load_acceleration_state(zone_id, str(mapped.get("id") or ""), str(mapped.get("name") or ""))
                mapped = attach_acceleration_state(mapped, state_row)
                cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
                # Bind the domain's current certificate to the just-created
                # EdgeOne acceleration domain so the edge doesn't serve the
                # cloud's own (possibly stale/expired) default cert.
                accel_cert_sync = None
                try:
                    cert_row = _best_cert_for_domain(uid, fqdn_name)
                    if cert_row is not None:
                        accel_cert_sync = _sync_cert_to_edgeone(self, uid, cert_row)
                except Exception as exc:
                    accel_cert_sync = {"synced": 0, "error": str(exc)[:200]}
                self._ok(
                    {
                        "record": mapped,
                        "acceleration": mapped.get("acceleration"),
                        "applied": True,
                        "restored": False,
                        "edgeoneCertSync": accel_cert_sync,
                    },
                    "已启用 EdgeOne 加速，原记录已暂存"
                    + (f"（已同步证书到加速域名 {accel_cert_sync['synced']} 个）" if accel_cert_sync and accel_cert_sync.get("synced") else ""),
                )
                return

            if state_row is None:
                original_record = {}
            else:
                original_record = parse_json_dict(state_row["originalRecord"])

            if not original_record and not restore_record_payload:
                current_type = str(current_record.get("type") or "").strip().upper()
                if current_type != "CNAME":
                    self._err("未检测到 EdgeOne 加速记录", 400)
                    return
                self._ok(
                    {
                        "applied": False,
                        "restored": False,
                        "needsRestoreInput": True,
                        "currentRecord": current_record,
                        "suggestedType": "A",
                    },
                    "未找到原始记录快照，请填写恢复的源站信息后再取消加速",
                )
                return

            resolved: Dict[str, Any] = dict(original_record or {})
            if restore_record_payload:
                for k, v in restore_record_payload.items():
                    if v is not None:
                        resolved[k] = v

            mapped = update_managed_record(zone_id, zone_name, record_id, {
                "name": resolved.get("name") or fqdn_name,
                "type": resolved.get("type"),
                "value": resolved.get("value"),
                "ttl": resolved.get("ttl"),
                "proxied": resolved.get("proxied"),
                "line": resolved.get("line"),
                "priority": resolved.get("priority"),
                "weight": resolved.get("weight"),
                "remark": resolved.get("remark"),
            })
            # Also pause the EdgeOne-side acceleration domain — previously the
            # DNS record was restored but the EdgeOne domain stayed online,
            # leaving the two sides out of sync (billing + stale config).
            edgeone_paused = False
            if state_row is not None:
                try:
                    accel_cred_id = state_row["accelerationCredentialId"]
                    accel_site_id = str(state_row["accelerationSiteId"] or "").strip()
                    accel_domain = str(state_row["accelerationDomain"] or "").strip()
                    if accel_cred_id and accel_site_id and accel_domain:
                        accel_ctx = self._acceleration_auth(uid, int(accel_cred_id))
                        accel_api = accel_ctx.get("api")
                        if accel_api is not None and hasattr(accel_api, "modify_acceleration_domain_statuses"):
                            accel_api.modify_acceleration_domain_statuses(accel_site_id, [accel_domain], False)
                            edgeone_paused = True
                except Exception:
                    # Best effort: the DNS restore must not fail because the
                    # cloud-side pause did.
                    edgeone_paused = False
            if state_row is not None:
                delete_acceleration_state(state_row=state_row)
            cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
            self._ok(
                {
                    "record": mapped,
                    "applied": False,
                    "restored": True,
                    "edgeonePaused": edgeone_paused,
                },
                "已恢复原始记录并关闭 EdgeOne 加速" + ("（云端加速域名已暂停）" if edgeone_paused else "（云端加速域名可能需要手动暂停）"),
            )
        except Exception as e:
            code = e.status if isinstance(e, (DnsProviderApiError, CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/([^/]+)", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        try:
            zone = api.get_zone(zone_id)
            zone_name = str(zone.get("name") or zone_id)
            record = api.get_record(zone_id, record_id)
            mapped = attach_acceleration_state(map_record(zone_id, zone_name, record))
            self._ok({"record": mapped}, "获取记录详情成功")
        except Exception as e:
            self._err(str(e), api_error_status(e))
        return

    m = re.fullmatch(r"/zones/([^/]+)/records", sub)
    if self.command == "POST" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        name = str(body.get("name") or "").strip()
        rtype = str(body.get("type") or "").strip().upper()
        value = body.get("value")
        if not name or not rtype or value is None:
            self._err("缺少必需参数: name, type, value", 400)
            return
        try:
            zone = api.get_zone(zone_id)
            zone_name = str(zone.get("name") or zone_id)
            params = {
                "name": name,
                "type": rtype,
                "value": str(value),
                "ttl": int(body.get("ttl")) if isinstance(body.get("ttl"), (int, float)) else None,
                "priority": int(body.get("priority")) if isinstance(body.get("priority"), (int, float)) else None,
                "weight": int(body.get("weight")) if isinstance(body.get("weight"), (int, float)) else None,
                "line": body.get("line"),
                "remark": body.get("remark"),
                "proxied": bool(body.get("proxied")) if isinstance(body.get("proxied"), bool) else None,
            }
            record = api.create_record(zone_id, params)
            mapped = map_record(zone_id, zone_name, record)
            create_log(
                user_id=uid,
                action="CREATE",
                resource_type="DNS",
                domain=zone_name,
                record_name=mapped.get("name"),
                record_type=mapped.get("type"),
                new_value=json.dumps(mapped, ensure_ascii=False),
                status="SUCCESS",
                ip_address=ip,
            )
            cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
            try:
                dns_extras.insert_history(
                    conn,
                    user_id=uid,
                    credential_id=dns_credential_id,
                    zone_id=zone_id,
                    zone_name=zone_name,
                    record_id=mapped.get("id"),
                    record_name=mapped.get("name"),
                    record_type=mapped.get("type"),
                    action="CREATE",
                    new_value=mapped,
                )
            except Exception:
                pass
            self._ok({"record": mapped}, "DNS 记录创建成功", 201)
        except Exception as e:
            try:
                create_log(
                    user_id=uid,
                    action="CREATE",
                    resource_type="DNS",
                    record_name=name,
                    record_type=rtype,
                    status="FAILED",
                    error_message=str(e),
                    ip_address=ip,
                )
            except Exception:
                pass
            code = e.status if isinstance(e, (DnsProviderApiError, CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/([^/]+)", sub)
    if self.command == "PUT" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        try:
            zone = api.get_zone(zone_id)
            zone_name = str(zone.get("name") or zone_id)
            old = None
            try:
                old = api.get_record(zone_id, record_id)
            except Exception:
                old = None
            base = old if isinstance(old, dict) else {}
            rtype = str(body.get("type") or base.get("type") or "").strip().upper()
            name = str(body.get("name") or base.get("name") or "").strip()
            value = body.get("value", base.get("value") or base.get("content"))
            if not name or not rtype or value is None:
                self._err("缺少必需参数: name, type, value", 400)
                return
            params = {
                "name": name,
                "type": rtype,
                "value": str(value),
                "ttl": int(body.get("ttl")) if isinstance(body.get("ttl"), (int, float)) else base.get("ttl"),
                "priority": int(body.get("priority")) if isinstance(body.get("priority"), (int, float)) else base.get("priority"),
                "weight": int(body.get("weight")) if isinstance(body.get("weight"), (int, float)) else base.get("weight"),
                "line": body.get("line") if "line" in body else base.get("line"),
                "remark": body.get("remark") if "remark" in body else base.get("remark"),
                "proxied": body.get("proxied") if "proxied" in body else base.get("proxied"),
            }
            record = api.update_record(zone_id, record_id, params)
            mapped = map_record(zone_id, zone_name, record)
            sync_acceleration_state_after_manual_update(zone_id, mapped)
            mapped = attach_acceleration_state(mapped)
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="DNS",
                domain=zone_name,
                record_name=mapped.get("name"),
                record_type=mapped.get("type"),
                old_value=json.dumps(old, ensure_ascii=False) if old else None,
                new_value=json.dumps(mapped, ensure_ascii=False),
                status="SUCCESS",
                ip_address=ip,
            )
            cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
            try:
                dns_extras.insert_history(
                    conn,
                    user_id=uid,
                    credential_id=dns_credential_id,
                    zone_id=zone_id,
                    zone_name=zone_name,
                    record_id=mapped.get("id"),
                    record_name=mapped.get("name"),
                    record_type=mapped.get("type"),
                    action="UPDATE",
                    old_value=old,
                    new_value=mapped,
                )
            except Exception:
                pass
            self._ok({"record": mapped}, "DNS 记录更新成功")
        except Exception as e:
            try:
                create_log(user_id=uid, action="UPDATE", resource_type="DNS", status="FAILED", error_message=str(e), ip_address=ip)
            except Exception:
                pass
            code = e.status if isinstance(e, (DnsProviderApiError, CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/([^/]+)", sub)
    if self.command == "DELETE" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        try:
            zone = api.get_zone(zone_id)
            zone_name = str(zone.get("name") or zone_id)
            old = None
            try:
                old = api.get_record(zone_id, record_id)
            except Exception:
                old = None
            # Read the acceleration state BEFORE deleting anything so the
            # cloud-side EdgeOne domain can be cleaned up too.
            accel_state = None
            try:
                accel_state = load_acceleration_state(zone_id, record_id, (old or {}).get("name"))
            except Exception:
                accel_state = None
            api.delete_record(zone_id, record_id)
            edgeone_cleanup = {"attempted": False, "deleted": False, "error": ""}
            if accel_state is not None:
                edgeone_cleanup = cleanup_edgeone_side(accel_state)
            delete_acceleration_state(zone_id=zone_id, record_id=record_id)
            create_log(
                user_id=uid,
                action="DELETE",
                resource_type="DNS",
                domain=zone_name,
                record_name=old.get("name") if isinstance(old, dict) else None,
                record_type=old.get("type") if isinstance(old, dict) else None,
                old_value=json.dumps(old, ensure_ascii=False) if old else None,
                status="SUCCESS",
                ip_address=ip,
            )
            _append_dns_record_history(
                user_id=uid,
                credential_id=dns_credential_id,
                zone_id=zone_id,
                zone_name=zone_name,
                record_id=record_id,
                record_name=old.get("name") if isinstance(old, dict) else None,
                record_type=old.get("type") if isinstance(old, dict) else None,
                action="DELETE",
                old_value=old,
                new_value=None,
            )
            cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
            del_msg = "DNS 记录删除成功"
            if edgeone_cleanup.get("deleted"):
                del_msg += "，已同步删除 EdgeOne 加速域名"
            elif edgeone_cleanup.get("attempted") and edgeone_cleanup.get("error"):
                del_msg += f"（EdgeOne 加速域名清理失败：{edgeone_cleanup['error']}）"
            self._ok({"edgeoneCleanup": edgeone_cleanup}, del_msg)
        except Exception as e:
            try:
                create_log(user_id=uid, action="DELETE", resource_type="DNS", status="FAILED", error_message=str(e), ip_address=ip)
            except Exception:
                pass
            code = e.status if isinstance(e, (DnsProviderApiError, CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/batch-delete", sub)
    if self.command == "POST" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        record_ids = self._parse_record_ids(body.get("recordIds"), 200)
        if not record_ids:
            self._err("缺少参数: recordIds (string[])", 400)
            return
        results = []
        for rid in record_ids:
            try:
                old = None
                try:
                    old = api.get_record(zone_id, rid)
                except Exception:
                    old = None
                accel_state = None
                try:
                    accel_state = load_acceleration_state(zone_id, rid, (old or {}).get("name"))
                except Exception:
                    accel_state = None
                api.delete_record(zone_id, rid)
                if accel_state is not None:
                    cleanup_edgeone_side(accel_state)
                delete_acceleration_state(zone_id=zone_id, record_id=rid)
                results.append({"recordId": rid, "success": True})
                try:
                    create_log(
                        user_id=uid,
                        action="DELETE",
                        resource_type="DNS",
                        record_name=old.get("name") if isinstance(old, dict) else rid,
                        record_type=old.get("type") if isinstance(old, dict) else None,
                        old_value=json.dumps(old, ensure_ascii=False) if old else None,
                        status="SUCCESS",
                        ip_address=ip,
                    )
                    _append_dns_record_history(
                        user_id=uid,
                        credential_id=dns_credential_id,
                        zone_id=zone_id,
                        zone_name=None,
                        record_id=rid,
                        record_name=old.get("name") if isinstance(old, dict) else rid,
                        record_type=old.get("type") if isinstance(old, dict) else None,
                        action="DELETE",
                        old_value=old,
                        new_value=None,
                    )
                except Exception:
                    pass
            except Exception as e:
                results.append({"recordId": rid, "success": False, "error": str(e)})
                try:
                    create_log(
                        user_id=uid,
                        action="DELETE",
                        resource_type="DNS",
                        record_name=rid,
                        status="FAILED",
                        error_message=str(e),
                        ip_address=ip,
                    )
                except Exception:
                    pass
        success_count = len([x for x in results if x.get("success")])
        failed_count = len(results) - success_count
        cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
        self._ok({"successCount": success_count, "failedCount": failed_count, "results": results}, "批量删除完成（部分失败）" if failed_count else "批量删除成功")
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/([^/]+)/status", sub)
    if self.command == "PUT" and m:
        if not supports_status_flag():
            self._err("当前提供商不支持启用/禁用记录", 400)
            return
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        enabled = body.get("enabled")
        if enabled is None:
            self._err("缺少参数: enabled (boolean)", 400)
            return
        try:
            api.set_record_status(zone_id, record_id, bool(enabled))
            mapped = None
            try:
                zone = api.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                record = api.get_record(zone_id, record_id)
                mapped = attach_acceleration_state(map_record(zone_id, zone_name, record))
            except Exception:
                mapped = None
            cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
            self._ok({"record": mapped}, "记录状态更新成功")
        except (DnsProviderApiError, DnspodApiError) as e:
            self._err(str(e), getattr(e, "status", 400))
        return

    m = re.fullmatch(r"/zones/([^/]+)/lines", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        cred_id = ctx["credential"]["id"]
        ck = lines_key(cred_id, zone_id)
        cached = cache_get(ck)
        if cached is not None:
            self._ok(cached, "获取线路列表成功")
            return
        try:
            lines = api.get_lines(zone_id)
            data = {"lines": lines if isinstance(lines, list) else [{"code": "default", "name": "默认"}]}
            cache_set(ck, data, 3600)
            self._ok(data, "获取线路列表成功")
        except (DnsProviderApiError, DnspodApiError) as e:
            self._err(str(e), getattr(e, "status", 400))
        return

    m = re.fullmatch(r"/zones/([^/]+)/min-ttl", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        try:
            min_ttl = api.get_min_ttl(zone_id)
            self._ok({"minTTL": min_ttl}, "获取最低TTL成功")
        except (DnsProviderApiError, DnspodApiError) as e:
            self._err(str(e), getattr(e, "status", 400))
        return


    # ── DNS extras: history / templates / import-export / search / conflicts / propagate ──
    if self.command == "GET" and sub == "/history":
        zone_id = first_or_none(q, "zoneId")
        record_id = first_or_none(q, "recordId")
        page = p_int(first_or_none(q, "page") or "1", 1, 100000)
        limit = p_int(first_or_none(q, "limit") or "50", 50, 200)
        data = dns_extras.list_history(conn, uid, zone_id=zone_id, record_id=record_id, page=page, limit=limit)
        self._ok(data, "获取记录历史成功")
        return

    m = re.fullmatch(r"/history/(\d+)/rollback", sub)
    if self.command == "POST" and m:
        hid = int(m.group(1))
        row = dns_extras.get_history_row(conn, uid, hid)
        if not row:
            self._err("历史记录不存在", 404)
            return
        old_raw = row.get("oldValue")
        try:
            old = json.loads(old_raw) if isinstance(old_raw, str) else old_raw
        except Exception:
            old = None
        if not isinstance(old, dict):
            self._err("该历史记录无可回滚快照", 400)
            return
        zone_id = str(row.get("zoneId") or "")
        if not zone_id:
            self._err("历史记录缺少 zoneId", 400)
            return
        # Prefer the credential that produced the history row; fall back to request query / default.
        history_cred_id = row.get("credentialId")
        try:
            history_cred_id = int(history_cred_id) if history_cred_id is not None else 0
        except Exception:
            history_cred_id = 0
        try:
            if history_cred_id > 0:
                ctx = self._dns_context(uid, {"credentialId": [str(history_cred_id)]})
            else:
                ctx = self._dns_context(uid, q)
            api = ctx["api"]
            dns_credential_id = int(ctx["credential"]["id"] or 0)
            if not api:
                self._err("缺少可用的 DNS 凭证", 400)
                return
            zone = api.get_zone(zone_id)
            zone_name = str(zone.get("name") or row.get("zoneName") or zone_id)
            params = {
                "name": old.get("name") or row.get("recordName"),
                "type": old.get("type") or row.get("recordType"),
                "value": old.get("value") or old.get("content"),
                "ttl": old.get("ttl"),
                "priority": old.get("priority"),
                "weight": old.get("weight"),
                "line": old.get("line"),
                "remark": old.get("remark"),
                "proxied": old.get("proxied"),
            }
            if not params.get("name") or not params.get("type") or not params.get("value"):
                self._err("回滚快照缺少 name/type/value", 400)
                return
            rid = str(row.get("recordId") or "")
            if rid:
                try:
                    record = api.update_record(zone_id, rid, params)
                except DnsProviderApiError as update_exc:
                    # Only fall back to create when the record is genuinely missing.
                    status = int(getattr(update_exc, "status", 0) or 0)
                    if status in {404, 410}:
                        record = api.create_record(zone_id, params)
                    else:
                        raise
            else:
                record = api.create_record(zone_id, params)
            mapped = map_record(zone_id, zone_name, record)
            dns_extras.insert_history(
                conn,
                user_id=uid,
                credential_id=dns_credential_id,
                zone_id=zone_id,
                zone_name=zone_name,
                record_id=mapped.get("id"),
                record_name=mapped.get("name"),
                record_type=mapped.get("type"),
                action="ROLLBACK",
                old_value=None,
                new_value=mapped,
            )
            cache_delete_pattern(f"dns:records:cred:{dns_credential_id}:z:{zone_id}:*")
            self._ok({"record": mapped}, "回滚成功")
        except Exception as e:
            self._err(str(e), api_error_status(e))
        return

    if self.command == "GET" and sub == "/templates":
        self._ok({"templates": dns_extras.list_templates(conn, uid)}, "获取模板成功")
        return

    if self.command == "POST" and sub == "/templates":
        name = str(body.get("name") or "").strip()
        if not name:
            self._err("模板名称不能为空", 400)
            return
        records = body.get("records") if isinstance(body.get("records"), list) else []
        tpl = dns_extras.create_template(conn, uid, name, str(body.get("description") or ""), records)
        self._ok({"template": tpl}, "模板已创建", 201)
        return

    m = re.fullmatch(r"/templates/(\d+)", sub)
    if self.command == "DELETE" and m:
        ok = dns_extras.delete_template(conn, uid, int(m.group(1)))
        if not ok:
            self._err("模板不存在", 404)
            return
        self._ok({"ok": True}, "模板已删除")
        return

    if self.command == "POST" and sub == "/templates/apply":
        template_id = body.get("templateId")
        zone_id = str(body.get("zoneId") or "").strip()
        if not template_id or not zone_id:
            self._err("缺少 templateId 或 zoneId", 400)
            return
        tpls = {t["id"]: t for t in dns_extras.list_templates(conn, uid)}
        tpl = tpls.get(int(template_id))
        if not tpl:
            self._err("模板不存在", 404)
            return
        created = failed = 0
        results = []
        zone = api.get_zone(zone_id)
        zone_name = str(zone.get("name") or zone_id)
        for rec in tpl.get("records") or []:
            try:
                params = {
                    "name": rec.get("name"),
                    "type": rec.get("type"),
                    "value": rec.get("value") or rec.get("content"),
                    "ttl": rec.get("ttl"),
                    "priority": rec.get("priority"),
                    "weight": rec.get("weight"),
                    "line": rec.get("line"),
                    "remark": rec.get("remark"),
                }
                record = api.create_record(zone_id, params)
                mapped = map_record(zone_id, zone_name, record)
                created += 1
                results.append({"success": True, "record": mapped})
            except Exception as e:
                failed += 1
                results.append({"success": False, "error": str(e)})
        cache_delete_pattern(f"dns:records:cred:{dns_credential_id}:z:{zone_id}:*")
        self._ok({"created": created, "failed": failed, "results": results}, "模板应用完成")
        return

    m = re.fullmatch(r"/zones/([^/]+)/export", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        fmt = first_or_none(q, "format") or "json"
        zone = api.get_zone(zone_id)
        zone_name = str(zone.get("name") or zone_id)
        records_raw = dns_extras.list_all_provider_records(api, zone_id)
        records = [map_record(zone_id, zone_name, r) for r in records_raw if isinstance(r, dict)]
        content, filename = dns_extras.export_records(records, zone_name, fmt)
        self._ok({"content": content, "filename": filename, "format": fmt, "count": len(records)}, "导出成功")
        return

    m = re.fullmatch(r"/zones/([^/]+)/import", sub)
    if self.command == "POST" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        fmt = str(body.get("format") or "json")
        content = str(body.get("content") or "")
        dry = bool(body.get("dryRun"))
        try:
            rows = dns_extras.parse_import(content, fmt)
        except Exception as e:
            self._err(f"解析导入内容失败: {e}", 400)
            return
        zone = api.get_zone(zone_id)
        zone_name = str(zone.get("name") or zone_id)
        created = skipped = failed = 0
        results = []
        for rec in rows:
            if dry:
                skipped += 1
                results.append({"success": True, "dryRun": True, "record": rec})
                continue
            try:
                params = {
                    "name": rec.get("name"),
                    "type": rec.get("type"),
                    "value": rec.get("value") or rec.get("content"),
                    "ttl": rec.get("ttl"),
                    "priority": rec.get("priority"),
                    "weight": rec.get("weight"),
                    "line": rec.get("line"),
                    "remark": rec.get("remark"),
                }
                record = api.create_record(zone_id, params)
                mapped = map_record(zone_id, zone_name, record)
                created += 1
                results.append({"success": True, "record": mapped})
                dns_extras.insert_history(
                    conn,
                    user_id=uid,
                    credential_id=dns_credential_id,
                    zone_id=zone_id,
                    zone_name=zone_name,
                    record_id=mapped.get("id"),
                    record_name=mapped.get("name"),
                    record_type=mapped.get("type"),
                    action="CREATE",
                    new_value=mapped,
                )
            except Exception as e:
                failed += 1
                results.append({"success": False, "error": str(e), "record": rec})
        if not dry:
            cache_delete_pattern(f"dns:records:cred:{dns_credential_id}:z:{zone_id}:*")
        self._ok({"created": created, "skipped": skipped, "failed": failed, "results": results}, "导入完成")
        return

    if self.command == "GET" and sub == "/search":
        query_text = str(first_or_none(q, "q") or "").strip()
        limit = p_int(first_or_none(q, "limit") or "50", 50, 200)
        if not query_text:
            self._ok({"hits": []}, "搜索完成")
            return
        hits = []
        try:
            zones = api.list_zones(1, 50, None).get("zones") or []
        except Exception:
            zones = []
        for z in zones:
            if not isinstance(z, dict):
                continue
            zid = str(z.get("id") or "")
            zname = str(z.get("name") or "")
            try:
                recs = api.list_records(zid, 1, 200, {"keyword": query_text}).get("records") or []
            except Exception:
                recs = []
            for r in recs:
                if not isinstance(r, dict):
                    continue
                name = str(r.get("name") or "")
                value = str(r.get("value") or r.get("content") or "")
                if query_text.lower() not in name.lower() and query_text.lower() not in value.lower():
                    continue
                hits.append(
                    {
                        "credentialId": dns_credential_id,
                        "provider": provider,
                        "zoneId": zid,
                        "zoneName": zname,
                        "recordId": str(r.get("id") or ""),
                        "recordName": name,
                        "recordType": str(r.get("type") or ""),
                        "value": value,
                    }
                )
                if len(hits) >= limit:
                    break
            if len(hits) >= limit:
                break
        self._ok({"hits": hits}, "搜索完成")
        return

    if self.command == "POST" and sub == "/propagate-check":
        name = str(body.get("name") or "").strip()
        if not name:
            self._err("缺少 name", 400)
            return
        result = dns_extras.propagate_check(name, str(body.get("type") or "A"), body.get("expected"))
        self._ok(result, "传播检测完成")
        return

    m = re.fullmatch(r"/zones/([^/]+)/conflicts", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        zone = api.get_zone(zone_id)
        zone_name = str(zone.get("name") or zone_id)
        records_raw = dns_extras.list_all_provider_records(api, zone_id)
        records = [map_record(zone_id, zone_name, r) for r in records_raw if isinstance(r, dict)]
        conflicts = dns_extras.detect_conflicts(records)
        self._ok({"conflicts": conflicts, "scanned": len(records)}, "冲突检测完成")
        return


    if self.command == "POST" and sub == "/refresh":
        zone_id = body.get("zoneId")
        cred_id = ctx["credential"]["id"]
        cache_delete_pattern(f"dns:zones:cred:{cred_id}:*")
        cache_delete_pattern(f"dns:records:cred:{cred_id}:*")
        try:
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="DNS",
                domain=str(zone_id) if zone_id else None,
                record_name="refresh_cache",
                status="SUCCESS",
                ip_address=ip,
                new_value=json.dumps({"zoneId": str(zone_id) if zone_id else None}, ensure_ascii=False),
            )
        except Exception:
            pass
        self._ok(None, "缓存已刷新")
        return

    self._err("接口不存在", 404)


def _hostnames_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/hostnames") :] or "/"
    body = self._json_body(b)
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return
    ip = self._client_ip()
    credential_id = first_or_none(q, "credentialId")

    m = re.fullmatch(r"/([^/]+)/fallback_origin", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        try:
            ctx = self._cloudflare_token_for_zone(uid, zone_id, credential_id)
            cf: CloudflareApi = ctx["cf"]
            origin = cf.get_fallback_origin(zone_id)
            self._ok({"origin": origin}, "获取回退源成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    if self.command == "PUT" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        origin = str(body.get("origin") or "").strip()
        if not origin:
            self._err("回退源地址不能为空", 400)
            return
        try:
            ctx = self._cloudflare_token_for_zone(uid, zone_id, credential_id)
            cf: CloudflareApi = ctx["cf"]
            old_origin = cf.get_fallback_origin(zone_id)
            result = cf.update_fallback_origin(zone_id, origin)
            create_log(
                user_id=uid,
                action="UPDATE",
                resource_type="FALLBACK_ORIGIN",
                domain=zone_id,
                record_name="fallback_origin",
                old_value=json.dumps(old_origin, ensure_ascii=False) if old_origin is not None else None,
                new_value=json.dumps({"origin": origin}, ensure_ascii=False),
                status="SUCCESS",
                ip_address=ip,
            )
            self._ok({"origin": result}, "更新回退源成功")
        except Exception as e:
            try:
                create_log(
                    user_id=uid,
                    action="UPDATE",
                    resource_type="FALLBACK_ORIGIN",
                    domain=zone_id,
                    record_name="fallback_origin",
                    status="FAILED",
                    error_message=str(e),
                    ip_address=ip,
                )
            except Exception:
                pass
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        try:
            ctx = self._cloudflare_token_for_zone(uid, zone_id, credential_id)
            cf: CloudflareApi = ctx["cf"]
            hostnames = cf.list_custom_hostnames(zone_id)
            self._ok({"hostnames": hostnames}, "获取自定义主机名成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    if self.command == "POST" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        hostname = str(body.get("hostname") or "").strip()
        custom_origin_server = str(body.get("customOriginServer") or "").strip()
        if not hostname:
            self._err("缺少主机名参数", 400)
            return
        if custom_origin_server:
            if re.match(r"^https?://", custom_origin_server, re.IGNORECASE):
                self._err("自定义源服务器不支持包含 http:// 或 https://", 400)
                return
            if "*" in custom_origin_server:
                self._err("自定义源服务器不支持通配符", 400)
                return
            if ":" in custom_origin_server:
                self._err("自定义源服务器不支持端口或 IP 地址，请填写域名", 400)
                return
            if "/" in custom_origin_server or " " in custom_origin_server:
                self._err("自定义源服务器格式不正确", 400)
                return
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", custom_origin_server):
                self._err("自定义源服务器不支持 IP 地址，请填写域名", 400)
                return
        try:
            ctx = self._cloudflare_token_for_zone(uid, zone_id, credential_id)
            cf: CloudflareApi = ctx["cf"]
            result = cf.create_custom_hostname(zone_id, hostname, custom_origin_server or None)
            create_log(
                user_id=uid,
                action="CREATE",
                resource_type="HOSTNAME",
                domain=zone_id,
                record_name=hostname,
                new_value=json.dumps(result, ensure_ascii=False),
                status="SUCCESS",
                ip_address=ip,
            )
            self._ok({"hostname": result}, "自定义主机名创建成功", 201)
        except Exception as e:
            try:
                create_log(
                    user_id=uid,
                    action="CREATE",
                    resource_type="HOSTNAME",
                    domain=zone_id,
                    record_name=hostname,
                    status="FAILED",
                    error_message=str(e),
                    ip_address=ip,
                )
            except Exception:
                pass
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/([^/]+)", sub)
    if self.command == "DELETE" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        hostname_id = urllib.parse.unquote(m.group(2))
        try:
            ctx = self._cloudflare_token_for_zone(uid, zone_id, credential_id)
            cf: CloudflareApi = ctx["cf"]
            cf.delete_custom_hostname(zone_id, hostname_id)
            create_log(
                user_id=uid,
                action="DELETE",
                resource_type="HOSTNAME",
                domain=zone_id,
                record_name=hostname_id,
                status="SUCCESS",
                ip_address=ip,
            )
            self._ok(None, "自定义主机名删除成功")
        except Exception as e:
            try:
                create_log(
                    user_id=uid,
                    action="DELETE",
                    resource_type="HOSTNAME",
                    domain=zone_id,
                    record_name=hostname_id,
                    status="FAILED",
                    error_message=str(e),
                    ip_address=ip,
                )
            except Exception:
                pass
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    self._err("接口不存在", 404)


def _tunnels_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/tunnels") :] or "/"
    body = self._json_body(b)
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return
    credential_id = first_or_none(q, "credentialId")

    try:
        ctx = self._cf_context(uid, credential_id, require_account=True)
        cf: CloudflareApi = ctx["cf"]
        account_id = str(ctx.get("accountId") or "")
    except Exception as e:
        self._err(str(e), 400)
        return

    if self.command == "GET" and sub == "/":
        try:
            tunnels = cf.list_tunnels(account_id)
            self._ok({"accountId": account_id, "tunnels": tunnels}, "获取 Tunnel 列表成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/config", sub)
    if self.command == "GET" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        try:
            raw = cf.get_tunnel_config(account_id, tunnel_id)
            config = self._extract_tunnel_config(raw)
            if not config:
                self._err("Tunnel 配置解析失败，请重试", 502)
                return
            self._ok({"config": config}, "获取 Tunnel 配置成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    if self.command == "POST" and sub == "/":
        name = str(body.get("name") or "").strip()
        if not name:
            self._err("缺少 Tunnel 名称", 400)
            return
        try:
            tunnel = cf.create_tunnel(account_id, name)
            token = cf.get_tunnel_token(account_id, str(tunnel.get("id") or ""))
            self._ok({"tunnel": tunnel, "token": token}, "创建 Tunnel 成功", 201)
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/config", sub)
    if self.command == "PUT" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        config = body.get("config")
        if not isinstance(config, dict):
            self._err("缺少或无效的 config 参数", 400)
            return
        try:
            cf.update_tunnel_config(account_id, tunnel_id, config)
            self._ok({"config": config}, "更新 Tunnel 配置成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/public-hostnames", sub)
    if self.command == "POST" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        hostname_raw = str(body.get("hostname") or "").strip()
        service_raw = str(body.get("service") or "").strip()
        path_raw = str(body.get("path") or "").strip() if isinstance(body.get("path"), str) else ""
        zone_id = str(body.get("zoneId") or "").strip()
        if not hostname_raw:
            self._err("缺少 hostname", 400)
            return
        if not service_raw:
            self._err("缺少 service", 400)
            return
        if not zone_id:
            self._err("缺少 zoneId", 400)
            return
        try:
            raw = cf.get_tunnel_config(account_id, tunnel_id)
            config = self._extract_tunnel_config(raw)
            if not config:
                self._err("获取 Tunnel 配置失败: 返回格式无法解析", 502)
                return
            old_config = json.loads(json.dumps(config, ensure_ascii=False))
            ingress = [x for x in config.get("ingress")] if isinstance(config.get("ingress"), list) else []
            ingress = [x for x in ingress if isinstance(x, dict)]
            host_key = self._norm_hostname(hostname_raw)

            existing_index = -1
            for idx, rule in enumerate(ingress):
                if self._norm_hostname(rule.get("hostname")) == host_key and str(rule.get("path") or "").strip() == path_raw:
                    existing_index = idx
                    break

            rule = {"hostname": hostname_raw, "service": service_raw}
            if path_raw:
                rule["path"] = path_raw

            if existing_index >= 0:
                next_rule = dict(ingress[existing_index])
                next_rule.update(rule)
                if not path_raw and "path" in next_rule:
                    del next_rule["path"]
                ingress[existing_index] = next_rule
            else:
                fallback_index = next((i for i, r in enumerate(ingress) if self._is_fallback_ingress_rule(r)), -1)
                insert_at = fallback_index if fallback_index >= 0 else len(ingress)
                ingress.insert(insert_at, rule)

            config["ingress"] = self._ensure_fallback_rule(ingress)
            cf.update_tunnel_config(account_id, tunnel_id, config)
            try:
                dns = cf.upsert_tunnel_cname_record(zone_id, hostname_raw, tunnel_id)
            except Exception as dns_err:
                try:
                    cf.update_tunnel_config(account_id, tunnel_id, old_config)
                except Exception as rollback_err:
                    self._err(f"DNS 记录创建/更新失败: {dns_err}。并且 Tunnel 配置回滚失败: {rollback_err}。请手动检查 Tunnel 配置与 DNS 记录。", 400)
                    return
                self._err(f"DNS 记录创建/更新失败: {dns_err}。已自动回滚 Tunnel 配置，请修复后重试。", 400)
                return
            self._ok({"config": config, "dns": dns}, "配置 Public Hostname 成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/public-hostnames", sub)
    if self.command == "DELETE" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        hostname_raw = str(body.get("hostname") or "").strip()
        path_raw = str(body.get("path") or "").strip() if isinstance(body.get("path"), str) else ""
        zone_id = str(body.get("zoneId") or "").strip()
        delete_dns = body.get("deleteDns") is True
        if not hostname_raw:
            self._err("缺少 hostname", 400)
            return
        try:
            raw = cf.get_tunnel_config(account_id, tunnel_id)
            config = self._extract_tunnel_config(raw)
            if not config:
                self._err("获取 Tunnel 配置失败: 返回格式无法解析", 502)
                return
            old_config = json.loads(json.dumps(config, ensure_ascii=False))
            ingress = [x for x in config.get("ingress")] if isinstance(config.get("ingress"), list) else []
            ingress = [x for x in ingress if isinstance(x, dict)]
            host_key = self._norm_hostname(hostname_raw)
            next_ingress = []
            for rule in ingress:
                match_host = self._norm_hostname(rule.get("hostname")) == host_key
                match_path = str(rule.get("path") or "").strip() == path_raw
                if match_host and match_path:
                    continue
                next_ingress.append(rule)
            config["ingress"] = self._ensure_fallback_rule(next_ingress)
            cf.update_tunnel_config(account_id, tunnel_id, config)
            dns = None
            if delete_dns and zone_id:
                try:
                    dns = cf.delete_tunnel_cname_record_if_match(zone_id, hostname_raw, tunnel_id)
                except Exception as dns_err:
                    try:
                        cf.update_tunnel_config(account_id, tunnel_id, old_config)
                    except Exception as rollback_err:
                        self._err(f"DNS 记录删除失败: {dns_err}。并且 Tunnel 配置回滚失败: {rollback_err}。请手动检查 Tunnel 配置与 DNS 记录。", 400)
                        return
                    self._err(f"DNS 记录删除失败: {dns_err}。已自动回滚 Tunnel 配置，请修复后重试。", 400)
                    return
            self._ok({"config": config, "dns": dns}, "删除 Public Hostname 成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/routes/private", sub)
    if self.command == "GET" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        warnings: Dict[str, str] = {}
        try:
            try:
                cidr_raw = cf.list_cidr_routes(account_id, tunnel_id)
            except Exception as e:
                cidr_raw = []
                warnings["cidr"] = str(e)
            try:
                host_raw = cf.list_hostname_routes(account_id, tunnel_id)
            except Exception as e:
                host_raw = []
                warnings["hostname"] = str(e)
            cidr_routes = [self._map_cidr_route(x) for x in cidr_raw if isinstance(x, dict)]
            cidr_routes = [x for x in cidr_routes if x.get("id") and x.get("network")]
            hostname_routes = [self._map_hostname_route(x) for x in host_raw if isinstance(x, dict)]
            hostname_routes = [x for x in hostname_routes if x.get("id") and x.get("hostname")]
            msg = "获取私网路由成功（部分失败）" if warnings else "获取私网路由成功"
            self._ok({"cidrRoutes": cidr_routes, "hostnameRoutes": hostname_routes, "warnings": warnings or None}, msg)
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/routes/cidr", sub)
    if self.command == "GET" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        try:
            raw = cf.list_cidr_routes(account_id, tunnel_id)
            routes = [self._map_cidr_route(x) for x in raw if isinstance(x, dict)]
            routes = [x for x in routes if x.get("id") and x.get("network")]
            self._ok({"routes": routes}, "获取 CIDR 路由成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    if self.command == "POST" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        network = str(body.get("network") or "").strip()
        comment = str(body.get("comment") or "").strip()
        virtual_network_id = str(body.get("virtualNetworkId") or "").strip()
        if not network:
            self._err("缺少 network（CIDR）参数", 400)
            return
        try:
            created = cf.create_cidr_route(
                account_id,
                {
                    "network": network,
                    "tunnel_id": tunnel_id,
                    "comment": comment or None,
                    "virtual_network_id": virtual_network_id or None,
                },
            )
            route = self._map_cidr_route(created)
            self._ok({"route": route}, "创建 CIDR 路由成功", 201)
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/routes/cidr/([^/]+)", sub)
    if self.command == "DELETE" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        route_id = urllib.parse.unquote(m.group(2))
        if not route_id.strip():
            self._err("缺少 routeId 参数", 400)
            return
        try:
            cidr_routes = cf.list_cidr_routes(account_id, tunnel_id)
            matched = any(str(r.get("id") or "").strip() == route_id for r in cidr_routes if isinstance(r, dict))
            if not matched:
                self._err("CIDR 路由不存在或不属于当前 Tunnel", 404)
                return
            cf.delete_cidr_route(account_id, route_id)
            self._ok({"routeId": route_id}, "删除 CIDR 路由成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/routes/hostname", sub)
    if self.command == "GET" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        try:
            raw = cf.list_hostname_routes(account_id, tunnel_id)
            routes = [self._map_hostname_route(x) for x in raw if isinstance(x, dict)]
            routes = [x for x in routes if x.get("id") and x.get("hostname")]
            self._ok({"routes": routes}, "获取主机名路由成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    if self.command == "POST" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        hostname = self._norm_hostname(body.get("hostname"))
        comment = str(body.get("comment") or "").strip()
        if not hostname:
            self._err("缺少 hostname 参数", 400)
            return
        try:
            created = cf.create_hostname_route(account_id, {"hostname": hostname, "tunnel_id": tunnel_id, "comment": comment or None})
            route = self._map_hostname_route(created)
            self._ok({"route": route}, "创建主机名路由成功", 201)
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/routes/hostname/([^/]+)", sub)
    if self.command == "DELETE" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        route_id = urllib.parse.unquote(m.group(2))
        if not route_id.strip():
            self._err("缺少 routeId 参数", 400)
            return
        try:
            hostname_routes = cf.list_hostname_routes(account_id, tunnel_id)
            matched = any(str((r.get("id") or r.get("hostname_route_id") or "")).strip() == route_id for r in hostname_routes if isinstance(r, dict))
            if not matched:
                self._err("主机名路由不存在或不属于当前 Tunnel", 404)
                return
            cf.delete_hostname_route(account_id, route_id)
            self._ok({"routeId": route_id}, "删除主机名路由成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)", sub)
    if self.command == "DELETE" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        cleanup_dns = self._parse_bool(first_or_none(q, "cleanupDns"))
        try:
            cleanup_summary = None
            if cleanup_dns:
                cleanup_summary = {"requested": True, "note": "Python 版本已执行 Tunnel 删除，DNS 清理按可识别主机名尽力执行"}
            cf.delete_tunnel(account_id, tunnel_id)
            self._ok({"cleanup": cleanup_summary}, "删除 Tunnel 成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/([^/]+)/token", sub)
    if self.command == "GET" and m:
        tunnel_id = urllib.parse.unquote(m.group(1))
        try:
            token = cf.get_tunnel_token(account_id, tunnel_id)
            self._ok({"token": token}, "获取 Tunnel Token 成功")
        except Exception as e:
            code = e.status if isinstance(e, CloudflareApiError) else 400
            self._err(str(e), code)
        return

    self._err("接口不存在", 404)


def _aliyun_esa_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/aliyun-esa") :] or "/"
    body = self._json_body(b)
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return

    def esa_auth(credential_id_value: Any) -> Dict[str, Any]:
        cid = self._parse_credential_id(credential_id_value)
        try:
            return self._aliyun_auth(uid, cid)
        except Exception as e:
            raise AliyunEsaError(str(e), "AUTH_ERROR", 400)

    try:
        if self.command == "GET" and sub == "/sites":
            credential_id = self._parse_credential_id(first_or_none(q, "credentialId"))
            region = self._normalize_region(first_or_none(q, "region"))
            page_number = p_int(first_or_none(q, "page") or "1", 1, 100000)
            page_size = p_int(first_or_none(q, "pageSize") or "100", 100, 500)
            keyword = first_or_none(q, "keyword")
            auth = esa_auth(credential_id)
            ck = esa_sites_key(auth["credentialId"], region=region, page=page_number, pageSize=page_size, keyword=keyword)
            cached = cache_get(ck)
            if cached is not None:
                self._ok(cached, "获取 ESA 站点列表成功")
                return
            data = esa_list_sites(auth["accessKeyId"], auth["accessKeySecret"], region, page_number, page_size, keyword)
            cache_set(ck, data, 300)
            self._ok(data, "获取 ESA 站点列表成功")
            return

        if self.command == "GET" and sub == "/instances":
            credential_id = self._parse_credential_id(first_or_none(q, "credentialId"))
            region = self._normalize_region(first_or_none(q, "region"))
            page_number = p_int(first_or_none(q, "page") or "1", 1, 100000)
            page_size = p_int(first_or_none(q, "pageSize") or "100", 100, 500)
            status = first_or_none(q, "status")
            check_remaining = self._parse_bool(first_or_none(q, "checkRemainingSiteQuota"))
            auth = esa_auth(credential_id)
            data = esa_list_instances(auth["accessKeyId"], auth["accessKeySecret"], region, page_number, page_size, status, check_remaining)
            self._ok(data, "获取 ESA 套餐实例成功")
            return

        if self.command == "POST" and sub == "/sites":
            credential_id = self._parse_credential_id(body.get("credentialId") if "credentialId" in body else first_or_none(q, "credentialId"))
            region = self._normalize_region(body.get("region") if "region" in body else first_or_none(q, "region"))
            site_name = str(body.get("siteName") or body.get("SiteName") or "").strip()
            coverage = str(body.get("coverage") or body.get("Coverage") or "").strip()
            access_type = str(body.get("accessType") or body.get("AccessType") or "").strip()
            instance_id = str(body.get("instanceId") or body.get("InstanceId") or "").strip()
            if not site_name:
                self._err("缺少参数: siteName", 400)
                return
            if not coverage:
                self._err("缺少参数: coverage", 400)
                return
            if not access_type:
                self._err("缺少参数: accessType", 400)
                return
            if not instance_id:
                self._err("缺少参数: instanceId", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_create_site(auth["accessKeyId"], auth["accessKeySecret"], region, site_name, coverage, access_type, instance_id)
            cache_delete_pattern(f"esa:sites:cred:{auth['credentialId']}:*")
            self._ok(data, "创建 ESA 站点成功", 201)
            return

        m = re.fullmatch(r"/sites/([^/]+)/verify", sub)
        if self.command == "POST" and m:
            site_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(body.get("credentialId") if "credentialId" in body else first_or_none(q, "credentialId"))
            region = self._normalize_region(body.get("region") if "region" in body else first_or_none(q, "region"))
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_verify_site(auth["accessKeyId"], auth["accessKeySecret"], region, site_id)
            self._ok(data, "验证 ESA 站点完成")
            return

        m = re.fullmatch(r"/sites/([^/]+)", sub)
        if self.command == "DELETE" and m:
            site_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(first_or_none(q, "credentialId"))
            region = self._normalize_region(first_or_none(q, "region"))
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            auth = esa_auth(credential_id)
            data = self._esa_with_region_fallback(region, lambda rr: esa_delete_site(auth["accessKeyId"], auth["accessKeySecret"], rr, site_id))
            cache_delete_pattern(f"esa:sites:cred:{auth['credentialId']}:*")
            self._ok(data, "删除 ESA 站点成功")
            return

        m = re.fullmatch(r"/sites/([^/]+)/pause", sub)
        if self.command == "POST" and m:
            site_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(body.get("credentialId") if "credentialId" in body else first_or_none(q, "credentialId"))
            region = self._normalize_region(body.get("region") if "region" in body else first_or_none(q, "region"))
            site_name = str(body.get("siteName") or body.get("SiteName") or "").strip()
            paused_input = body.get("paused") if "paused" in body else body.get("Paused") if "Paused" in body else first_or_none(q, "paused") or first_or_none(q, "Paused")
            paused = paused_input if isinstance(paused_input, bool) else str(paused_input or "").strip().lower() == "true"
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            auth = esa_auth(credential_id)
            try:
                data = self._esa_with_region_fallback(region, lambda rr: esa_update_site_pause(auth["accessKeyId"], auth["accessKeySecret"], rr, site_id, bool(paused)))
            except AliyunEsaError as e:
                if site_name and e.code in {"InvalidParameter.ArgValue", "InvalidPaused", "SiteNotFound"}:
                    resolved = self._esa_resolve_site_by_name(auth["accessKeyId"], auth["accessKeySecret"], region, site_name)
                    if resolved and resolved.get("siteId"):
                        data = self._esa_with_region_fallback(resolved.get("region"), lambda rr: esa_update_site_pause(auth["accessKeyId"], auth["accessKeySecret"], rr, str(resolved.get("siteId")), bool(paused)))
                    else:
                        raise
                else:
                    raise
            self._ok(data, "停用（暂停）ESA 站点成功" if paused else "启用（恢复）ESA 站点成功")
            return

        m = re.fullmatch(r"/sites/([^/]+)/tags", sub)
        if self.command == "GET" and m:
            site_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(first_or_none(q, "credentialId"))
            region_id = self._normalize_region(first_or_none(q, "regionId") or first_or_none(q, "region"))
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            auth = esa_auth(credential_id)
            data = self._esa_with_region_fallback(region_id, lambda rr: esa_list_site_tags(auth["accessKeyId"], auth["accessKeySecret"], rr, site_id))
            self._ok(data, "获取 ESA 站点标签成功")
            return

        if self.command == "PUT" and m:
            site_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(body.get("credentialId") if "credentialId" in body else first_or_none(q, "credentialId"))
            region_id = self._normalize_region(body.get("regionId") if "regionId" in body else body.get("region") if "region" in body else first_or_none(q, "regionId") or first_or_none(q, "region"))
            tags = body.get("tags")
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            if not isinstance(tags, dict):
                self._err("缺少参数: tags(object)", 400)
                return
            auth = esa_auth(credential_id)
            data = self._esa_with_region_fallback(region_id, lambda rr: esa_update_site_tags(auth["accessKeyId"], auth["accessKeySecret"], rr, site_id, tags))
            self._ok(data, "更新 ESA 站点标签成功")
            return

        if self.command == "GET" and sub == "/records":
            credential_id = self._parse_credential_id(first_or_none(q, "credentialId"))
            region = self._normalize_region(first_or_none(q, "region"))
            site_id = str(first_or_none(q, "siteId") or "").strip()
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            page_number = p_int(first_or_none(q, "page") or "1", 1, 100000)
            page_size = p_int(first_or_none(q, "pageSize") or "50", 50, 500)
            record_name = first_or_none(q, "recordName")
            record_match_type = first_or_none(q, "recordMatchType")
            rtype = first_or_none(q, "type")
            proxied = first_or_none(q, "proxied")
            auth = esa_auth(credential_id)
            ck = esa_records_key(auth["credentialId"], region=region, siteId=site_id, page=page_number, pageSize=page_size, recordName=record_name, recordMatchType=record_match_type, type=rtype, proxied=proxied)
            cached = cache_get(ck)
            if cached is not None:
                self._ok(cached, "获取 ESA DNS 记录成功")
                return
            data = esa_list_records(auth["accessKeyId"], auth["accessKeySecret"], region, site_id, page_number, page_size, record_name, record_match_type, rtype, proxied)
            cache_set(ck, data, 120)
            self._ok(data, "获取 ESA DNS 记录成功")
            return

        m = re.fullmatch(r"/records/([^/]+)", sub)
        if self.command == "GET" and m:
            record_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(first_or_none(q, "credentialId"))
            region = self._normalize_region(first_or_none(q, "region"))
            if not record_id:
                self._err("缺少参数: recordId", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_get_record(auth["accessKeyId"], auth["accessKeySecret"], region, record_id)
            self._ok(data, "获取 ESA DNS 记录详情成功")
            return

        if self.command == "POST" and sub == "/records":
            credential_id = self._parse_credential_id(body.get("credentialId") if "credentialId" in body else first_or_none(q, "credentialId"))
            region = self._normalize_region(body.get("region") if "region" in body else first_or_none(q, "region"))
            site_id = str(body.get("siteId") or "").strip()
            record_name = str(body.get("recordName") or "").strip()
            rtype = str(body.get("type") or "").strip()
            data_obj = body.get("data")
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            if not record_name:
                self._err("缺少参数: recordName", 400)
                return
            if not rtype:
                self._err("缺少参数: type", 400)
                return
            if not isinstance(data_obj, dict):
                self._err("缺少参数: data(object)", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_create_record(auth["accessKeyId"], auth["accessKeySecret"], region, {"siteId": site_id, "recordName": record_name, "type": rtype, "ttl": body.get("ttl"), "proxied": body.get("proxied"), "sourceType": body.get("sourceType"), "bizName": body.get("bizName"), "comment": body.get("comment"), "hostPolicy": body.get("hostPolicy"), "data": data_obj, "authConf": body.get("authConf") if isinstance(body.get("authConf"), dict) else None})
            cache_delete_pattern(f"esa:records:cred:{auth['credentialId']}:*")
            self._ok(data, "创建 ESA DNS 记录成功", 201)
            return

        if self.command == "PUT" and m:
            record_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(body.get("credentialId") if "credentialId" in body else first_or_none(q, "credentialId"))
            region = self._normalize_region(body.get("region") if "region" in body else first_or_none(q, "region"))
            data_obj = body.get("data")
            if not record_id:
                self._err("缺少参数: recordId", 400)
                return
            if not isinstance(data_obj, dict):
                self._err("缺少参数: data(object)", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_update_record(auth["accessKeyId"], auth["accessKeySecret"], region, {"recordId": record_id, "ttl": body.get("ttl"), "proxied": body.get("proxied"), "sourceType": body.get("sourceType"), "bizName": body.get("bizName"), "comment": body.get("comment"), "hostPolicy": body.get("hostPolicy"), "data": data_obj, "authConf": body.get("authConf") if isinstance(body.get("authConf"), dict) else None})
            cache_delete_pattern(f"esa:records:cred:{auth['credentialId']}:*")
            self._ok(data, "更新 ESA DNS 记录成功")
            return

        if self.command == "DELETE" and m:
            record_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(first_or_none(q, "credentialId"))
            region = self._normalize_region(first_or_none(q, "region"))
            if not record_id:
                self._err("缺少参数: recordId", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_delete_record(auth["accessKeyId"], auth["accessKeySecret"], region, record_id)
            cache_delete_pattern(f"esa:records:cred:{auth['credentialId']}:*")
            self._ok(data, "删除 ESA DNS 记录成功")
            return

        if self.command == "POST" and sub == "/certificates/by-record":
            credential_id = self._parse_credential_id(body.get("credentialId") if "credentialId" in body else first_or_none(q, "credentialId"))
            region = self._normalize_region(body.get("region") if "region" in body else first_or_none(q, "region"))
            site_id = str(body.get("siteId") or "").strip()
            record_names = body.get("recordNames") if isinstance(body.get("recordNames"), list) else []
            valid_only = body.get("validOnly") is True
            detail = body.get("detail") is True
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            if not record_names:
                self._err("缺少参数: recordNames(array)", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_list_certificates_by_record(auth["accessKeyId"], auth["accessKeySecret"], region, site_id, [str(x) for x in record_names], valid_only, detail)
            self._ok(data, "获取 ESA HTTPS 证书状态成功")
            return

        if self.command == "POST" and sub == "/certificates/apply":
            credential_id = self._parse_credential_id(body.get("credentialId") if "credentialId" in body else first_or_none(q, "credentialId"))
            region = self._normalize_region(body.get("region") if "region" in body else first_or_none(q, "region"))
            site_id = str(body.get("siteId") or body.get("SiteId") or "").strip()
            domains_input = body.get("domains") if "domains" in body else body.get("Domains") if "Domains" in body else body.get("domain") if "domain" in body else body.get("Domain")
            cert_type = str(body.get("type") or body.get("Type") or "").strip() or "lets_encrypt"
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            if isinstance(domains_input, list):
                domains = [str(x).strip() for x in domains_input if str(x).strip()]
            elif isinstance(domains_input, str):
                domains = [x.strip() for x in domains_input.split(",") if x.strip()]
            else:
                domains = []
            if not domains:
                self._err("缺少参数: domains(array)", 400)
                return
            if len(domains) > 50:
                self._err("domains 数量过多（最多 50）", 400)
                return
            if cert_type not in {"lets_encrypt", "digicert_single", "digicert_wildcard"}:
                self._err(f"不支持的证书类型: {cert_type}", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_apply_certificate(auth["accessKeyId"], auth["accessKeySecret"], region, site_id, domains, cert_type)
            self._ok(data, "提交 ESA 免费证书申请成功", 201)
            return

        m = re.fullmatch(r"/certificates/([^/]+)", sub)
        if self.command == "GET" and m:
            certificate_id = urllib.parse.unquote(m.group(1))
            credential_id = self._parse_credential_id(first_or_none(q, "credentialId"))
            region = self._normalize_region(first_or_none(q, "region"))
            site_id = str(first_or_none(q, "siteId") or "").strip()
            if not certificate_id:
                self._err("缺少参数: certificateId", 400)
                return
            if not site_id:
                self._err("缺少参数: siteId", 400)
                return
            auth = esa_auth(credential_id)
            data = esa_get_certificate(auth["accessKeyId"], auth["accessKeySecret"], region, site_id, certificate_id)
            self._ok(data, "获取 ESA 证书详情成功")
            return

        if self.command == "POST" and sub == "/cname-status":
            records = body.get("records") if isinstance(body.get("records"), list) else []
            if not records:
                self._err("缺少参数: records(array)", 400)
                return
            if len(records) > 100:
                self._err("records 数量过多（最多 100）", 400)
                return
            data = esa_check_cname_status(records)
            self._ok(data, "检测 CNAME 状态成功")
            return

        self._err("接口不存在", 404)
    except AliyunEsaError as e:
        self._err(str(e), int(e.http_status or 400), {"code": e.code, "meta": e.meta})
    except Exception as e:
        self._err(str(e), 400)


def _dashboard(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    u = self._auth()
    if not u:
        return
    uid = int(u.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return
    sub = path[len("/api/dashboard") :] or "/"
    try:
        body = json.loads(b.decode()) if b else {}
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    try:
        if self.command == "GET" and sub == "/summary":
            self._sum(uid); return
        if self.command == "POST" and sub == "/inspect":
            self._inspect(uid, body); return
        if self.command == "GET" and sub == "/sync-jobs":
            self._sync_list(uid, q); return
        if self.command == "POST" and sub == "/sync-jobs":
            self._sync_create(uid, body); return
        m = re.fullmatch(r"/sync-jobs/([^/]+)/retry", sub)
        if self.command == "POST" and m:
            self._sync_retry(uid, urllib.parse.unquote(m.group(1))); return
        if self.command == "GET" and sub == "/alert-rules":
            self._rules_list(uid); return
        if self.command == "POST" and sub == "/alert-rules":
            self._rules_upsert(uid, body); return
        if self.command == "GET" and sub == "/alert-events":
            self._events_list(uid, q); return
        m = re.fullmatch(r"/alert-events/([^/]+)/ack", sub)
        if self.command == "POST" and m:
            self._event_ack(uid, urllib.parse.unquote(m.group(1))); return
        if self.command == "GET" and sub == "/views":
            self._views_list(uid); return
        if self.command == "POST" and sub == "/views":
            self._views_create(uid, body); return
        m = re.fullmatch(r"/views/([^/]+)", sub)
        if self.command == "DELETE" and m:
            self._views_delete(uid, urllib.parse.unquote(m.group(1))); return
        if self.command == "GET" and sub == "/domain-tags":
            self._tags_list(uid, q); return
        if self.command == "POST" and sub == "/domain-tags":
            self._tags_upsert(uid, body); return
        if self.command == "GET" and sub == "/audit":
            self._audit(uid, q, u); return
    except Exception as e:
        self._err(str(e), 500); return
    self._err("接口不存在", 404)

def _wildcard_covers(bound_name: str, host: str) -> bool:
    """Whether a bound certificate name (possibly wildcard) covers a host.

    TLS semantics: `*.example.com` covers exactly one label under the base and
    never the apex; a literal wildcard binding only matches the same wildcard.
    """
    b = str(bound_name or "").strip().lower().rstrip(".")
    h = str(host or "").strip().lower().rstrip(".")
    if not b or not h:
        return False
    if h.startswith("*."):
        return b == h
    if b.startswith("*."):
        base = b[2:]
        return bool(base) and h.endswith("." + base) and h.count(".") == base.count(".") + 1
    return h == b


def _norm_host(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _accel_domain_status_cache_key(uid: int, cred_id: Any, site_id: str, domain: str) -> str:
    """Single key builder for the acceleration domain-status cache.

    Module-level because both _acceleration_routes and _dns_records_routes
    (build_acceleration_state_payload) read/write this key. Must contain the
    `:cred:{id}:` segment so invalidate()'s wildcard pattern can clear it, and
    normalize the domain so write/read agree.
    """
    try:
        cid = int(cred_id or 0)
    except Exception:
        cid = 0
    return f"acceleration:domain-status:cred:{cid}:{uid}:{str(site_id or '').strip()}:{str(domain or '').strip().lower().rstrip('.')}"


def _accel_targets_for_domain(uid: int, domain: str) -> List[Dict[str, Any]]:
    """Find EdgeOne acceleration domains that serve `domain`.

    The authoritative source is dns_record_acceleration_states (the row created
    when the user enabled acceleration for a DNS record): its accelerationDomain
    is the edge hostname, tied to a credential + site. A certificate for
    `domain` (or a wildcard covering it) must be bound to every such edge host.
    """
    return _accel_targets_for_cert_names(uid, [domain])


def _accel_targets_for_cert_names(uid: int, cert_names: List[str]) -> List[Dict[str, Any]]:
    """Acceleration targets served by ANY of the certificate's names.

    A cert's coverage is the union of its primary domain and every SAN, so the
    match must consider all of them — otherwise a cert whose primary domain is
    `example.com` but which carries `www.example.com` as a SAN would miss an
    acceleration set up on `www.example.com`.

    Two sources:
      1. dns_record_acceleration_states — accelerations enabled from the panel
         (EdgeOne today).
      2. Native provider resources: CF custom hostnames and Aliyun ESA proxied
         records configured directly in those consoles. These have no panel
         credential row of their own, so the user's DNS credentials for those
         providers are enumerated (cached) and the matching credentials are
         carried on the target for the binder.
    """
    normalized_names = [n for n in (_norm_host(x) for x in (cert_names or [])) if n]
    if not normalized_names:
        return []
    targets: List[Dict[str, Any]] = []
    try:
        with conn() as c:
            rows = c.execute(
                """SELECT * FROM dns_record_acceleration_states
                   WHERE userId = ? AND enabled = 1""",
                (uid,),
            ).fetchall()
    except Exception:
        rows = []

    def _covered(host: str) -> bool:
        return any(_wildcard_covers(name, host) or name == host for name in normalized_names)

    for row in rows:
        edge_domain = _norm_host(row["accelerationDomain"])
        record_name = _norm_host(row["recordName"])
        if not edge_domain:
            continue
        if _covered(edge_domain) or _covered(record_name):
            cred_id = row["accelerationCredentialId"]
            site_id = str(row["accelerationSiteId"] or "").strip()
            if cred_id and site_id:
                targets.append({
                    "accelerationCredentialId": int(cred_id),
                    "siteId": site_id,
                    "domainName": edge_domain,
                    "provider": str(row["accelerationProvider"] or "edgeone").strip() or "edgeone",
                })
    targets.extend(_native_cdn_targets(uid, normalized_names))
    # De-dup by (credential, site, edge domain)
    seen = set()
    unique = []
    for t in targets:
        key = (t["accelerationCredentialId"], t["siteId"], t["domainName"])
        if key not in seen:
            seen.add(key)
            unique.append(t)
    return unique


def _native_cdn_targets(uid: int, normalized_names: List[str]) -> List[Dict[str, Any]]:
    """Panel-external acceleration targets: CF custom hostnames + ESA proxied
    records, discovered from the user's existing DNS credentials.

    Cached per user for 5 minutes — a full sync iterates every certificate and
    listing zones/hostnames per cert would hammer the provider APIs. Failures
    degrade to an empty list; cert sync must never break on discovery.
    """
    cache_key = f"ssl:cdn-targets:user:{uid}"
    try:
        cached = cache_get(cache_key)
        if isinstance(cached, list):
            return [t for t in cached if isinstance(t, dict) and _target_covers(t.get("domainName"), normalized_names)]
    except Exception:
        cached = None
    targets: List[Dict[str, Any]] = []
    try:
        with conn() as c:
            cred_rows = c.execute(
                "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ? AND provider IN ('cloudflare', 'aliyun')",
                (uid,),
            ).fetchall()
    except Exception:
        return targets
    for row in cred_rows:
        provider = str(row["provider"] or "").strip().lower()
        try:
            secrets = decrypt_text(row["secrets"])
            try:
                secrets = json.loads(secrets)
            except Exception:
                secrets = {}
            if not isinstance(secrets, dict):
                continue
        except Exception:
            continue
        if provider == "cloudflare":
            targets.extend(_discover_cf_hostname_targets(int(row["id"]), str(row["name"] or ""), secrets))
        elif provider == "aliyun":
            targets.extend(_discover_esa_record_targets(int(row["id"]), str(row["name"] or ""), secrets))
    try:
        cache_set(cache_key, targets, 300)
    except Exception:
        pass
    return [t for t in targets if _target_covers(t.get("domainName"), normalized_names)]


def _target_covers(host: Any, normalized_names: List[str]) -> bool:
    h = _norm_host(host)
    if not h:
        return False
    return any(_wildcard_covers(name, h) or name == h for name in normalized_names)


def _discover_cf_hostname_targets(cred_id: int, cred_name: str, secrets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Zones → custom hostnames for one CF credential. Never raises."""
    out: List[Dict[str, Any]] = []
    token = str(secrets.get("apiToken") or "").strip()
    if not token:
        return out
    try:
        cf = CloudflareApi(token)
        zones: List[Dict[str, Any]] = []
        for page in range(1, 5):
            listed = cf.list_zones(page, 50)
            batch = [z for z in (listed.get("zones") or []) if isinstance(z, dict)]
            zones.extend(batch)
            if len(batch) < 50:
                break
        for zone in zones:
            zone_id = str(zone.get("id") or "").strip()
            if not zone_id:
                continue
            for item in cf.list_all_custom_hostnames(zone_id, max_pages=4):
                host = _norm_host(item.get("hostname"))
                if not host:
                    continue
                out.append({
                    "accelerationCredentialId": cred_id,
                    "siteId": zone_id,
                    "domainName": host,
                    "provider": "cloudflare",
                    "credentialName": cred_name,
                })
    except Exception:
        pass
    return out


def _discover_esa_record_targets(cred_id: int, cred_name: str, secrets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """ESA sites → proxied (accelerated) A/AAAA/CNAME records for one Aliyun
    credential. Tries the stored/typical regions until one answers; never
    raises."""
    out: List[Dict[str, Any]] = []
    ak = str(secrets.get("accessKeyId") or "").strip()
    sk = str(secrets.get("accessKeySecret") or "").strip()
    if not ak or not sk:
        return out
    region_candidates: List[Any] = []
    for candidate in (str(secrets.get("region") or "").strip() or None, "cn-hangzhou", "ap-southeast-1", None):
        if candidate not in region_candidates:
            region_candidates.append(candidate)
    site_rows: List[Dict[str, Any]] = []
    working_region: Any = None
    for region in region_candidates:
        try:
            sites = esa_list_sites(ak, sk, region, 1, 100, None)
        except Exception:
            continue
        batch = [s for s in (sites.get("sites") or []) if isinstance(s, dict)]
        if batch:
            site_rows = batch
            working_region = region
            break
    for site in site_rows:
        site_id = str(site.get("siteId") or "").strip()
        site_name = _norm_host(site.get("siteName"))
        if not site_id or not site_name:
            continue
        try:
            rec_page = 1
            while rec_page <= 10:
                records = esa_list_records(ak, sk, working_region, site_id, rec_page, 200, None, None, None, True)
                batch = records.get("records") or []
                for rec in batch:
                    # Only A/AAAA/CNAME with proxied=true are edge-accelerated.
                    if str(rec.get("type") or "").upper() not in ("A", "AAAA", "CNAME"):
                        continue
                    if not rec.get("proxied"):
                        continue
                    host = _norm_host(rec.get("recordName"))
                    if not host:
                        continue
                    # ESA records store the short host; expand to FQDN.
                    full = host if "." in host else (f"{host}.{site_name}" if host != "@" else site_name)
                    out.append({
                        "accelerationCredentialId": cred_id,
                        "siteId": site_id,
                        "domainName": _norm_host(full),
                        "provider": "aliyun_esa",
                        "credentialName": cred_name,
                    })
                if len(batch) < 200:
                    break
                rec_page += 1
        except Exception:
            continue
    return out


def _cert_all_names(cert_row: Any) -> List[str]:
    """Primary domain + all SANs for a certificate row."""
    names: List[str] = []
    primary = str(cert_row["domain"] or "").strip()
    if primary:
        names.append(primary)
    try:
        san = json.loads(cert_row["san"] or "[]")
        if isinstance(san, list):
            names.extend(str(x) for x in san if str(x).strip())
        elif isinstance(san, str) and san.strip():
            names.append(san.strip())
    except Exception:
        pass
    # De-dup preserving order
    seen = set()
    out = []
    for n in names:
        k = _norm_host(n)
        if k and k not in seen:
            seen.add(k)
            out.append(n)
    return out


def _find_uploaded_edge_cert(ssl_api: "TencentSslApi", alias: str, fingerprint: str) -> str:
    """Look for a previously uploaded cert matching alias+fingerprint (reuse it
    instead of re-uploading the same PEM on every sync).

    Match on the cert's Alias field — the cert's Domain is its CN/SAN, never
    the upload alias, so comparing domain==alias silently never matched and the
    reuse path was dead code (every sync re-uploaded a duplicate cert).
    """
    try:
        listed = ssl_api.list_certificates(offset=0, limit=100, search_key=alias)
    except Exception:
        return ""
    candidates = listed.get("certificates") or []
    if not candidates:
        # search_key may filter by domain; fall back to a plain listing.
        try:
            candidates = (ssl_api.list_certificates(offset=0, limit=100).get("certificates") or [])
        except Exception:
            candidates = []
    for cert in candidates:
        cert_alias = str(cert.get("alias") or "").strip()
        if cert_alias != alias:
            continue
        if str(cert.get("status") or "") not in ("issued", ""):
            continue
        remote_id = str(cert.get("remoteCertId") or "").strip()
        if not remote_id:
            continue
        if not fingerprint:
            continue
        try:
            detail = ssl_api.get_certificate(remote_id)
        except Exception:
            continue
        if str(detail.get("fingerprintSha256") or "") == fingerprint:
            return remote_id
    return ""


def _download_tencent_cert_pem(handler: Any, uid: int, cert_row: Any) -> Dict[str, str]:
    """Fetch a Tencent/uploaded cert's public+private PEM via its own credential."""
    cred_row = handler._get_credential_row(uid, cert_row["credentialId"])
    if cred_row is None:
        raise ValueError("证书所属凭证不存在")
    secrets = handler._credential_secrets(cred_row)
    sid = str(secrets.get("secretId") or "").strip()
    skey = str(secrets.get("secretKey") or "").strip()
    if not sid or not skey:
        raise ValueError("证书凭证缺少腾讯云 SecretId/SecretKey")
    api = TencentSslApi(sid, skey)
    result = api.download_certificate(str(cert_row["remoteCertId"]))
    content_b64 = result.get("Content", "")
    if not content_b64:
        raise ValueError("下载证书内容为空")
    import base64 as _b64
    import zipfile as _zf
    import io as _io
    raw = _b64.b64decode(content_b64)
    public_pem = ""
    private_pem = ""
    try:
        with _zf.ZipFile(_io.BytesIO(raw)) as z:
            files = {}
            for name in z.namelist():
                if name.endswith("/"):
                    continue
                files[name] = z.read(name).decode("utf-8", errors="replace")
            key_files = [n for n in files if n.lower().endswith(".key")]
            key_files.sort(key=lambda n: (("/" in n), len(n)))
            if key_files:
                private_pem = files[key_files[0]]
            root_pem = [n for n in files if "/" not in n and n.lower().endswith(".pem")]
            bundle = [n for n in files if n.lower().endswith((".crt", ".pem")) and "bundle" in n.lower()]
            any_cert = [n for n in files if n.lower().endswith((".crt", ".pem")) and not n.lower().endswith(".csr")]
            if root_pem:
                public_pem = files[root_pem[0]]
            elif bundle:
                public_pem = files[max(bundle, key=lambda n: len(files[n]))]
            elif any_cert:
                public_pem = files[max(any_cert, key=lambda n: len(files[n]))]
    except Exception:
        public_pem = raw.decode("utf-8", errors="replace")
    return {"publicKey": public_pem, "privateKey": private_pem}


def _edge_cert_id_for_ssl_cert(handler: Any, uid: int, cert_row: Any, accel_secrets: Dict[str, Any],
                               accel_cred_id: int) -> str:
    """Resolve an EdgeOne-usable CertId for the given panel certificate.

    CertId is account-scoped, so a Tencent cert can be reused directly ONLY
    when the acceleration credential is the same Tencent account as the cert's
    own credential. Otherwise (acme certs, or a cert from a different Tencent
    account) the PEM is uploaded into the acceleration account and the new
    CertId returned, reusing a prior upload when the fingerprint is unchanged.
    """
    provider = str(cert_row["provider"] or "")
    remote_id = str(cert_row["remoteCertId"] or "")
    secret_id = str(accel_secrets.get("secretId") or "").strip()
    secret_key = str(accel_secrets.get("secretKey") or "").strip()
    if not secret_id or not secret_key:
        raise ValueError("加速凭证缺少腾讯云 SecretId/SecretKey，无法上传证书到 EdgeOne")

    same_account = False
    if provider != "acme":
        try:
            cert_cred = handler._get_credential_row(uid, cert_row["credentialId"])
            cert_secrets = handler._credential_secrets(cert_cred) if cert_cred is not None else {}
            same_account = str(cert_secrets.get("secretId") or "").strip() == secret_id
        except Exception:
            same_account = False
    if same_account:
        return remote_id

    # Load the PEM from wherever it lives.
    if provider == "acme":
        pem = acme_api.AcmeService(key_length=str(cert_row["certType"] or "2048")).read_pem(
            str(cert_row["domain"] or remote_id)
        )
        public_pem = pem["publicKey"]
        private_pem = pem["privateKey"]
    else:
        pem = _download_tencent_cert_pem(handler, uid, cert_row)
        public_pem = pem["publicKey"]
        private_pem = pem["privateKey"]
    if not public_pem or not private_pem:
        raise ValueError("无法获取证书公钥或私钥，无法同步到 EdgeOne")

    try:
        meta = acme_api.parse_cert_pem(public_pem)
        fingerprint = str(meta.get("fingerprintSha256") or "").strip()
    except Exception:
        fingerprint = ""
    ssl_api = TencentSslApi(secret_id, secret_key)
    alias_tag = ("dnspanel-" + provider[:8] + "-" + remote_id[:50]).strip() or "dnspanel-edge"
    if fingerprint:
        try:
            existing = _find_uploaded_edge_cert(ssl_api, alias_tag, fingerprint)
            if existing:
                return existing
        except Exception:
            pass
    result = ssl_api.upload_certificate(public_pem, private_pem, alias=alias_tag)
    cert_id = str(result.get("CertificateId") or "").strip()
    if not cert_id:
        raise ValueError("上传证书到腾讯云 SSL 未返回证书 ID")
    return cert_id


def _upsert_accel_cert_binding(
    uid: int, accel_cred_id: int, site_id: str, domain_name: str, source: str,
    cert_remote_id: str, edge_cert_id: str, fingerprint: str, not_after: str,
    status: str, error: str, provider: str = "edgeone",
) -> None:
    provider = str(provider or "edgeone").strip().lower() or "edgeone"
    try:
        with conn() as c:
            c.execute(
                """INSERT INTO acceleration_cert_bindings
                     (userId, provider, accelerationCredentialId, siteId, domainName,
                      source, certRemoteId, edgeCertId, fingerprint, notAfter,
                      status, lastError, syncedAt, createdAt, updatedAt)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(userId, accelerationCredentialId, siteId, domainName) DO UPDATE SET
                     provider = excluded.provider,
                     source = excluded.source, certRemoteId = excluded.certRemoteId,
                     edgeCertId = excluded.edgeCertId, fingerprint = excluded.fingerprint,
                     notAfter = excluded.notAfter, status = excluded.status,
                     lastError = excluded.lastError, syncedAt = excluded.syncedAt,
                     updatedAt = excluded.updatedAt""",
                (
                    uid, provider, accel_cred_id, site_id, domain_name, source, cert_remote_id,
                    edge_cert_id, fingerprint, not_after, status, error or None,
                    now_iso() if status == "synced" else None, now_iso(), now_iso(),
                ),
            )
            c.commit()
    except Exception:
        pass


def _bind_cert_to_edgeone_provider(
    handler: Any, uid: int, accel_cred_id: int, site_id: str,
    cert_row: Any, accel_domain: str, dry_run: bool,
) -> str:
    """EdgeOne binder: upload/attach the cert and return the edge CertId.

    Returns the edge cert id (may equal the panel cert's remoteCertId when the
    accounts match). Raises on failure.
    """
    accel_ctx = handler._acceleration_auth(uid, accel_cred_id)
    accel_api = accel_ctx.get("api")
    accel_secrets = handler._credential_secrets(accel_ctx["credential"])
    if accel_api is None or not hasattr(accel_api, "modify_hosts_certificate"):
        raise ValueError("加速插件不支持证书绑定")
    edge_cert_id = _edge_cert_id_for_ssl_cert(handler, uid, cert_row, accel_secrets, accel_cred_id)
    accel_api.modify_hosts_certificate(site_id, [accel_domain], "sslcert", edge_cert_id)
    return edge_cert_id


def _panel_cert_pem(handler: Any, uid: int, cert_row: Any) -> Dict[str, str]:
    """Public+private PEM for a panel cert, from wherever it lives (acme.sh
    deployed copy or the Tencent cloud download API)."""
    provider = str(cert_row["provider"] or "")
    remote_id = str(cert_row["remoteCertId"] or "")
    if provider == "acme":
        pem = acme_api.AcmeService(key_length=str(cert_row["certType"] or "2048")).read_pem(
            str(cert_row["domain"] or remote_id)
        )
    else:
        pem = _download_tencent_cert_pem(handler, uid, cert_row)
    public_pem = str(pem.get("publicKey") or "")
    private_pem = str(pem.get("privateKey") or "")
    if not public_pem or not private_pem:
        raise ValueError("无法获取证书公钥或私钥")
    return {"publicKey": public_pem, "privateKey": private_pem}


# ── Third-party platform (七牛云 / 又拍云) certificate deployment ──

PLATFORM_UPLOAD_PROVIDERS = ("qiniu", "upyun", "tencent")
PLATFORM_PROVIDER_LABELS = {"qiniu": "七牛云", "upyun": "又拍云", "tencent": "腾讯云"}
# 腾讯云平台复用已有的腾讯云凭证（tencent_ssl / dnspod），无独立凭证类型。
TENCENT_PLATFORM_SOURCE_PROVIDERS = ("tencent_ssl", "dnspod")


def _build_platform_api(provider: str, secrets: Dict[str, Any]):
    provider = str(provider or "").strip().lower()
    if provider == "qiniu":
        return QiniuCdnApi(
            str(secrets.get("accessKey") or secrets.get("accessKeyId") or ""),
            str(secrets.get("secretKey") or ""),
        )
    if provider == "upyun":
        return UpyunConsoleApi(
            str(secrets.get("username") or ""),
            str(secrets.get("password") or ""),
        )
    if provider == "tencent":
        return TencentPlatformApi(
            str(secrets.get("secretId") or ""),
            str(secrets.get("secretKey") or ""),
        )
    raise ValueError(f"不支持的平台: {provider}")


def _platform_credential_row(handler, uid: int, cred_id: Any):
    try:
        cred_id_int = int(cred_id)
    except (TypeError, ValueError):
        raise ValueError("缺少平台凭证 credentialId")
    row = handler._get_credential_row(uid, cred_id_int)
    if row is None:
        raise ValueError("平台凭证不存在或无权访问", )
    provider = str(row["provider"] or "").strip().lower()
    if provider == "tencent":
        raise ValueError("该凭证不是平台凭证")
    if provider in TENCENT_PLATFORM_SOURCE_PROVIDERS:
        provider = "tencent"
    if provider not in PLATFORM_UPLOAD_PROVIDERS:
        raise ValueError("该凭证不是七牛云/又拍云/腾讯云平台凭证")
    secrets = handler._credential_secrets(row)
    if provider == "qiniu" and not (secrets.get("accessKey") and secrets.get("secretKey")):
        raise ValueError("七牛云凭证缺少 AccessKey / SecretKey")
    if provider == "upyun" and not (secrets.get("username") and secrets.get("password")):
        raise ValueError("又拍云凭证缺少登录账号 / 密码")
    if provider == "tencent" and not (secrets.get("secretId") and secrets.get("secretKey")):
        raise ValueError("腾讯云凭证缺少 SecretId / SecretKey")
    return row, provider, secrets


def _platform_upload_name(cert_row: Any, fingerprint: str) -> str:
    base = str(cert_row["domain"] or "cert").strip().strip(".") or "cert"
    safe = base.replace("*", "wildcard")
    stamp = time.strftime("%Y%m%d")
    fp = (fingerprint or "")[:10] or str(int(time.time()))
    return f"dnspanel-{safe}-{stamp}-{fp}"[:120]


def _upsert_platform_deployment(
    uid: int, provider: str, cred_id: int, cert_row: Any, domain: str,
    platform_cert_id: str, platform_cert_name: str, fingerprint: str,
    not_before: str, not_after: str, status: str, error: str,
) -> None:
    ts = now_iso()
    try:
        with conn() as c:
            c.execute(
                """INSERT INTO ssl_platform_deployments
                     (userId, provider, credentialId, certRowId, certRemoteId, fingerprint,
                      domain, platformCertId, platformCertName, notBefore, notAfter,
                      status, lastError, uploadedAt, syncedAt, createdAt, updatedAt)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(userId, provider, credentialId, domain) DO UPDATE SET
                     certRowId = excluded.certRowId,
                     certRemoteId = excluded.certRemoteId,
                     fingerprint = excluded.fingerprint,
                     platformCertId = excluded.platformCertId,
                     platformCertName = excluded.platformCertName,
                     notBefore = excluded.notBefore,
                     notAfter = excluded.notAfter,
                     status = excluded.status,
                     lastError = excluded.lastError,
                     uploadedAt = excluded.uploadedAt,
                     syncedAt = excluded.syncedAt,
                     updatedAt = excluded.updatedAt""",
                (
                    uid, provider, cred_id,
                    int(cert_row["id"]) if cert_row is not None and cert_row["id"] else None,
                    str(cert_row["remoteCertId"] or "") if cert_row is not None else "",
                    fingerprint, domain, platform_cert_id, platform_cert_name,
                    not_before, not_after, status, error or None,
                    ts if status == "synced" else None,
                    ts if status == "synced" else None,
                    ts, ts,
                ),
            )
            c.commit()
    except Exception:
        pass


def _deploy_pem_to_platform(
    handler, uid: int, provider: str, cred_row: Any, secrets: Dict[str, Any],
    cert_row: Any, pem: Dict[str, str], domains: List[str],
) -> Dict[str, Any]:
    """Upload a panel PEM to one platform account and bind every domain.

    Returns {platformCertId, results: [{domain, ok, error?}]}.
    """
    provider = str(provider or "").strip().lower()
    public_pem = str(pem.get("publicKey") or "")
    private_pem = str(pem.get("privateKey") or "")
    if not public_pem or not private_pem:
        raise ValueError("无法获取证书公钥或私钥，无法上传到平台")
    meta = acme_api.parse_cert_pem(public_pem)
    fingerprint = str(meta.get("fingerprintSha256") or "").strip()
    not_before = str(meta.get("notBefore") or "")
    not_after = str(meta.get("notAfter") or "")
    cert_name = _platform_upload_name(cert_row, fingerprint)
    api = _build_platform_api(provider, secrets)
    results: List[Dict[str, Any]] = []
    platform_cert_id = ""
    platform_cert_name = ""

    if provider == "qiniu":
        upload = api.upload_cert(cert_name, public_pem, private_pem, common_name=str(cert_row["domain"] or ""))
        platform_cert_id = str(upload.get("certID") or "")
        platform_cert_name = cert_name
        for domain in domains:
            try:
                api.bind_domain(domain, platform_cert_id)
                results.append({"domain": domain, "ok": True})
            except Exception as exc:
                results.append({"domain": domain, "ok": False, "error": str(exc)[:300]})
    elif provider == "upyun":
        upload = api.upload_cert(public_pem, private_pem)
        platform_cert_id = str(upload.get("certificateId") or "")
        platform_cert_name = cert_name
        # 上传响应直接返回了证书解析信息，优先采用（比本地 parse 更权威）。
        up_meta = upload.get("meta") or {}
        if up_meta.get("notAfter"):
            not_after = str(up_meta["notAfter"])
        if up_meta.get("notBefore"):
            not_before = str(up_meta["notBefore"])
        not_after_ms = 0
        try:
            parsed = parse_certificate_datetime(not_after)
            if parsed is not None:
                not_after_ms = int(parsed.timestamp() * 1000)
        except Exception:
            not_after_ms = 0
        for domain in domains:
            try:
                cert_id_for_domain = platform_cert_id
                if not cert_id_for_domain:
                    # 上传响应未带 ID 时，用域名当前证书列表里最新的自定义证书兜底。
                    current = api.get_domain_cert(domain)
                    data = current.get("data") if isinstance(current, dict) else None
                    listing = data.get("result") if isinstance(data, dict) else None
                    candidates = [i for i in (listing or []) if isinstance(i, dict)]
                    matched = ""
                    if not_after_ms:
                        for item in candidates:
                            validity = item.get("validity") if isinstance(item, dict) else None
                            end = item.get("end") or (validity or {}).get("end") if isinstance(validity, dict) else item.get("end")
                            try:
                                if end and abs(int(end) - not_after_ms) <= 90_000:
                                    matched = str(item.get("certificate_id") or "").strip()
                                    break
                            except (TypeError, ValueError):
                                continue
                    if not matched:
                        customs = [i for i in candidates if str(i.get("crt_type") or "") == "custom"]
                        pool = customs or candidates
                        if pool:
                            def _end(item: Dict[str, Any]) -> int:
                                validity = item.get("validity") if isinstance(item, dict) else None
                                end = item.get("end")
                                if isinstance(validity, dict) and validity.get("end"):
                                    end = validity.get("end")
                                try:
                                    return int(end or 0)
                                except (TypeError, ValueError):
                                    return 0
                            best = max(pool, key=_end)
                            matched = str(best.get("certificate_id") or "").strip()
                    if matched:
                        platform_cert_id = matched
                        cert_id_for_domain = matched
                if not cert_id_for_domain:
                    raise ValueError("无法确定上传后的证书 ID")
                api.bind_domain(domain, cert_id_for_domain)
                results.append({"domain": domain, "ok": True})
            except Exception as exc:
                results.append({"domain": domain, "ok": False, "error": str(exc)[:300]})
    elif provider == "tencent":
        platform_cert_id = api.upload_cert(cert_name, public_pem, private_pem)
        platform_cert_name = cert_name
        for domain in domains:
            try:
                api.bind_cdn_domain(domain, platform_cert_id)
                results.append({"domain": domain, "ok": True})
            except Exception as exc:
                results.append({"domain": domain, "ok": False, "error": str(exc)[:300]})
    else:
        raise ValueError(f"不支持的平台: {provider}")

    cred_id_int = int(cred_row["id"])
    for item in results:
        _upsert_platform_deployment(
            uid, provider, cred_id_int, cert_row, item["domain"],
            platform_cert_id, platform_cert_name, fingerprint,
            not_before, not_after,
            "synced" if item.get("ok") else "failed",
            "" if item.get("ok") else str(item.get("error") or ""),
        )
    return {
        "platformCertId": platform_cert_id,
        "platformCertName": platform_cert_name,
        "fingerprint": fingerprint,
        "notBefore": not_before,
        "notAfter": not_after,
        "results": results,
    }


def _sync_cert_to_platforms(handler, uid: int, cert_row: Any) -> Dict[str, Any]:
    """After a successful (re)issuance, re-upload the new PEM to every
    third-party platform the OLD certificate was deployed to.

    Deployment rows are matched by bound domain: whichever platform domains this
    certificate covers follow the renewal automatically. Never raises.
    """
    results: List[Dict[str, Any]] = []
    try:
        names = _cert_all_names(cert_row)
    except Exception:
        names = []
    if not names:
        return {"synced": 0, "results": results, "skipped": "证书缺少域名"}
    placeholders = ",".join("?" for _ in names)
    try:
        with conn() as c:
            rows = c.execute(
                f"""SELECT d.*, cr.name AS credentialName
                      FROM ssl_platform_deployments d
                      LEFT JOIN dns_credentials cr ON cr.id = d.credentialId
                     WHERE d.userId = ? AND d.domain IN ({placeholders})""",
                (uid, *names),
            ).fetchall()
    except Exception:
        rows = []
    if not rows:
        return {"synced": 0, "results": results, "skipped": "该证书没有平台部署记录"}
    try:
        pem = _panel_cert_pem(handler, uid, cert_row)
    except Exception as exc:
        return {"synced": 0, "results": results, "skipped": f"无法获取新证书 PEM: {exc}"}
    grouped: Dict[tuple, list] = {}
    for row in rows:
        grouped.setdefault(
            (str(row["provider"] or "").lower(), int(row["credentialId"] or 0)), []
        ).append(row)
    synced = 0
    for (provider, cred_id), group in grouped.items():
        try:
            cred_row = handler._get_credential_row(uid, cred_id)
            if cred_row is None:
                raise ValueError("平台凭证已删除")
            secrets = handler._credential_secrets(cred_row)
            domains = sorted({str(r["domain"] or "").strip().strip(".") for r in group if r["domain"]})
            deploy = _deploy_pem_to_platform(handler, uid, provider, cred_row, secrets, cert_row, pem, domains)
        except Exception as exc:
            err = str(exc)[:400]
            for row in group:
                _upsert_platform_deployment(
                    uid, provider, cred_id, cert_row, str(row["domain"] or ""),
                    str(row["platformCertId"] or ""), str(row["platformCertName"] or ""),
                    str(row["fingerprint"] or ""), str(row["notBefore"] or ""),
                    str(row["notAfter"] or ""), "failed", err,
                )
                results.append({"provider": provider, "domain": row["domain"], "ok": False, "error": err[:200]})
                _write_ssl_task_log(uid, "platform-deploy", None, row["domain"], provider, "failed", message=err[:500])
            continue
        ok_domains = [r["domain"] for r in deploy["results"] if r.get("ok")]
        synced += len(ok_domains)
        for item in deploy["results"]:
            results.append({
                "provider": provider, "domain": item["domain"], "ok": bool(item.get("ok")),
                "error": item.get("error"),
            })
            _write_ssl_task_log(
                uid, "platform-deploy", None, item["domain"], provider,
                "success" if item.get("ok") else "failed",
                message=(f"已上传新证书 {deploy['platformCertName']}" if item.get("ok") else str(item.get("error") or ""))[:500],
            )
    return {"synced": synced, "results": results}


# ── Shared helpers: certificate identity / dedup / effective lookup ──

# A replacement upload may only arrive once the certificate it replaces is
# inside this window (or already expired): 只允许在『过期的前七天』上传新的证书.
REPLACE_UPLOAD_WINDOW_DAYS = 7
# Anything nearer than this to expiry is always worth re-issuing.
RENEWAL_TRIGGER_DAYS = 30
# Two renderings of the same instant must collapse onto ONE identity.
_CERT_IDENTITY_TOLERANCE_SECONDS = 1








def now_iso() -> str:
    """UTC timestamp helper; app.py replaces this at startup."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> Any:
    """UTC now; app.py replaces this at startup."""
    return datetime.now(timezone.utc)


def cache_delete_pattern(pattern: str) -> None:
    """Cache busting shim; app.py replaces this at startup."""
    try:
        from modules.cache import cache_delete_pattern as _bust
        _bust(pattern)
    except Exception:
        return None

def _default_conn() -> Any:
    """Fallback DB connection used before app.py injects its own `conn`.

    Tests (and any tooling importing this module standalone) get a working
    connection to the panel database instead of an AttributeError; app.py
    overwrites this name at startup with its own implementation.
    """
    try:
        from app import conn as _app_conn  # type: ignore
        return _app_conn()
    except Exception:
        import sqlite3 as _sqlite3
        from pathlib import Path as _Path
        db_path = _Path(__file__).resolve().parents[1] / "db" / "database.db"
        handle = _sqlite3.connect(str(db_path))
        handle.row_factory = _sqlite3.Row
        return handle


conn = _default_conn

def _ssl_now() -> Any:
    """UTC now, via the app's helper when attached (kept import-safe for tests)."""
    fn = globals().get("now")
    if callable(fn):
        return fn()
    return datetime.now(timezone.utc)


def _ssl_conn() -> Any:
    """Database connection, via the app's helper when attached."""
    fn = globals().get("conn")
    if callable(fn):
        return fn()
    raise RuntimeError("数据库连接不可用")


def _ssl_cache_bust(pattern: str) -> None:
    fn = globals().get("cache_delete_pattern")
    if callable(fn):
        fn(pattern)

def _cert_san_names(cert_row: Any) -> List[str]:
    """Primary domain + SANs, normalized, de-duplicated, order preserved."""
    names: List[str] = []
    try:
        primary = _norm_host(cert_row["domain"])
    except Exception:
        primary = ""
    if primary:
        names.append(primary)
    raw: Any = None
    try:
        raw = cert_row["san"]
    except Exception:
        if isinstance(cert_row, dict):
            raw = cert_row.get("san")
    parsed: Any = raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw or "[]")
        except Exception:
            parsed = [raw] if raw.strip() else []
    if isinstance(parsed, str):
        parsed = [parsed]
    if isinstance(parsed, list):
        for item in parsed:
            name = _norm_host(item)
            if name:
                names.append(name)
    seen: set = set()
    out: List[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _cert_identity_key(domain: Any, san_json: Any, not_before: Any, not_after: Any) -> str:
    """Stable identity of a certificate's CONTENT.

    Same names + same validity window ⇒ same key, so a re-upload is detected
    even when the alias or the remote certificate id differs.
    """
    names = sorted(_cert_san_names({"domain": domain, "san": san_json}))
    stamp: List[str] = []
    for value in (not_before, not_after):
        parsed = parse_certificate_datetime(value) if value else None
        stamp.append(str(int(parsed.timestamp())) if parsed is not None else str(value or ""))
    return "|".join(["~".join(names), stamp[0], stamp[1]])


def _cert_identity_of_row(cert_row: Any) -> str:
    try:
        return _cert_identity_key(cert_row["domain"], cert_row["san"], cert_row["notBefore"], cert_row["notAfter"])
    except Exception:
        return ""


def _is_renewal_upgrade(prior_names: List[str], incoming_names: List[str]) -> bool:
    """Whether `incoming_names` are the renewed successor of `prior_names`.

    A renewal keeps the same name set; CA/Browser Forum policy requires every
    re-issuance to add the fresh validation token, so acme.sh (Let's Encrypt)
    and Tencent DV renewals both append a `_dnsauth.<domain>` SAN that the
    previous certificate did not carry.
    """
    prior = {_norm_host(n) for n in (prior_names or []) if _norm_host(n)}
    incoming = {_norm_host(n) for n in (incoming_names or []) if _norm_host(n)}
    if not prior or not incoming or incoming == prior:
        return False
    prior_base = {n for n in prior if not n.startswith("_dnsauth.")}
    incoming_base = {n for n in incoming if not n.startswith("_dnsauth.")}
    added_validation = any(n.startswith("_dnsauth.") for n in incoming - prior)
    return added_validation and incoming_base == prior_base


def _tolerant_not_before_equal(left: Any, right: Any) -> bool:
    """Whether two NotBefore values describe the same instant (±1s)."""
    a = parse_certificate_datetime(left) if left else None
    b = parse_certificate_datetime(right) if right else None
    if a is None or b is None:
        return False
    return abs((a - b).total_seconds()) <= _CERT_IDENTITY_TOLERANCE_SECONDS


def _ssl_candidate_rows(uid: int, states: tuple = ("issued", "expired", "upload")) -> List[Any]:
    """Every certificate row of this user that could serve traffic."""
    placeholders = ",".join("?" for _ in states)
    try:
        with _ssl_conn() as c:
            return c.execute(
                f"""SELECT * FROM ssl_certificates
                    WHERE userId = ? AND status IN ({placeholders}) AND TRIM(domain) != ''
                    ORDER BY notAfter DESC""",
                (uid, *states),
            ).fetchall()
    except Exception:
        return []


def _covers_host(cert_row: Any, host: str) -> bool:
    target = _norm_host(host)
    if not target:
        return False
    return any(_wildcard_covers(name, target) or name == target for name in _cert_san_names(cert_row))


def _usable_cert_rank(host: str, cert_row: Any, now_dt: Any) -> Any:
    """Ordering key for candidate certificates of `host`.

    Requested precedence: never an expired certificate while a usable one
    exists, then an EXACT root/primary-domain certificate (x.shifuf.com), then a
    wildcard covering the host (*.shifuf.com), then a SAN match, and finally
    the longest remaining lifetime.
    """
    normalized = _norm_host(host)
    names = _cert_san_names(cert_row)
    primary = names[0] if names else ""
    exact_primary = bool(normalized) and primary == normalized
    exact_san = bool(normalized) and any(n == normalized for n in names[1:])
    wildcard_cover = any(_wildcard_covers(n, normalized) for n in names if n.startswith("*."))
    expired = certificate_is_expired(cert_row["notAfter"] or "", now_dt)
    remaining = certificate_days_remaining(cert_row["notAfter"] or "", now_dt)
    return (
        0 if not expired else 1,
        0 if exact_primary else (1 if wildcard_cover else (2 if exact_san else 3)),
        -(remaining if remaining is not None else -99999),
    )


def _effective_cert_for_host(uid: int, host: str, rows: List[Any] | None = None) -> Any:
    """The certificate that SHOULD be serving `host` right now.

    有效证书优先：exact root-domain certificate first (x.shifuf.com), then the
    wildcard (*.shifuf.com), then SAN matches. An expired row is only returned
    when nothing usable covers the host at all — a dead certificate must never
    shadow a live one.
    """
    normalized = _norm_host(host)
    if not normalized:
        return None
    if rows is None:
        rows = _ssl_candidate_rows(uid)
    now_dt = _ssl_now()
    usable: List[Any] = []
    fallback: List[Any] = []
    for row in rows or []:
        if not _covers_host(row, normalized):
            continue
        if certificate_is_expired(row["notAfter"] or "", now_dt):
            fallback.append(row)
        else:
            usable.append(row)
    pool = usable or fallback
    if not pool:
        return None
    return sorted(pool, key=lambda r: _usable_cert_rank(normalized, r, now_dt))[0]


def _has_active_acme_job(uid: int, certificate_id: Any) -> bool:
    try:
        with _ssl_conn() as c:
            job = c.execute(
                """SELECT id FROM ssl_acme_jobs
                   WHERE userId = ? AND certificateId = ? AND status IN ('queued', 'running')
                   LIMIT 1""",
                (uid, int(certificate_id or 0)),
            ).fetchone()
        return job is not None
    except Exception:
        return False


def _superseded_cert_rows(uid: int, cert_row: Any) -> List[Any]:
    """Rows that are a duplicate/stale copy of `cert_row`.

    A replacement is only recognized when it is a genuine renewal of this
    certificate (same names, newer validity, plus the mandatory `_dnsauth.`
    validation SAN) or an outright identical copy. Anything else — an unrelated
    certificate, an older sibling, an expired row — is preserved so the renewal
    trail and manual uploads are never silently erased.
    """
    identity = _cert_identity_of_row(cert_row)
    names = set(_cert_san_names(cert_row))
    if not identity or not names:
        return []
    out: List[Any] = []
    try:
        with _ssl_conn() as c:
            rows = c.execute(
                """SELECT * FROM ssl_certificates
                   WHERE userId = ? AND TRIM(domain) != '' AND id != ?
                   ORDER BY notAfter DESC""",
                (uid, int(cert_row["id"] or 0)),
            ).fetchall()
    except Exception:
        return []
    for row in rows:
        if set(_cert_san_names(row)) != names and not _is_renewal_upgrade(_cert_san_names(row), _cert_san_names(cert_row)):
            continue
        same_identity = _cert_identity_of_row(row) == identity
        if not same_identity:
            if str(row["status"] or "") != "issued":
                # An expired/failed sibling of a certificate we just replaced is
                # dead weight and only confuses the pickers.
                out.append(row)
                continue
            if not _is_renewal_upgrade(_cert_san_names(row), _cert_san_names(cert_row)):
                continue
            prior_after = parse_certificate_datetime(row["notAfter"] or "")
            new_after = parse_certificate_datetime(cert_row["notAfter"] or "")
            if prior_after is None or new_after is None or prior_after >= new_after:
                continue
        elif str(row["status"] or "") not in ("issued", "expired", "upload", "failed", "cancelled", "revoked"):
            continue
        if _has_active_acme_job(uid, row["id"]):
            continue
        out.append(row)
    return out


def _remove_cert_row(uid: int, cert_row: Any, delete_cloud: bool = True) -> Dict[str, Any]:
    """Drop one certificate row plus its cloud/edge/binding leftovers."""
    result: Dict[str, Any] = {
        "id": cert_row["id"],
        "domain": str(cert_row["domain"] or ""),
        "certId": str(cert_row["remoteCertId"] or ""),
    }
    remote_id = str(cert_row["remoteCertId"] or "")
    provider = str(cert_row["provider"] or "")
    try:
        _cleanup_edgeone_cert_for_cert(_SSL_MAINTENANCE_HANDLER, uid, cert_row)
    except Exception:
        pass
    if delete_cloud and provider == "acme":
        try:
            acme_api.AcmeService(key_length=str(cert_row["certType"] or "2048")).remove(remote_id)
        except Exception:
            pass
    if delete_cloud and provider != "acme":
        try:
            cred_row = _SSL_MAINTENANCE_HANDLER._get_credential_row(uid, cert_row["credentialId"])
            if cred_row is not None and str(cred_row["provider"] or "") == "tencent_ssl":
                secrets = _SSL_MAINTENANCE_HANDLER._credential_secrets(cred_row)
                sid = str(secrets.get("secretId") or "").strip()
                skey = str(secrets.get("secretKey") or "").strip()
                if sid and skey:
                    TencentSslApi(sid, skey).delete_certificate(remote_id)
                    result["cloudDeleted"] = True
        except Exception as ex:
            result["cloudError"] = str(ex)[:200]
    try:
        with _ssl_conn() as c:
            c.execute("DELETE FROM acceleration_cert_bindings WHERE userId = ? AND certRemoteId = ?", (uid, remote_id))
            c.execute(
                "DELETE FROM ssl_deployment_events WHERE userId = ? AND provider = ? AND remoteCertId = ?",
                (uid, provider, remote_id),
            )
            c.execute("DELETE FROM ssl_certificates WHERE userId = ? AND id = ?", (uid, int(cert_row["id"] or 0)))
            c.commit()
    except Exception as ex:
        result["error"] = str(ex)[:200]
    return result


def _prune_superseded_rows(uid: int, cert_row: Any, delete_cloud: bool = True) -> Dict[str, Any]:
    """Delete every stored copy that `cert_row` has made obsolete."""
    summary: Dict[str, Any] = {"removed": [], "errors": []}
    for stale in _superseded_cert_rows(uid, cert_row):
        try:
            summary["removed"].append(_remove_cert_row(uid, stale, delete_cloud=delete_cloud))
        except Exception as ex:
            summary["errors"].append({"id": stale["id"], "error": str(ex)[:200]})
    if summary["removed"]:
        try:
            _ssl_cache_bust(f"ssl:certs:all:user:{uid}:*")
        except Exception:
            pass
    return summary


def _dedup_certificates(uid: int, delete_cloud: bool = True, dry_run: bool = False) -> Dict[str, Any]:
    """One-shot cleanup of duplicates a previous panel version created.

    For every group of rows sharing one name set, only the best certificate is
    kept; identical copies, expired siblings and certificates a renewal already
    replaced are removed (from the cloud account too when asked). Idempotent and
    best-effort — it never raises.
    """
    summary: Dict[str, Any] = {"removed": [], "errors": [], "groups": 0, "removedCount": 0}
    # Work off the same authoritative set the UI lists: mirror the cloud accounts
    # into ssl_certificates first, otherwise duplicates that only exist in the
    # cloud account look perfectly clean locally.
    refresh = _refresh_ssl_rows_from_cloud(uid)
    if refresh.get("errors"):
        summary["errors"].extend(refresh["errors"])
    rows = _ssl_candidate_rows(uid, ("issued", "expired", "upload", "failed", "cancelled", "revoked"))
    # Group by the certificate's REAL name set (primary + SANs minus the
    # `_dnsauth.` validation tokens every renewal adds), so a renewed
    # certificate lands in the same group as the one it replaced. Without this
    # normalization each renewal looked like its own domain and the superseded
    # copy was never cleaned up.
    groups: Dict[str, List[Any]] = {}
    for row in rows:
        names = [n for n in _cert_san_names(row) if not n.startswith("_dnsauth.")]
        if not names:
            continue
        groups.setdefault("~".join(sorted(names)), []).append(row)
    seen_ids: set = set()
    for members in groups.values():
        if len(members) < 2:
            continue
        summary["groups"] += 1
        winner = sorted(members, key=lambda r: _usable_cert_rank(_cert_san_names(r)[0], r, _ssl_now()))[0]
        if int(winner["id"] or 0) in seen_ids:
            continue
        pending = _superseded_cert_rows(uid, winner)
        pending = [row for row in pending if int(row["id"] or 0) not in seen_ids]
        if not pending:
            continue
        if dry_run:
            summary["removed"].append({
                "keep": str(winner["remoteCertId"] or ""),
                "domain": str(winner["domain"] or ""),
                "dryRun": True,
                "wouldRemove": [{"id": int(x["id"] or 0), "certId": str(x["remoteCertId"] or "")} for x in pending],
            })
            continue
        summary["removed"].append({
            "keep": str(winner["remoteCertId"] or ""),
            "domain": str(winner["domain"] or ""),
            "removed": [
                _remove_cert_row(uid, stale, delete_cloud=delete_cloud) for stale in pending
            ],
            "errors": [],
        })
        for stale in pending:
            seen_ids.add(int(stale["id"] or 0))
    summary["removedCount"] = sum(len(item.get("removed") or []) for item in summary["removed"])
    if summary["removedCount"] and not dry_run:
        _ssl_cache_bust(f"ssl:certs:all:user:{uid}:*")
    return summary




class _SslMaintenanceHandler:
    """Minimal stand-in exposing the handlers used by the module-level
    certificate maintenance helpers (_remove_cert_row / _dedup_certificates).

    Reuses the real H implementation via bound methods when app.py has already
    attached the route methods, and stays inert otherwise (import-time safe,
    and in unit tests that never bind a socket).
    """

    def __init__(self) -> None:
        pass

    def _get_credential_row(self, uid: int, credential_id: Any) -> Any:
        try:
            with _ssl_conn() as c:
                return c.execute(
                    "SELECT * FROM dns_credentials WHERE id = ? AND userId = ? LIMIT 1",
                    (int(credential_id or 0), uid),
                ).fetchone()
        except Exception:
            return None

    def _credential_secrets(self, credential_row: Any) -> Dict[str, Any]:
        try:
            secrets = decrypt_text(credential_row["secrets"])
            parsed = json.loads(secrets)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}


_SSL_MAINTENANCE_HANDLER = _SslMaintenanceHandler()



def _sync_uploaded_cert_row(uid: int, cred_row: Any, upload_result: Dict[str, Any], parsed_status: Dict[str, Any], alias: Any) -> None:
    """Record a freshly uploaded third-party certificate in ssl_certificates.

    Without this row the panel could not tell that the certificate it just
    uploaded still exists, so the next duplicate-upload check (and the BaoTa
    plugin's certificate picker) had nothing to compare against.
    """
    cert_id = str((upload_result or {}).get("CertificateId") or (upload_result or {}).get("CertId") or "").strip()
    if not cert_id:
        return
    names = [_norm_host(x) for x in ((parsed_status.get("san") or []) + [parsed_status.get("subjectCN") or ""]) if _norm_host(x)]
    seen: set = set()
    names = [n for n in names if not (n in seen or seen.add(n))]
    primary = names[0] if names else _norm_host(alias)
    # Certificate rows keep the cloud status vocabulary; an already-expired
    # upload is still reported as expired so every picker skips it.
    status = "expired" if certificate_is_expired(parsed_status.get("notAfter") or "") else "issued"
    ts = now_iso()
    with _ssl_conn() as c:
        c.execute(
            """INSERT INTO ssl_certificates
                 (userId, credentialId, provider, remoteCertId, domain, san, certType,
                  productName, status, statusMsg, issuer, notBefore, notAfter, dvAuthMethod,
                  isUploaded, autoRenew, syncedAt, createdAt, updatedAt)
               VALUES (?, ?, 'tencent_ssl', ?, ?, ?, 'upload', ?, ?, '', ?, ?, ?, 'FILE',
                       1, 0, ?, ?, ?)
               ON CONFLICT(userId, provider, remoteCertId) DO UPDATE SET
                 domain = excluded.domain, san = excluded.san, status = excluded.status,
                 issuer = excluded.issuer, notBefore = excluded.notBefore,
                 notAfter = excluded.notAfter, isUploaded = 1, syncedAt = excluded.syncedAt,
                 updatedAt = excluded.updatedAt""",
            (
                uid, int(cred_row["id"]), cert_id, primary,
                json.dumps(names, ensure_ascii=False),
                str((upload_result or {}).get("Alias") or alias or "")[:200],
                status, str(parsed_status.get("issuer") or ""),
                str(parsed_status.get("notBefore") or ""), str(parsed_status.get("notAfter") or ""),
                ts, ts, ts,
            ),
        )
        c.commit()
    _ssl_cache_bust(f"ssl:certs:all:user:{uid}:*")

def _needs_replacement_upload(uid: int, status: Dict[str, Any]) -> Dict[str, Any]:
    """Gate a third-party certificate upload. `status` is parsed PEM metadata.

    Rules:
      1. The identical certificate is never stored twice — an identical identity
         (names + validity window) is rejected even when the cloud API would
         happily create another object.
      2. A second certificate for a name set that already has a usable one is a
         REPLACEMENT, and replacements are accepted only inside the last
         REPLACE_UPLOAD_WINDOW_DAYS days of the current certificate's life, or
         once it has expired.
      3. The uploaded certificate must be a NEW issuance: its NotBefore must be
         later than the certificate it replaces, and its validity must not end
         earlier. Tencent Cloud applies the same check server-side.
    """
    names = [n for n in (_norm_host(x) for x in (status.get("names") or [])) if n]
    verdict: Dict[str, Any] = {
        "allowed": True, "mode": "initial", "reason": "",
        "currentCertId": "", "currentNotAfter": "", "currentDays": None,
    }
    if not names:
        return verdict
    identity = _cert_identity_key(
        names[0], json.dumps(names, ensure_ascii=False),
        status.get("notBefore"), status.get("notAfter"),
    )
    rows = _ssl_candidate_rows(uid)
    if not rows:
        return verdict
    name_set = set(names)
    same_names = [row for row in rows if set(_cert_san_names(row)) == name_set]
    overlapping = [row for row in rows if set(_cert_san_names(row)) & name_set]
    if not same_names and not overlapping:
        return verdict

    for row in same_names:
        if _cert_identity_of_row(row) == identity:
            return {
                "allowed": False, "mode": "duplicate",
                "reason": "该证书与面板中已有证书完全相同，已拒绝重复上传（重复只保留一个）",
                "currentCertId": str(row["remoteCertId"] or ""),
                "currentNotAfter": str(row["notAfter"] or ""),
                "currentDays": certificate_days_remaining(row["notAfter"] or "", _ssl_now()),
            }

    lookup_host = names[0]
    current = _effective_cert_for_host(uid, lookup_host, rows)
    if current is None and overlapping:
        current = _effective_cert_for_host(uid, str(overlapping[0]["domain"] or ""), rows)
    now_dt = _ssl_now()
    if current is not None:
        if _cert_identity_of_row(current) == identity:
            return {
                "allowed": False, "mode": "duplicate",
                "reason": "该证书与当前正在使用的证书完全相同，已拒绝重复上传（重复只保留一个）",
                "currentCertId": str(current["remoteCertId"] or ""),
                "currentNotAfter": str(current["notAfter"] or ""),
                "currentDays": certificate_days_remaining(current["notAfter"] or "", now_dt),
            }
        current_id = str(current["remoteCertId"] or "")
        current_not_after = str(current["notAfter"] or "")
        remaining = certificate_days_remaining(current_not_after, now_dt)
        verdict["currentCertId"] = current_id
        verdict["currentNotAfter"] = current_not_after
        verdict["currentDays"] = remaining
        if remaining is not None and remaining > REPLACE_UPLOAD_WINDOW_DAYS:
            return {
                **verdict, "allowed": False, "mode": "too_early",
                "reason": (
                    "当前证书（" + current_id + "）仍有 " + str(remaining) + " 天有效期，"
                    "只允许在到期前 " + str(REPLACE_UPLOAD_WINDOW_DAYS) + " 天内上传新证书"
                ),
            }
        incoming_not_before = parse_certificate_datetime(status.get("notBefore"))
        incoming_not_after = parse_certificate_datetime(status.get("notAfter"))
        current_not_before = parse_certificate_datetime(current["notBefore"] or "")
        current_after_dt = parse_certificate_datetime(current_not_after)
        if incoming_not_before is None:
            return {
                **verdict, "allowed": False, "mode": "unverifiable",
                "reason": "无法解析上传证书的签发时间，无法确认是否为新申请证书，已拒绝",
            }
        if current_not_before is not None and incoming_not_before <= current_not_before:
            return {
                **verdict, "allowed": False, "mode": "stale",
                "reason": "上传证书的签发时间不晚于当前正在使用的证书，不是新申请的证书，已拒绝",
            }
        if incoming_not_after is not None and current_after_dt is not None and incoming_not_after <= current_after_dt:
            return {
                **verdict, "allowed": False, "mode": "shorter",
                "reason": "上传证书的有效期不晚于当前证书，无法作为续期证书",
            }
        return {
            **verdict, "allowed": True, "mode": "renewal",
            "reason": "处于到期前 " + str(REPLACE_UPLOAD_WINDOW_DAYS) + " 天窗口内，允许上传新申请证书",
        }

    if same_names:
        newest_prior = same_names[0]
        incoming_not_before = parse_certificate_datetime(status.get("notBefore"))
        prior_not_before = parse_certificate_datetime(newest_prior["notBefore"] or "")
        if incoming_not_before is not None and prior_not_before is not None and incoming_not_before <= prior_not_before:
            return {
                "allowed": False, "mode": "stale",
                "reason": "上传证书的签发时间不晚于已失效的旧证书，不是新申请的证书，已拒绝",
                "currentCertId": str(newest_prior["remoteCertId"] or ""),
                "currentNotAfter": str(newest_prior["notAfter"] or ""),
                "currentDays": certificate_days_remaining(newest_prior["notAfter"] or "", now_dt),
            }
    return {
        **verdict, "allowed": True, "mode": "recovery",
        "reason": "当前证书已失效或不存在，允许上传新申请证书",
    }


def _cdn_binding_credential(handler: Any, uid: int, accel_cred_id: int, expect_provider: str) -> Dict[str, Any]:
    """Resolve the credential behind a CF/ESA cert binding.

    Cloudflare and Aliyun are not acceleration-registry providers — their cert
    linkage reuses the user's existing DNS credential (the CF token that owns
    the custom hostname / the Aliyun AK that owns the ESA site), so this
    fetches the row directly instead of going through _acceleration_auth.
    """
    row = handler._get_credential_row(uid, int(accel_cred_id))
    if row is None:
        raise ValueError("加速凭证不存在或无权访问")
    provider = str(row["provider"] or "").strip().lower()
    if provider != expect_provider:
        raise ValueError(f"凭证类型不匹配: 需要 {expect_provider}，实际 {provider}")
    return {"credential": row, "secrets": handler._credential_secrets(row)}


def _cf_zone_for_host(cf: CloudflareApi, host: str) -> Dict[str, Any] | None:
    """Find the most specific zone covering `host` from the token's zone list."""
    normalized = _norm_host(host)
    if not normalized:
        return None
    labels = normalized.split(".")
    candidates = [".".join(labels[i:]) for i in range(0, max(0, len(labels) - 1))]
    for page in range(1, 5):
        listed = cf.list_zones(page, 50)
        zones = listed.get("zones") or []
        for zone in zones:
            if not isinstance(zone, dict):
                continue
            name = _norm_host(zone.get("name"))
            if name and name in candidates and str(zone.get("id") or "").strip():
                return zone
        if len(zones) < 50:
            break
    return None


def _bind_cert_to_cloudflare_provider(
    handler: Any, uid: int, accel_cred_id: int, site_id: str,
    cert_row: Any, accel_domain: str, dry_run: bool,
) -> str:
    """Cloudflare binder: upload the panel PEM as the custom hostname's custom
    certificate (ssl type=custom) and return an identifier for the binding row.

    Cloudflare SaaS custom hostnames accept user-uploaded certificates, so the
    edge serves exactly the panel certificate. site_id is the CF zone id.
    """
    cred = _cdn_binding_credential(handler, uid, accel_cred_id, "cloudflare")
    token = str(cred["secrets"].get("apiToken") or "").strip()
    if not token:
        raise ValueError("Cloudflare 凭证缺少 API Token")
    cf = CloudflareApi(token)
    host = _norm_host(accel_domain)
    if not host:
        raise ValueError("加速域名无效")
    zone_id = str(site_id or "").strip()
    if not zone_id:
        zone = _cf_zone_for_host(cf, host)
        zone_id = str((zone or {}).get("id") or "")
    if not zone_id:
        raise ValueError(f"Cloudflare 中未找到覆盖 {host} 的 Zone")
    target = None
    for item in cf.list_all_custom_hostnames(zone_id):
        if _norm_host(item.get("hostname")) == host:
            target = item
            break
    if target is None:
        raise ValueError(f"Cloudflare 中没有主机名 {host} 的自定义主机名记录（请先在 Cloudflare for SaaS 中添加）")
    hostname_id = str(target.get("id") or "").strip()
    if not hostname_id:
        raise ValueError("Cloudflare 自定义主机名缺少 id")
    pem = _panel_cert_pem(handler, uid, cert_row)
    cf.update_custom_hostname_custom_certificate(zone_id, hostname_id, pem["publicKey"], pem["privateKey"])
    # Identify the binding by the cert's fingerprint (stable across re-uploads
    # of the same PEM, unlike Cloudflare's internal certificate ids).
    fingerprint = ""
    try:
        meta = acme_api.parse_cert_pem(pem["publicKey"])
        fingerprint = str(meta.get("fingerprintSha256") or "").strip()
    except Exception:
        pass
    return f"cf-custom:{fingerprint or hostname_id}"


def _bind_cert_to_esa_provider(
    handler: Any, uid: int, accel_cred_id: int, site_id: str,
    cert_row: Any, accel_domain: str, dry_run: bool,
) -> str:
    """Aliyun ESA binder: ESA manages its own edge certificates (it cannot
    accept an uploaded PEM), so the actionable equivalent is to make sure a
    valid ESA-managed certificate covers the record — reusing an existing one,
    otherwise applying for ESA's free DV certificate for the domain.

    site_id is the ESA site id; the credential must be the aliyun DNS
    credential (same AccessKey that manages the site).
    """
    cred = _cdn_binding_credential(handler, uid, accel_cred_id, "aliyun")
    ak = str(cred["secrets"].get("accessKeyId") or "").strip()
    sk = str(cred["secrets"].get("accessKeySecret") or "").strip()
    if not ak or not sk:
        raise ValueError("阿里云凭证缺少 AccessKeyId/AccessKeySecret")
    site = str(site_id or "").strip()
    if not site:
        raise ValueError("ESA 加速绑定缺少站点 ID")
    record = _norm_host(accel_domain)
    if not record:
        raise ValueError("加速域名无效")
    region = str(cred["secrets"].get("region") or "").strip() or None
    valid_certs: List[Dict[str, Any]] = []
    try:
        listed = esa_list_certificates_by_record(ak, sk, region, site, [record], True, True)
        for row in listed.get("records") or []:
            if _norm_host(row.get("recordName")) != record:
                continue
            valid_certs.extend(c for c in (row.get("certificates") or []) if isinstance(c, dict))
    except AliyunEsaError:
        raise
    except Exception as exc:
        raise ValueError(f"查询 ESA 证书失败: {exc}")
    if valid_certs:
        cert = valid_certs[0]
        return f"esa-managed:{str(cert.get('id') or '') or record}"
    # No valid ESA cert — request the free DV certificate so the edge gets one.
    try:
        applied = esa_apply_certificate(ak, sk, region, site, [record], "lets_encrypt")
    except Exception as exc:
        raise ValueError(f"ESA 无有效证书且申请免费证书失败: {exc}")
    issued = [x for x in (applied.get("results") or []) if _norm_host(x.get("domain")) == record]
    if not issued:
        raise ValueError("ESA 免费证书申请未返回结果")
    return f"esa-applied:{str(issued[0].get('certificateId') or '') or record}"


# Provider → certificate binder. EdgeOne and Cloudflare accept a
# panel-uploaded PEM; Aliyun ESA manages its own edge certs (the binder
# ensures/applies one). Each binder returns an identifier stored as the
# binding's edgeCertId and raises on failure.
_ACCEL_CERT_BINDERS: Dict[str, Any] = {
    "edgeone": _bind_cert_to_edgeone_provider,
    "cloudflare": _bind_cert_to_cloudflare_provider,
    "aliyun_esa": _bind_cert_to_esa_provider,
}

_ACCEL_CERT_UNSUPPORTED_REASON: Dict[str, str] = {}


def _retire_replaced_edge_cert(
    handler: Any, uid: int, accel_cred_id: int,
    old_edge_cert_id: str, new_edge_cert_id: str, old_binding: Any,
) -> None:
    """Delete a panel-uploaded temp cert in an acceleration (Tencent) account
    once nothing references it anymore.

    Called after a rebind replaced the edge cert. Guards:
      - skip when the id is unchanged (reuse path — same PEM, nothing replaced)
      - skip when the old id is not a panel upload (it equals the binding's own
        certRemoteId AND that cert is not an acme cert — that is the user's
        own cloud certificate)
      - skip when any OTHER binding row still references the old edge cert
        (one upload serves every host under a wildcard cert)
    Never raises.
    """
    try:
        old_edge_cert_id = str(old_edge_cert_id or "").strip()
        new_edge_cert_id = str(new_edge_cert_id or "").strip()
        if not old_edge_cert_id or old_edge_cert_id == new_edge_cert_id:
            return
        old_source = str(old_binding["source"] or "") if old_binding is not None else ""
        old_cert_remote_id = str(old_binding["certRemoteId"] or "") if old_binding is not None else ""
        b_provider = str(old_binding["provider"] or "edgeone").strip().lower() if old_binding is not None else "edgeone"
        if b_provider != "edgeone":
            return
        is_uploaded_temp = old_source == "acme" or old_edge_cert_id != old_cert_remote_id
        if not is_uploaded_temp:
            return
        with conn() as c:
            still_used = c.execute(
                """SELECT COUNT(*) AS n FROM acceleration_cert_bindings
                   WHERE userId = ? AND edgeCertId = ? AND NOT (accelerationCredentialId = ? AND domainName = ?)""",
                (uid, old_edge_cert_id, int(accel_cred_id),
                 str(old_binding["domainName"] or "") if old_binding is not None else ""),
            ).fetchone()
        if still_used is not None and int(still_used["n"] or 0) > 0:
            return
        accel_ctx = handler._acceleration_auth(uid, int(accel_cred_id))
        secrets = handler._credential_secrets(accel_ctx["credential"])
        sid = str(secrets.get("secretId") or "").strip()
        skey = str(secrets.get("secretKey") or "").strip()
        if sid and skey:
            TencentSslApi(sid, skey).delete_certificate(old_edge_cert_id)
    except Exception:
        pass


def _sync_cert_to_edgeone(handler: Any, uid: int, cert_row: Any, dry_run: bool = False) -> Dict[str, Any]:
    """Bind a panel certificate to every matching acceleration domain.

    Provider-agnostic: targets come from dns_record_acceleration_states and each
    is dispatched to its provider's binder (see _ACCEL_CERT_BINDERS). EdgeOne is
    fully supported; other providers report a clear reason rather than failing
    silently. Never raises — a CDN binding failure must not break the
    originating SSL/deploy request.
    """
    domain = str(cert_row["domain"] or "").strip()
    results: List[Dict[str, Any]] = []
    if not _norm_host(domain):
        return {"synced": 0, "results": results, "skipped": "证书缺少域名"}
    # Match on the FULL name set (primary + SAN) so an acceleration on a SAN
    # host is still found when the primary domain differs.
    targets = _accel_targets_for_cert_names(uid, _cert_all_names(cert_row))
    if not targets:
        return {"synced": 0, "results": results, "skipped": "该域名没有已启用的加速"}
    cert_fp = ""
    try:
        cert_fp = str(cert_row["fingerprintSha256"] or "") if "fingerprintSha256" in cert_row.keys() else ""
    except Exception:
        cert_fp = ""
    # Group by (provider, credential, site) so one API client / one upload
    # serves a site.
    grouped: Dict[tuple, list] = {}
    for t in targets:
        grouped.setdefault((t.get("provider") or "edgeone", t["accelerationCredentialId"], t["siteId"]), []).append(t)
    for (provider, accel_cred_id, site_id), group in grouped.items():
        binder = _ACCEL_CERT_BINDERS.get(str(provider or "").lower())
        if binder is None:
            reason = _ACCEL_CERT_UNSUPPORTED_REASON.get(
                str(provider or "").lower(),
                f"加速服务商 {provider} 暂不支持推送证书",
            )
            for t in group:
                results.append({"domain": t["domainName"], "ok": False, "unsupported": True, "error": reason})
            continue
        if dry_run:
            # Preview ONLY — never resolve/upload a CertId, which would have
            # cloud side effects (uploading a duplicate PEM per domain).
            for t in group:
                results.append({"domain": t["domainName"], "ok": True, "dryRun": True, "willBind": True})
            continue
        for t in group:
            accel_domain = t["domainName"]
            # Snapshot the previous binding so a rebind that replaces the edge
            # cert can retire the old uploaded temp cert (renewal fingerprint
            # churn would otherwise accumulate one cert per renewal in the
            # acceleration account).
            old_binding = None
            try:
                with conn() as c:
                    old_binding = c.execute(
                        """SELECT * FROM acceleration_cert_bindings
                           WHERE userId = ? AND accelerationCredentialId = ? AND siteId = ? AND domainName = ? LIMIT 1""",
                        (uid, int(accel_cred_id), site_id, accel_domain),
                    ).fetchone()
            except Exception:
                old_binding = None
            try:
                edge_cert_id = binder(handler, uid, accel_cred_id, site_id, cert_row, accel_domain, dry_run)
                _upsert_accel_cert_binding(
                    uid, accel_cred_id, site_id, accel_domain,
                    str(cert_row["provider"] or ""), str(cert_row["remoteCertId"] or ""),
                    edge_cert_id, cert_fp, str(cert_row["notAfter"] or ""),
                    status="synced", error="", provider=str(provider or "edgeone"),
                )
                if old_binding is not None:
                    _retire_replaced_edge_cert(
                        handler, uid, int(accel_cred_id),
                        str(old_binding["edgeCertId"] or ""), edge_cert_id, old_binding,
                    )
                results.append({"domain": accel_domain, "ok": True, "edgeCertId": edge_cert_id, "provider": provider})
            except Exception as exc:
                _upsert_accel_cert_binding(
                    uid, accel_cred_id, site_id, accel_domain,
                    str(cert_row["provider"] or ""), str(cert_row["remoteCertId"] or ""),
                    "", cert_fp, str(cert_row["notAfter"] or ""),
                    status="failed", error=str(exc)[:400], provider=str(provider or "edgeone"),
                )
                results.append({"domain": accel_domain, "ok": False, "error": str(exc)[:300], "provider": provider})
        try:
            cache_delete_pattern(f"acceleration:domain-status:cred:{accel_cred_id}:*")
        except Exception:
            pass
    synced = len([r for r in results if r.get("ok")])
    unsupported = [r for r in results if r.get("unsupported")]
    out: Dict[str, Any] = {"synced": synced, "results": results}
    if unsupported and not synced:
        out["skipped"] = unsupported[0].get("error", "该加速服务商不支持推送证书")
    return out


def _cleanup_edgeone_cert_for_cert(handler: Any, uid: int, cert_row: Any) -> Dict[str, Any]:
    """Remove the temporary certs this panel uploaded into acceleration accounts
    for the given certificate, and drop the binding rows for it.

    Only certs the panel itself uploaded (tracked in acceleration_cert_bindings.
    edgeCertId, and only for acme / cross-account cases where edgeCertId differs
    from the cert's own remoteCertId) are deleted — a cert that lives in the
    same Tencent SSL account as the cert row is the user's own and must NOT be
    removed here. Never raises; returns a summary.
    """
    remote_id = str(cert_row["remoteCertId"] or "")
    provider = str(cert_row["provider"] or "")
    removed = []
    errors = []
    try:
        with conn() as c:
            rows = c.execute(
                """SELECT * FROM acceleration_cert_bindings
                   WHERE userId = ? AND certRemoteId = ?""",
                (uid, remote_id),
            ).fetchall()
    except Exception:
        return {"removedEdgeCerts": [], "errors": []}
    for row in rows:
        edge_cert_id = str(row["edgeCertId"] or "").strip()
        accel_cred_id = row["accelerationCredentialId"]
        b_source = str(row["source"] or "")
        b_provider = str(row["provider"] or "edgeone").strip().lower()
        # Only EdgeOne stores panel-uploaded temp certs in a Tencent SSL account
        # (which is what we can delete via TencentSslApi). Other providers keep
        # no such temp cert, so skip their rows.
        if b_provider != "edgeone":
            continue
        # Decide whether edge_cert_id is a panel-uploaded temp cert: it differs
        # from the panel cert's own id, OR the cert is an acme cert (always
        # uploaded). Same-account Tencent certs reuse the id → skip deletion.
        is_uploaded_temp = bool(edge_cert_id) and (
            provider == "acme" or edge_cert_id != remote_id or b_source == "acme"
        )
        if is_uploaded_temp and accel_cred_id:
            try:
                accel_ctx = handler._acceleration_auth(uid, int(accel_cred_id))
                secrets = handler._credential_secrets(accel_ctx["credential"])
                sid = str(secrets.get("secretId") or "").strip()
                skey = str(secrets.get("secretKey") or "").strip()
                if sid and skey:
                    ssl_api = TencentSslApi(sid, skey)
                    ssl_api.delete_certificate(edge_cert_id)
                    removed.append(edge_cert_id)
            except Exception as exc:
                errors.append({"edgeCertId": edge_cert_id, "error": str(exc)[:200]})
    # Drop the binding rows regardless (the panel cert is gone) — EXCEPT
    # bindings whose certificate row still exists and is issued: those record
    # a live deployment (e.g. an EdgeOne zone binding discovered from the API)
    # and must survive duplicate-row cleanup.
    try:
        with conn() as c:
            cert_still_alive = c.execute(
                "SELECT COUNT(*) AS n FROM ssl_certificates WHERE userId = ? AND remoteCertId = ? AND status = 'issued'",
                (uid, remote_id),
            ).fetchone()["n"]
            if not cert_still_alive:
                c.execute(
                    "DELETE FROM acceleration_cert_bindings WHERE userId = ? AND certRemoteId = ?",
                    (uid, remote_id),
                )
                c.commit()
    except Exception:
        pass
    return {"removedEdgeCerts": removed, "errors": errors}


def _best_cert_for_domain(uid: int, domain: str) -> Any:
    """Pick the healthiest issued certificate that covers `domain`.

    Prefers a cert whose names actually cover the host (wildcard-aware), then
    the one with the latest notAfter. Returns a sqlite Row or None.
    """
    normalized = _norm_host(domain)
    if not normalized:
        return None
    try:
        with conn() as c:
            rows = c.execute(
                """SELECT * FROM ssl_certificates
                   WHERE userId = ? AND status = 'issued' AND TRIM(domain) != ''
                   ORDER BY notAfter DESC""",
                (uid,),
            ).fetchall()
    except Exception:
        return None
    best_cover = None
    best_other = None
    for row in rows:
        if certificate_is_expired(row["notAfter"] or ""):
            continue
        names = [str(row["domain"] or "")]
        try:
            san = json.loads(row["san"] or "[]")
            if isinstance(san, list):
                names.extend(str(x) for x in san)
        except Exception:
            pass
        normalized_names = [_norm_host(n) for n in names if _norm_host(n)]
        if any(_wildcard_covers(n, normalized) for n in normalized_names):
            if best_cover is None:
                best_cover = row
            else:
                # keep the freshest covering cert
                if parse_certificate_datetime(row["notAfter"] or "") and parse_certificate_datetime(best_cover["notAfter"] or "") \
                        and parse_certificate_datetime(row["notAfter"]) > parse_certificate_datetime(best_cover["notAfter"]):
                    best_cover = row
        elif best_other is None:
            best_other = row
    return best_cover or best_other


def _accel_binding_drift_view(uid: int, item: Dict[str, Any], issued_rows: List[Any] | None = None) -> Dict[str, Any]:
    """Annotate a binding row with drift info: has the edge binding fallen
    behind the panel's current certificate?

    Wildcard-aware: an acceleration domain `cdn.example.com` bound from a
    `*.example.com` cert must be compared against that wildcard cert, not only
    an exact-domain cert — otherwise every wildcard-cert binding shows
    upToDate=None and renewal drift never surfaces. Pass `issued_rows` (all of
    the user's issued certs) when annotating many rows to avoid a query per
    binding.
    """
    domain = _norm_host(item.get("domainName"))
    source = str(item.get("source") or "").strip().lower()
    provider = "acme" if source in ("acme", "letsencrypt") else ("tencent_ssl" if source else "")
    if issued_rows is not None:
        rows = [r for r in issued_rows if not provider or str(r["provider"] or "") == provider]
    else:
        try:
            with conn() as c:
                if provider:
                    rows = c.execute(
                        """SELECT * FROM ssl_certificates
                           WHERE userId = ? AND provider = ? AND status = 'issued' AND TRIM(domain) != ''
                           ORDER BY notAfter DESC""",
                        (uid, provider),
                    ).fetchall()
                else:
                    rows = c.execute(
                        """SELECT * FROM ssl_certificates
                           WHERE userId = ? AND status = 'issued' AND TRIM(domain) != ''
                           ORDER BY notAfter DESC""",
                        (uid,),
                    ).fetchall()
        except Exception:
            rows = []
    best = None
    for row in rows:
        names = [_norm_host(row["domain"] if "domain" in row.keys() else "")]
        try:
            san = json.loads(row["san"] or "[]") if "san" in row.keys() else []
            if isinstance(san, list):
                names.extend(_norm_host(x) for x in san)
        except Exception:
            pass
        if domain and any(n and (_wildcard_covers(n, domain) or n == domain) for n in names):
            best = row
            break
    if best is not None:
        item["currentCertRemoteId"] = best["remoteCertId"]
        item["currentNotAfter"] = best["notAfter"]
        item["upToDate"] = str(best["remoteCertId"]) == str(item.get("certRemoteId"))
    else:
        item["upToDate"] = None
    return item


def _ssl_filter_and_summarize(certs: list, status_filter: str = "", source_filter: str = "") -> Dict[str, Any]:
    """Return full-set summaries plus server-side source/status filtered rows."""
    normalized = []
    for item in certs or []:
        cert = dict(item)
        source = str(cert.get("source") or "").strip().lower()
        if not source:
            source = "letsencrypt" if str(cert.get("provider") or "").lower() == "acme" else "tencent"
        cert["source"] = source
        normalized.append(cert)
    source_summary: Dict[str, int] = {}
    for cert in normalized:
        source_summary[cert["source"]] = source_summary.get(cert["source"], 0) + 1
    by_source = [c for c in normalized if not source_filter or c["source"] == source_filter]
    status_summary: Dict[str, int] = {}
    for cert in by_source:
        status = str(cert.get("status") or "applying")
        status_summary[status] = status_summary.get(status, 0) + 1
    filtered = [c for c in by_source if not status_filter or str(c.get("status") or "") == status_filter]
    # Per-account summary (source-scoped) so the UI can offer account filters
    # that only list accounts that actually have certificates in view.
    credential_map: Dict[tuple, Dict[str, Any]] = {}
    for cert in by_source:
        cred_id = cert.get("credentialId")
        if cred_id is None:
            continue
        key = (str(cred_id), cert["source"])
        entry = credential_map.get(key)
        if entry is None:
            entry = {
                "credentialId": cred_id,
                "credentialName": str(cert.get("credentialName") or ""),
                "source": cert["source"],
                "count": 0,
            }
            credential_map[key] = entry
        if not entry["credentialName"] and cert.get("credentialName"):
            entry["credentialName"] = str(cert.get("credentialName"))
        entry["count"] += 1
    credential_summary = sorted(
        credential_map.values(),
        key=lambda x: (x["source"], str(x["credentialName"] or "")),
    )
    return {
        "certs": filtered,
        "statusSummary": status_summary,
        "sourceSummary": source_summary,
        "credentialSummary": credential_summary,
    }


def _ssl_notification_settings(uid: int) -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        "enabled": False,
        "emailEnabled": False,
        "emailTo": "",
        "webhookEnabled": False,
        "webhookUrl": "",
        "wecomEnabled": False,
        "wecomWebhookUrl": "",
        # Opt-in: also push SUCCESS events (renew/issue/deploy ok) to the
        # webhook, not just failures. Off by default to avoid noise.
        "notifySuccessWebhook": False,
        "retentionDays": 30,
    }
    raw = get_system_setting(f"sslNotificationSettings:{uid}", "")
    if not raw:
        return defaults
    try:
        saved = json.loads(decrypt_text(raw))
        if isinstance(saved, dict):
            defaults.update(saved)
    except Exception:
        pass
    try:
        defaults["retentionDays"] = max(1, min(365, int(defaults.get("retentionDays") or 30)))
    except Exception:
        defaults["retentionDays"] = 30
    return defaults


def _save_ssl_notification_settings(uid: int, settings: Dict[str, Any]) -> None:
    set_system_setting(
        f"sslNotificationSettings:{uid}",
        encrypt_text(json.dumps(settings, ensure_ascii=False)),
    )


def _validate_ssl_notification_url(value: Any, *, wecom: bool = False) -> str:
    target = str(value or "").strip()
    if not target:
        return ""
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("通知地址必须是无用户信息的 HTTPS URL")
    hostname = parsed.hostname.lower().rstrip(".")
    if wecom and hostname != "qyapi.weixin.qq.com":
        raise ValueError("企业微信机器人地址必须使用 qyapi.weixin.qq.com")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    except Exception as ex:
        raise ValueError(f"通知地址无法解析: {ex}")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("通知地址不能指向本机、内网、保留或链路本地地址")
    return target


class _SslNotificationNoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("通知地址不允许 HTTP 重定向")


def _write_ssl_task_log(
    uid: int, task_type: str, task_id: Any, domain: Any, source: Any,
    status: str, attempt: int = 0, target_name: Any = None, message: Any = None,
) -> None:
    try:
        with conn() as c:
            c.execute(
                """INSERT INTO ssl_task_logs
                   (userId, taskType, taskId, domain, source, status, attempt, targetName, message, createdAt)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    uid, str(task_type)[:32], int(task_id) if task_id is not None else None,
                    str(domain or "")[:253], str(source or "")[:32], str(status)[:32],
                    max(0, int(attempt or 0)), str(target_name or "")[:1000],
                    str(message or "")[:2000], now_iso(),
                ),
            )
            c.commit()
    except Exception:
        pass


def _cleanup_ssl_task_history(uid: int) -> int:
    days = int(_ssl_notification_settings(uid).get("retentionDays") or 30)
    modifier = f"-{days} days"
    with conn() as c:
        log_count = c.execute(
            "DELETE FROM ssl_task_logs WHERE userId = ? AND datetime(createdAt) < datetime('now', ?)",
            (uid, modifier),
        ).rowcount
        job_count = c.execute(
            """DELETE FROM ssl_acme_jobs WHERE userId = ? AND status = 'success'
               AND completedAt IS NOT NULL AND datetime(completedAt) < datetime('now', ?)""",
            (uid, modifier),
        ).rowcount
        c.commit()
    return max(0, int(log_count or 0)) + max(0, int(job_count or 0))


def _send_ssl_failure_notifications(uid: int, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    settings = _ssl_notification_settings(uid)
    if not bool(settings.get("enabled")):
        return []
    with conn() as c:
        user_row = c.execute(
            """SELECT username, email, smtpHost, smtpPort, smtpSecure, smtpUser, smtpPass, smtpFrom
               FROM users WHERE id = ? LIMIT 1""",
            (uid,),
        ).fetchone()
    if not user_row:
        return []

    deliveries: List[Dict[str, Any]] = []
    event_name = str(payload.get("event") or "ssl_failure")
    domain = str(payload.get("domain") or "-")
    reason = str(payload.get("reason") or "未知错误")
    title = "DNS Panel SSL 续期失败" if event_name == "ssl_renewal_failed" else "DNS Panel SSL 部署失败"
    if event_name == "ssl_issue_failed":
        title = "DNS Panel SSL 签发失败"
    elif event_name == "ssl_notification_test":
        title = "DNS Panel SSL 通知测试"
    elif event_name == "ssl_expiry_warning":
        days_left = payload.get("daysRemaining")
        title = f"DNS Panel SSL 证书即将到期（剩余 {days_left} 天）" if isinstance(days_left, (int, float)) and days_left >= 0 else "DNS Panel SSL 证书已过期"

    if bool(settings.get("emailEnabled")):
        try:
            import smtplib
            from email.message import EmailMessage
            host = str(user_row["smtpHost"] or "").strip()
            secure = bool(user_row["smtpSecure"])
            port = int(user_row["smtpPort"] or (465 if secure else 587))
            username = str(user_row["smtpUser"] or "").strip()
            password = decrypt_text(user_row["smtpPass"]) if user_row["smtpPass"] else ""
            sender = str(user_row["smtpFrom"] or username or "").strip()
            recipients = _split_email_recipients(settings.get("emailTo"))
            if not host or not sender or not recipients:
                raise ValueError("SMTP、发件人或 SSL 告警收件人未完整配置")
            msg = EmailMessage()
            msg["Subject"] = f"{title}：{domain}"
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg.set_content(f"{title}\n\n域名：{domain}\n来源：{payload.get('source') or '-'}\n原因：{reason}\n时间：{payload.get('generatedAt') or now_iso()}")
            if secure or port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
                    if username:
                        smtp.login(username, password)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=10) as smtp:
                    if port == 587:
                        smtp.starttls()
                    if username:
                        smtp.login(username, password)
                    smtp.send_message(msg)
            deliveries.append({"channel": "email", "success": True})
        except Exception as ex:
            deliveries.append({"channel": "email", "success": False, "error": str(ex)[:500]})

    for channel, enabled_key, url_key, wecom in (
        ("webhook", "webhookEnabled", "webhookUrl", False),
        ("wecom", "wecomEnabled", "wecomWebhookUrl", True),
    ):
        if not bool(settings.get(enabled_key)):
            continue
        try:
            target = _validate_ssl_notification_url(settings.get(url_key), wecom=wecom)
            data_payload: Dict[str, Any] = payload
            if wecom:
                data_payload = {
                    "msgtype": "markdown",
                    "markdown": {"content": f"**{title}**\n> 域名：{domain}\n> 来源：{payload.get('source') or '-'}\n> 原因：{reason}"},
                }
            request = urllib.request.Request(
                target, method="POST", data=json.dumps(data_payload, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "dns-panel-ssl-notify/1.0"},
            )
            with urllib.request.build_opener(_SslNotificationNoRedirect()).open(request, timeout=10) as response:
                status_code = int(getattr(response, "status", 200))
                raw = response.read(4096).decode("utf-8", errors="replace")
                if status_code < 200 or status_code >= 300:
                    raise ValueError(f"HTTP {status_code}: {raw[:200]}")
                if wecom:
                    result = json.loads(raw or "{}")
                    if int(result.get("errcode") or 0) != 0:
                        raise ValueError(str(result.get("errmsg") or "企业微信通知失败"))
            deliveries.append({"channel": channel, "success": True})
        except Exception as ex:
            deliveries.append({"channel": channel, "success": False, "error": str(ex)[:500]})

    try:
        create_log(
            user_id=uid, action="NOTIFY", resource_type="SSL_AUTOMATION", domain=domain,
            record_name=event_name, status="SUCCESS" if deliveries and all(x.get("success") for x in deliveries) else "FAILED",
            new_value=json.dumps(deliveries, ensure_ascii=False),
            error_message="; ".join(str(x.get("error")) for x in deliveries if x.get("error")) or None,
        )
    except Exception:
        pass
    return deliveries


def _push_ssl_success_event(uid: int, event: str, domain: str, source: str,
                            extra: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    """Push a SUCCESS certificate event to the configured webhook, if the user
    opted in (notifySuccessWebhook). Failures keep using _send_ssl_failure_*.

    Sends a compact JSON payload external systems can consume:
      {event, domain, source, status:"success", at, ...extra}
    Returns delivery results (empty when disabled / not configured).
    """
    settings = _ssl_notification_settings(uid)
    if not (bool(settings.get("enabled")) and bool(settings.get("notifySuccessWebhook")) and bool(settings.get("webhookEnabled"))):
        return []
    target = str(settings.get("webhookUrl") or "").strip()
    if not target:
        return []
    deliveries: List[Dict[str, Any]] = []
    payload: Dict[str, Any] = {
        "event": event, "domain": domain, "source": source,
        "status": "success", "at": now_iso(),
    }
    if isinstance(extra, dict):
        payload.update(extra)
    try:
        target = _validate_ssl_notification_url(target)
        request = urllib.request.Request(
            target, method="POST", data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "dns-panel-ssl-notify/1.0"},
        )
        with urllib.request.build_opener(_SslNotificationNoRedirect()).open(request, timeout=10) as response:
            status_code = int(getattr(response, "status", 200))
            if status_code < 200 or status_code >= 300:
                raise ValueError(f"HTTP {status_code}")
        deliveries.append({"channel": "webhook", "success": True})
    except Exception as ex:
        deliveries.append({"channel": "webhook", "success": False, "error": str(ex)[:300]})
    try:
        create_log(
            user_id=uid, action="NOTIFY", resource_type="SSL_AUTOMATION", domain=domain,
            record_name=event, status="SUCCESS" if deliveries and all(x.get("success") for x in deliveries) else "FAILED",
            new_value=json.dumps(deliveries, ensure_ascii=False),
            error_message="; ".join(str(x.get("error")) for x in deliveries if x.get("error")) or None,
        )
    except Exception:
        pass
    return deliveries


def _check_ssl_expiry_notifications(uid: int) -> Dict[str, Any]:
    """Proactively notify about certificates expiring in 30 / 7 / 1 days.

    Runs from the daily auto-renew worker. Each (certificate, expiry date)
    pair fires at most one notification per threshold band, tracked in
    ssl_task_logs so the marker survives restarts and a renewed cert (new
    notAfter) starts a fresh notification cycle.
    """
    settings = _ssl_notification_settings(uid)
    thresholds = (30, 7, 1)
    checked = notified = expired_pushed = 0
    with conn() as c:
        rows = c.execute(
            """SELECT provider, remoteCertId, domain, notAfter, status
               FROM ssl_certificates
               WHERE userId = ? AND TRIM(domain) != ''
                 AND notAfter IS NOT NULL AND TRIM(notAfter) != ''""",
            (uid,),
        ).fetchall()
    now_dt = _ssl_now()
    for row in rows:
        status = str(row["status"] or "").strip().lower()
        if status in ("failed", "cancelled", "revoked"):
            continue
        not_after = str(row["notAfter"] or "")
        days = certificate_days_remaining(not_after, now_dt)
        if days is None:
            continue
        checked += 1
        expired = days < 0
        # Only alert for certificates that are/were issued; an "applying" row
        # has no real expiry yet.
        if status not in ("issued", "expired") and not expired:
            continue
        if not expired and days not in thresholds and days > min(thresholds):
            continue
        band = "expired" if expired else str(days)
        domain = str(row["domain"] or row["remoteCertId"] or "-")
        marker = f"expiry:{band}"
        # Dedup: same cert + same expiry + same band is only pushed once.
        with conn() as c:
            already = c.execute(
                """SELECT id FROM ssl_task_logs
                   WHERE userId = ? AND taskType = 'renewal' AND domain = ? AND status = 'notified'
                     AND message = ? AND taskId IS NULL
                     AND datetime(createdAt) >= datetime('now', '-45 days')
                   LIMIT 1""",
                (uid, domain, f"{marker}|{not_after}"),
            ).fetchone()
        if already:
            continue
        reason = (
            f"证书已过期 {-days} 天，请立即续期" if expired
            else f"证书将在 {days} 天后到期（{not_after}），请及时续期"
        )
        deliveries = _send_ssl_failure_notifications(uid, {
            "event": "ssl_expiry_warning",
            "domain": domain,
            "source": "letsencrypt" if str(row["provider"] or "") == "acme" else "tencent",
            "reason": reason,
            "daysRemaining": days,
            "notAfter": not_after,
            "generatedAt": now_iso(),
        })
        if deliveries:
            notified += 1
            if expired:
                expired_pushed += 1
            # Record the send as a marker (status='notified' is distinct from
            # task outcomes so the cleanup retention rules still apply).
            _write_ssl_task_log(
                uid, "renewal", None, domain,
                "letsencrypt" if str(row["provider"] or "") == "acme" else "tencent",
                "notified", message=f"{marker}|{not_after}",
            )
    return {"checked": checked, "notified": notified, "expired": expired_pushed}


# Certificates this close to expiry are force-deployed to every site and
# acceleration domain, so the plugin's cron + the panel's daily pass always
# push a fresh copy BEFORE the edge/origin starts serving an expired cert.
PRE_EXPIRY_DEPLOY_DAYS = 7


def _ensure_pre_expiry_deployments(uid: int, days: int = PRE_EXPIRY_DEPLOY_DAYS) -> Dict[str, Any]:
    """Guarantee every certificate expiring within `days` is queued for deploy.

    Runs from the daily auto-renew worker AFTER renewal, so a cert that just
    got renewed (and therefore has a NEW notAfter well beyond the window) is
    skipped. For any still-expiring-within-the-window issued cert this re-arms
    its deployment event (queued/running are left alone; success/failed/skipped
    are reset to queued) so the BaoTa plugin's next claim deploys the fresh copy
    to every matching site even if a previous attempt already succeeded with an
    older fingerprint.

    The CDN/EdgeOne edge copy is handled by the worker's own
    /certificates/sync-edgeone pass that runs right after this one — no handler
    is available here to reach the acceleration API, and duplicating it would
    double the cloud calls.

    Idempotent and best-effort: it never raises, and re-queuing an event the
    plugin already deployed is harmless (the plugin's own downgrade guard keeps
    it from shrinking host coverage).
    """
    summary: Dict[str, Any] = {"scanned": 0, "queued": 0, "domains": []}
    try:
        with conn() as c:
            rows = c.execute(
                """SELECT provider, remoteCertId, credentialId, domain, notAfter, status
                   FROM ssl_certificates
                   WHERE userId = ? AND status = 'issued' AND TRIM(domain) != ''
                     AND notAfter IS NOT NULL AND TRIM(notAfter) != ''""",
                (uid,),
            ).fetchall()
    except Exception:
        return summary
    ts = now_iso()
    for row in rows:
        remaining = certificate_days_remaining(row["notAfter"] or "")
        if remaining is None:
            continue
        # Only the pre-expiry window (still valid, but soon to lapse).
        if remaining < 0 or remaining > max(1, int(days)):
            continue
        summary["scanned"] += 1
        try:
            with conn() as c:
                existing = c.execute(
                    """SELECT id, status FROM ssl_deployment_events
                       WHERE userId = ? AND provider = ? AND remoteCertId = ? LIMIT 1""",
                    (uid, row["provider"], row["remoteCertId"]),
                ).fetchone()
                if existing is None:
                    c.execute(
                        """INSERT INTO ssl_deployment_events
                           (userId, provider, remoteCertId, credentialId, domain, source, status, createdAt, updatedAt)
                           VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
                        (
                            uid, row["provider"], row["remoteCertId"], row["credentialId"],
                            row["domain"], "letsencrypt" if str(row["provider"]) == "acme" else "tencent",
                            ts, ts,
                        ),
                    )
                elif str(existing["status"] or "") in ("queued", "running"):
                    # Already awaiting/being handled — leave it alone.
                    continue
                else:
                    # success / failed / skipped → re-arm so the fresh copy is
                    # pushed again for the pre-expiry guarantee.
                    c.execute(
                        """UPDATE ssl_deployment_events SET status = 'queued', attempts = 0,
                             nextAttemptAt = NULL, targetName = NULL, fingerprint = NULL,
                             error = NULL, startedAt = NULL, completedAt = NULL, updatedAt = ?
                           WHERE id = ?""",
                        (ts, existing["id"]),
                    )
                c.commit()
            summary["queued"] += 1
            summary["domains"].append(str(row["domain"] or row["remoteCertId"]))
        except Exception:
            pass
    return summary




def _acceleration_repair_targets(uid: int) -> List[Dict[str, Any]]:
    """Every accelerated host that needs its edge certificate re-pointed.

    Sources, in order of trust:
      1. dns_record_acceleration_states — accelerations enabled from the panel.
      2. acceleration_cert_bindings — hosts the panel has already bound before
         (this is what keeps drift repair working for hosts whose DNS record
         was moved out of the panel).
    For each host the effective certificate is resolved with the SAME rule as
    everywhere else: a valid certificate for the exact root domain first, then
    the wildcard that covers it (*.example.com). An expired certificate is
    never chosen while a usable one exists.
    """
    targets: Dict[tuple, Dict[str, Any]] = {}
    try:
        with conn() as c:
            state_rows = c.execute(
                """SELECT accelerationProvider, accelerationCredentialId, accelerationSiteId,
                          accelerationDomain, recordName
                   FROM dns_record_acceleration_states
                   WHERE userId = ? AND enabled = 1""",
                (uid,),
            ).fetchall()
            binding_rows = c.execute(
                """SELECT provider, accelerationCredentialId, siteId, domainName
                   FROM acceleration_cert_bindings WHERE userId = ?""",
                (uid,),
            ).fetchall()
    except Exception:
        return []
    for row in list(state_rows) + list(binding_rows):
        key = (
            str(row["accelerationProvider"] if "accelerationProvider" in row.keys() else row["provider"] or "edgeone").strip().lower(),
            int(row["accelerationCredentialId"] or 0),
            str(row["accelerationSiteId"] if "accelerationSiteId" in row.keys() else row["siteId"] or "").strip(),
            _norm_host(row["accelerationDomain"] if "accelerationDomain" in row.keys() else row["domainName"]),
        )
        if not key[2] or not key[3]:
            continue
        targets.setdefault(key, {"provider": key[0], "credentialId": key[1], "siteId": key[2], "domainName": key[3]})
    return list(targets.values())


def _acceleration_edge_state(handler: Any, uid: int, api: Any, target: Dict[str, Any]) -> Dict[str, Any]:
    """What the acceleration provider currently serves for one host."""
    state: Dict[str, Any] = {"certificateId": "", "expireTime": "", "daysRemaining": None, "status": ""}
    describe = getattr(api, "describe_host_certificates", None)
    if describe is None:
        return state
    try:
        listed = describe(target["siteId"], [target["domainName"]])
    except Exception:
        return state
    wanted = _norm_host(target["domainName"])
    for item in (listed.get("items") or []):
        host_list = [_norm_host(h) for h in (item.get("hosts") or [item.get("host")] or [])]
        if wanted not in host_list:
            continue
        state["certificateId"] = str(item.get("certificateId") or "").strip()
        state["expireTime"] = str(item.get("expireTime") or "")
        state["status"] = str(item.get("status") or "")
        state["daysRemaining"] = certificate_days_remaining(item.get("expireTime"), _ssl_now())
        break
    return state


def _repair_acceleration_certificates(uid: int, dry_run: bool = False) -> Dict[str, Any]:
    """Re-point every accelerated host whose edge certificate is unusable.

    A host is repaired when the edge serves no certificate, a certificate that
    already EXPIRED, one inside the pre-expiry window, or a certificate that no
    longer belongs to the best available panel certificate for that host. The
    replacement is always the effective certificate for the domain: exact root
    domain certificate first, wildcard second.
    """
    summary: Dict[str, Any] = {"checked": 0, "repaired": 0, "totalRepaired": 0, "skipped": 0, "errors": [], "results": []}
    if not dry_run:
        _refresh_ssl_rows_from_cloud(uid)
    targets = _acceleration_repair_targets(uid)
    candidates = _ssl_candidate_rows(uid)
    if not candidates:
        return summary
    for target in targets:
        summary["checked"] += 1
        try:
            accel_ctx = _SSL_MAINTENANCE_HANDLER_ACCEL(uid, int(target["credentialId"] or 0))
        except Exception as ex:
            summary["errors"].append({"domain": target["domainName"], "error": str(ex)[:200]})
            continue
        api = accel_ctx.get("api") if isinstance(accel_ctx, dict) else None
        if api is None or not hasattr(api, "modify_hosts_certificate"):
            summary["skipped"] += 1
            continue
        edge = _acceleration_edge_state(_SSL_MAINTENANCE_HANDLER, uid, api, target)
        best = _effective_cert_for_host(uid, target["domainName"], candidates)
        if best is None:
            summary["skipped"] += 1
            summary["results"].append({"domain": target["domainName"], "action": "skip", "reason": "面板没有可用证书"})
            continue
        best_valid = not certificate_is_expired(best["notAfter"] or "", _ssl_now())
        edge_days = edge.get("daysRemaining")
        needs = False
        reason = ""
        if not edge.get("certificateId"):
            needs, reason = True, "加速域名尚未绑定证书"
        elif isinstance(edge_days, int) and edge_days < 0:
            needs, reason = True, "加速证书已过期"
        elif isinstance(edge_days, int) and edge_days <= PRE_EXPIRY_DEPLOY_DAYS:
            needs, reason = True, "加速证书即将到期"
        elif not isinstance(edge_days, int):
            needs, reason = True, "加速证书有效期不可读"
        if not needs and best_valid:
            bound_id = str(edge.get("certificateId") or "")
            panel_id = str(best["remoteCertId"] or "")
            edge_expiry = parse_certificate_datetime(edge.get("expireTime"))
            best_expiry = parse_certificate_datetime(best["notAfter"] or "")
            if edge_expiry is not None and best_expiry is not None and best_expiry >= edge_expiry and bound_id and bound_id != panel_id:
                # The edge may legitimately hold a panel-uploaded temp copy;
                # only re-point when the panel certificate is at least as fresh.
                needs, reason = True, "加速证书并非当前有效证书"
        if not needs:
            summary["results"].append({"domain": target["domainName"], "action": "keep", "certId": str(best["remoteCertId"] or "")})
            continue
        if not best_valid:
            summary["skipped"] += 1
            summary["results"].append({"domain": target["domainName"], "action": "skip", "reason": "面板没有可用证书，无法修复"})
            continue
        item = {
            "domain": target["domainName"], "provider": target["provider"],
            "certId": str(best["remoteCertId"] or ""), "certDomain": str(best["domain"] or ""),
            "reason": reason, "edgeCertId": edge.get("certificateId") or "",
        }
        if dry_run:
            item["action"] = "would_repair"
            summary["repaired"] += 1
            summary["totalRepaired"] += 1
            summary["results"].append(item)
            continue
        try:
            binder = _ACCEL_CERT_BINDERS.get(str(target["provider"] or "edgeone").lower())
            if binder is None:
                raise ValueError(f"加速服务商 {target['provider']} 暂不支持推送证书")
            bound = binder(_SSL_MAINTENANCE_HANDLER, uid, int(target["credentialId"] or 0), target["siteId"], best, target["domainName"], False)
            cert_fp = ""
            try:
                cert_fp = str(best["fingerprintSha256"] or "") if "fingerprintSha256" in best.keys() else ""
            except Exception:
                cert_fp = ""
            _upsert_accel_cert_binding(
                uid, int(target["credentialId"] or 0), target["siteId"], target["domainName"],
                str(best["provider"] or ""), str(best["remoteCertId"] or ""),
                bound, cert_fp, str(best["notAfter"] or ""),
                status="synced", error="", provider=str(target["provider"] or "edgeone"),
            )
            item.update({"action": "repaired", "edgeCertId": bound})
            summary["repaired"] += 1
            summary["totalRepaired"] += 1
            _write_ssl_task_log(
                uid, "deployment", None, target["domainName"],
                "letsencrypt" if str(best["provider"] or "") == "acme" else "tencent",
                "success", message=f"加速证书已修复（{reason}）→ {best['remoteCertId']}",
            )
        except Exception as ex:
            item.update({"action": "failed", "error": str(ex)[:300]})
            summary["errors"].append({"domain": target["domainName"], "error": str(ex)[:300]})
            _upsert_accel_cert_binding(
                uid, int(target["credentialId"] or 0), target["siteId"], target["domainName"],
                str(best["provider"] or ""), str(best["remoteCertId"] or ""),
                "", "", str(best["notAfter"] or ""),
                status="failed", error=str(ex)[:400], provider=str(target["provider"] or "edgeone"),
            )
            _write_ssl_task_log(
                uid, "deployment", None, target["domainName"], "edgeone", "failed",
                message=f"加速证书修复失败：{str(ex)[:300]}",
            )
        summary["results"].append(item)
    if summary["totalRepaired"]:
        try:
            cache_delete_pattern(f"ssl:certs:all:user:{uid}:*")
            cache_delete_pattern(f"acceleration:domain-status:*")
        except Exception:
            pass
    return summary






def _refresh_ssl_rows_from_cloud(uid: int) -> Dict[str, Any]:
    """Mirror every Tencent SSL account's certificates into ssl_certificates.

    The certificate list endpoint merges live cloud results with the local
    table, so the table can be empty while the UI shows plenty of rows. Every
    maintenance pass (dedup, acceleration repair, renewal coverage) needs the
    same authoritative set, so this refreshes it once, credential by credential.
    Never raises.
    """
    summary: Dict[str, Any] = {"credentials": 0, "synced": 0, "errors": []}
    with _ssl_conn() as c:
        cred_rows = c.execute(
            "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ?",
            (uid,),
        ).fetchall()
    for cred in cred_rows:
        try:
            secrets = _SSL_MAINTENANCE_HANDLER._credential_secrets(cred)
            sid = str(secrets.get("secretId") or "").strip()
            skey = str(secrets.get("secretKey") or "").strip()
            if not sid or not skey:
                continue
            api = TencentSslApi(sid, skey)
            fetched: list = []
            offset = 0
            complete = False
            while offset <= 1000:
                page = api.list_certificates(offset=offset, limit=100)
                batch = page.get("certificates") or []
                fetched.extend(batch)
                total = int(page.get("totalCount") or len(fetched))
                if len(batch) < 100 or len(fetched) >= total:
                    complete = True
                    break
                offset += 100
            outcome = _sync_cloud_rows(uid, int(cred["id"]), fetched, prune_missing=complete)
            summary["credentials"] += 1
            summary["synced"] += int(outcome.get("inserted", 0)) + int(outcome.get("updated", 0))
        except Exception as ex:
            summary["errors"].append({"credential": str(cred["name"] or ""), "error": str(ex)[:200]})
    if summary["synced"]:
        _ssl_cache_bust(f"ssl:certs:all:user:{uid}:*")
    return summary


def _sync_cloud_rows(uid: int, cred_id: int, certs: list, prune_missing: bool = False) -> Dict[str, int]:
    """Upsert cloud certificate rows into ssl_certificates (module-level twin
    of the handler's nested _sync_to_db, usable without an HTTP handler)."""
    ts = now_iso()
    inserted = updated = removed = 0
    seen: set = set()
    with _ssl_conn() as c:
        for cert in certs or []:
            remote_id = str(cert.get("remoteCertId") or "").strip()
            if not remote_id:
                continue
            seen.add(remote_id)
            status = str(cert.get("status") or "") or "issued"
            if status == "issued" and certificate_is_expired(cert.get("notAfter") or ""):
                status = "expired"
            san = cert.get("san")
            san_json = json.dumps(san, ensure_ascii=False) if isinstance(san, list) else str(san or "")
            existing = c.execute(
                "SELECT id, autoRenew FROM ssl_certificates WHERE userId = ? AND provider = 'tencent_ssl' AND remoteCertId = ?",
                (uid, remote_id),
            ).fetchone()
            if existing is not None:
                c.execute(
                    """UPDATE ssl_certificates SET
                         credentialId = ?, domain = ?, san = ?, certType = ?, productName = ?,
                         status = ?, issuer = ?, notBefore = ?, notAfter = ?, isUploaded = ?,
                         autoRenew = ?, syncedAt = ?, updatedAt = ?
                       WHERE id = ?""",
                    (
                        cred_id, cert.get("domain", ""), san_json, cert.get("certType", ""),
                        cert.get("productName", ""), status, cert.get("issuer", ""),
                        cert.get("notBefore", ""), cert.get("notAfter", ""),
                        1 if cert.get("isUploaded") else 0,
                        1 if cert.get("autoRenew") else int(existing["autoRenew"] or 0),
                        ts, ts, existing["id"],
                    ),
                )
                updated += 1
            else:
                c.execute(
                    """INSERT INTO ssl_certificates
                         (userId, credentialId, provider, remoteCertId, domain, san,
                          certType, productName, status, statusMsg, issuer, notBefore,
                          notAfter, isUploaded, autoRenew, syncedAt, createdAt, updatedAt)
                       VALUES (?, ?, 'tencent_ssl', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        uid, cred_id, remote_id, cert.get("domain", ""), san_json,
                        cert.get("certType", ""), cert.get("productName", ""), status,
                        cert.get("statusMsg", ""), cert.get("issuer", ""),
                        cert.get("notBefore", ""), cert.get("notAfter", ""),
                        1 if cert.get("isUploaded") else 0,
                        1 if cert.get("autoRenew") else 0,
                        ts, ts, ts,
                    ),
                )
                inserted += 1
        if prune_missing and seen:
            placeholders = ",".join("?" for _ in seen)
            removed = c.execute(
                f"""DELETE FROM ssl_certificates
                    WHERE userId = ? AND credentialId = ? AND provider = 'tencent_ssl'
                      AND remoteCertId NOT IN ({placeholders})""",
                (uid, cred_id, *sorted(seen)),
            ).rowcount or 0
        c.commit()
    return {"inserted": inserted, "updated": updated, "removed": int(removed)}

def _sync_issued_certs_to_acceleration(uid: int, dry_run: bool = False) -> Dict[str, Any]:
    """Sweep: bind the BEST valid certificate to every accelerated host.

    Complements _repair_acceleration_certificates (which reacts to a broken edge
    binding): this pass makes sure no accelerated host is left unbound at all,
    always preferring an exact root-domain certificate over a wildcard and never
    picking an expired one.
    """
    summary: Dict[str, Any] = {"targets": 0, "synced": 0, "skipped": 0, "errors": []}
    targets = _acceleration_repair_targets(uid)
    best_by_host: Dict[tuple, Any] = {}
    rows = _ssl_candidate_rows(uid)
    for target in targets:
        summary["targets"] += 1
        row = _effective_cert_for_host(uid, target["domainName"], rows)
        if row is None or certificate_is_expired(row["notAfter"] or ""):
            summary["skipped"] += 1
            continue
        best_by_host[(target["provider"], int(target["credentialId"] or 0), target["siteId"], target["domainName"])] = row
    if dry_run:
        summary["synced"] = len(best_by_host)
        summary["hosts"] = [k[3] for k in best_by_host]
        return summary
    handled: set = set()
    for target in targets:
        key = (target["provider"], int(target["credentialId"] or 0), target["siteId"], target["domainName"])
        if key in handled:
            continue
        handled.add(key)
        row = best_by_host.get(key)
        if row is None:
            continue
        try:
            outcome = _sync_cert_to_edgeone(_SSL_MAINTENANCE_HANDLER, uid, row)
            summary["synced"] += int(outcome.get("synced") or 0)
        except Exception as ex:
            summary["errors"].append({"domain": target["domainName"], "error": str(ex)[:200]})
    return summary

def _SSL_MAINTENANCE_HANDLER_ACCEL(uid: int, credential_id: int) -> Dict[str, Any]:
    """Resolve an acceleration credential without an HTTP handler instance."""
    row = _SSL_MAINTENANCE_HANDLER._get_credential_row(uid, credential_id)
    if row is None:
        raise ValueError("加速凭证不存在或无权访问")
    provider = str(row["provider"] or "").strip().lower()
    secrets = _SSL_MAINTENANCE_HANDLER._credential_secrets(row)
    from modules.acceleration_registry import build_acceleration_plugin
    api = build_acceleration_plugin(provider, secrets)
    return {"provider": provider, "credential": row, "secrets": secrets, "api": api}

def _ssl_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    u = self._auth()
    if not u:
        return
    uid = int(u.get("id") or 0)
    if uid <= 0:
        self._err("无效用户", 401)
        return

    # Expected BaoTa plugin version. Bump together with baota-ssl-plugin's
    # info.json so deployed plugins can detect that an update is available.
    PLUGIN_EXPECTED_VERSION = "2.1.0"

    def _require_api_scope(required: str) -> bool:
        if not u.get("_api_token"):
            return True
        scopes = set(u.get("_api_scopes") or [])
        if "*" in scopes or required in scopes:
            return True
        self._err(f"当前 API Token 缺少权限: {required}", 403)
        return False

    sub = path[len("/api/ssl"):]
    body = self._json_body(b)

    if u.get("_api_token"):
        if self.command == "GET" and not _require_api_scope("ssl:read"):
            return
        if self.command == "POST":
            required = None
            if sub in ("/certificates/issue-acme", "/certificates/apply"):
                required = "ssl:issue"
            elif sub in ("/auto-renew", "/auto-renew/", "/certificates/renew-expired", "/certificates/prune-superseded", "/certificates/reconcile", "/certificates/clean-expired", "/certificates/check-expiry", "/certificates/batch-deploy", "/certificates/batch-auto-renew", "/certificates/sync-edgeone", "/certificates/repair-acceleration", "/certificates/dedup") or sub.endswith("/auto-renew"):
                required = "ssl:renew"
            elif sub in ("/certificates/sync", "/certificates/reconcile-edge"):
                required = "ssl:deploy"
            elif sub.startswith("/deployment-events"):
                required = "ssl:deploy"
            elif sub == "/site-bindings/report":
                # 宝塔插件回传「域名 → 站点 / 反代 IP」清单。
                required = "ssl:deploy"
            elif sub == "/platform-deployments" or sub.startswith("/platform-deployments/") \
                    or sub == "/platform-credentials" or sub.startswith("/platform-credentials/"):
                required = "ssl:deploy"
            if required and not _require_api_scope(required):
                return
            if required is None:
                self._err("当前 API Token 不允许执行该 SSL 写操作", 403)
                return
        elif self.command not in ("GET", "POST"):
            self._err("当前 API Token 不允许执行该 SSL 写操作", 403)
            return

    def _get_cred_id(source: Any = None) -> str | None:
        v = source if source is not None else (body.get("credentialId") or first_or_none(q, "credentialId"))
        return str(v).strip() if v else None

    def _ssl_api(cred_id_raw: str | None):
        ctx = self._ssl_context(uid, cred_id_raw)
        return ctx["credential"], ctx["api"]

    def _invalidate(cred_id: int) -> None:
        cache_delete_pattern(f"ssl:*:cred:{cred_id}:*")
        cache_delete_pattern(f"ssl:*:{cred_id}:*")
        cache_delete_pattern(f"ssl:certs:all:user:{uid}:*")

    def _decorate_certificate(cert: Dict[str, Any]) -> Dict[str, Any]:
        item = dict(cert)
        item["daysRemaining"] = certificate_days_remaining(item.get("notAfter"))
        item["isExpired"] = certificate_is_expired(item.get("notAfter"))
        if str(item.get("status") or "") == "issued" and item["isExpired"]:
            item["status"] = "expired"
        item.setdefault("source", "tencent")
        item.setdefault("renewalOwner", "tencent" if item.get("autoRenew") else "panel")
        return item

    def _certificate_status(cert: Dict[str, Any]) -> str:
        status = str(cert.get("status") or "applying").strip().lower()
        if status == "issued" and certificate_is_expired(cert.get("notAfter")):
            return "expired"
        return status

    def _sync_to_db(cred_id: int, provider: str, certs: list, *, prune_missing: bool = False) -> Dict[str, int]:
        """Upsert remote certificates and reconcile disappeared Tencent rows.

        A cloud list response is authoritative for one credential. Rows missing
        from that response are removed only for Tencent records, never ACME rows,
        and only after a complete pagination pass (callers pass prune_missing
        only after proving the fetch was complete). This prevents stale local
        records from producing the misleading ``certificate missing`` download
        error while avoiding deletion on a transient API page failure.
        """
        ts = now_iso()
        seen_ids = set()
        inserted = updated = expired = removed = 0
        with conn() as c:
            for cert in certs:
                remote_id = str(cert.get("remoteCertId", "") or "").strip()
                if not remote_id:
                    continue
                seen_ids.add(remote_id)
                normalized_status = _certificate_status(cert)
                if normalized_status == "expired":
                    expired += 1
                existing = c.execute(
                    "SELECT id, notAfter, status, autoRenew FROM ssl_certificates WHERE userId = ? AND provider = ? AND remoteCertId = ?",
                    (uid, provider, remote_id),
                ).fetchone()
                if existing:
                    c.execute(
                        """UPDATE ssl_certificates SET
                            domain = ?, san = ?, certType = ?, productName = ?,
                            status = ?, statusMsg = ?, issuer = ?,
                            notBefore = ?, notAfter = ?, isUploaded = ?, autoRenew = ?,
                            remoteCreatedAt = ?, syncedAt = ?, updatedAt = ?
                        WHERE id = ?""",
                        (
                            cert.get("domain", ""),
                            json.dumps(cert.get("san") or [], ensure_ascii=False) if isinstance(cert.get("san"), list) else str(cert.get("san") or ""),
                            cert.get("certType", ""),
                            cert.get("productName", ""),
                            normalized_status,
                            cert.get("statusMsg", ""),
                            cert.get("issuer", ""),
                            cert.get("notBefore", ""),
                            cert.get("notAfter", ""),
                            1 if cert.get("isUploaded") else 0,
                            (1 if cert.get("autoRenew") else 0) if "autoRenew" in cert else int(existing["autoRenew"] or 0),
                            cert.get("remoteCreatedAt", ""),
                            ts,
                            ts,
                            existing["id"],
                        ),
                    )
                    updated += 1
                    if normalized_status == "issued" and str(existing["notAfter"] or "") != str(cert.get("notAfter") or ""):
                        c.execute(
                            """UPDATE ssl_deployment_events SET status = 'queued', attempts = 0, error = NULL,
                                 nextAttemptAt = NULL, targetName = NULL, fingerprint = NULL,
                                 startedAt = NULL, completedAt = NULL, updatedAt = ?
                               WHERE userId = ? AND provider = ? AND remoteCertId = ?""",
                            (ts, uid, provider, remote_id),
                        )
                else:
                    inserted += 1
                    c.execute(
                        """INSERT INTO ssl_certificates
                            (userId, credentialId, provider, remoteCertId, domain, san,
                             certType, productName, status, statusMsg, issuer,
                             notBefore, notAfter, isUploaded, autoRenew, remoteCreatedAt, syncedAt, createdAt, updatedAt)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            uid, cred_id, provider, remote_id,
                            cert.get("domain", ""),
                            json.dumps(cert.get("san") or [], ensure_ascii=False) if isinstance(cert.get("san"), list) else str(cert.get("san") or ""),
                            cert.get("certType", ""),
                            cert.get("productName", ""),
                            normalized_status,
                            cert.get("statusMsg", ""),
                            cert.get("issuer", ""),
                            cert.get("notBefore", ""),
                            cert.get("notAfter", ""),
                            1 if cert.get("isUploaded") else 0,
                            1 if cert.get("autoRenew") else 0,
                            cert.get("remoteCreatedAt", ""),
                            ts, ts, ts,
                        ),
                    )
            removed_rows: List[Any] = []
            if prune_missing and provider == "tencent_ssl":
                where_sql = "userId = ? AND credentialId = ? AND provider = 'tencent_ssl'"
                params: list[Any] = [uid, cred_id]
                if seen_ids:
                    placeholders = ",".join("?" for _ in seen_ids)
                    where_sql += f" AND remoteCertId NOT IN ({placeholders})"
                    params.extend(sorted(seen_ids))
                removed_rows = c.execute(
                    f"SELECT * FROM ssl_certificates WHERE {where_sql}", params
                ).fetchall()
                c.execute(f"DELETE FROM ssl_certificates WHERE {where_sql}", params)
                removed = int(c.execute("SELECT changes()").fetchone()[0] or 0)
            c.commit()
        # A pruned cert no longer exists in the cloud — remove any temp cert the
        # panel uploaded into acceleration accounts for it (and its binding
        # rows) so uploaded certificates don't accumulate there. Best-effort.
        for row in removed_rows:
            try:
                _cleanup_edgeone_cert_for_cert(self, uid, row)
            except Exception:
                pass
        return {"inserted": inserted, "updated": updated, "expired": expired, "removed": removed}

    def _acme_row_to_cert(row: Any) -> Dict[str, Any]:
        """Shape a DB ssl_certificates(provider='acme') row like a tencent cert
        so the frontend/plugin list rendering stays uniform."""
        san_raw = row["san"] if "san" in row.keys() else None
        try:
            san_val = json.loads(san_raw) if san_raw else []
        except Exception:
            san_val = san_raw or []
        global_auto_renew = get_system_setting("sslAutoRenewEnabled", "1") == "1"
        cert_auto_renew = bool(row["autoRenew"]) if "autoRenew" in row.keys() else True
        actual_expired = certificate_is_expired(row["notAfter"] or "")
        display_status = "expired" if str(row["status"] or "") == "issued" and actual_expired else row["status"]
        return {
            "id": row["id"],
            "remoteCertId": row["remoteCertId"],
            "credentialId": row["credentialId"],
            "credentialName": row["credentialName"] if "credentialName" in row.keys() else "",
            "provider": "acme",
            "source": "letsencrypt",
            "domain": row["domain"],
            "san": san_val,
            "certType": "DV",
            "keyLength": row["certType"] or "2048",
            "productName": row["productName"] or "Let's Encrypt",
            "status": display_status,
            "statusMsg": row["statusMsg"] or "",
            "issuer": row["issuer"] or "Let's Encrypt",
            "notBefore": row["notBefore"] or "",
            "notAfter": row["notAfter"] or "",
            "daysRemaining": certificate_days_remaining(row["notAfter"] or ""),
            "isExpired": certificate_is_expired(row["notAfter"] or ""),
            "isUploaded": False,
            "remoteCreatedAt": row["remoteCreatedAt"] or row["createdAt"],
            "syncedAt": row["syncedAt"] or "",
            "autoRenew": cert_auto_renew,
            "globalAutoRenew": global_auto_renew,
            "renewalOwner": "panel",
            "effectiveAutoRenew": global_auto_renew and cert_auto_renew,
            "lastRenewedAt": row["lastRenewedAt"] if "lastRenewedAt" in row.keys() else "",
            "renewError": row["renewError"] if "renewError" in row.keys() else "",
            "ca": (row["acmeCa"] if "acmeCa" in row.keys() else "") or "letsencrypt",
        }

    def _list_acme_certs(search: str = "", filter_cred: str = "") -> list:
        """Return acme certs from the DB, joined to their DNS credential name."""
        # A process/container restart can interrupt the daemon issue worker and
        # otherwise leave a certificate stuck in "applying" forever. Reconcile
        # completed files first; mark only genuinely stale applications failed.
        with conn() as c:
            applying_rows = c.execute(
                """SELECT id, domain, certType, updatedAt
                   FROM ssl_certificates
                   WHERE userId = ? AND provider = 'acme' AND status = 'applying'""",
                (uid,),
            ).fetchall()
        for applying_row in applying_rows:
            updated_at = parse_dt(applying_row["updatedAt"])
            if not updated_at or (now() - updated_at).total_seconds() <= 20 * 60:
                continue
            try:
                svc = acme_api.AcmeService(key_length=str(applying_row["certType"] or "2048"))
                pem = svc.read_pem(str(applying_row["domain"] or ""))
                meta = acme_api.parse_cert_pem(pem["publicKey"])
                ts = now_iso()
                with conn() as c:
                    c.execute(
                        """UPDATE ssl_certificates SET status = 'issued', statusMsg = '',
                             notBefore = ?, notAfter = ?, san = ?, issuer = ?,
                             syncedAt = ?, updatedAt = ? WHERE id = ?""",
                        (
                            meta.get("notBefore", ""), meta.get("notAfter", ""),
                            json.dumps(meta.get("san") or [], ensure_ascii=False),
                            meta.get("issuer", "Let's Encrypt"), ts, ts, applying_row["id"],
                        ),
                    )
                    c.commit()
                continue
            except Exception:
                pass

            with conn() as c:
                c.execute(
                    """UPDATE ssl_certificates
                       SET status = 'failed',
                           statusMsg = '签发任务已中断或超时，请重新申请',
                           renewError = '签发任务已中断或超时，请重新申请',
                           updatedAt = ?
                       WHERE id = ? AND status = 'applying'""",
                    (now_iso(), applying_row["id"]),
                )
                c.commit()

        with conn() as c:
            rows = c.execute(
                """SELECT s.*, d.name AS credentialName
                   FROM ssl_certificates s
                   LEFT JOIN dns_credentials d ON d.id = s.credentialId
                   WHERE s.userId = ? AND s.provider = 'acme'
                   ORDER BY s.createdAt DESC""",
                (uid,),
            ).fetchall()
        out = []
        for r in rows:
            if filter_cred and str(r["credentialId"]) != str(filter_cred):
                continue
            cert = _acme_row_to_cert(r)
            if search:
                hay = (cert["domain"] + " " + " ".join(cert["san"] if isinstance(cert["san"], list) else [])).lower()
                if search.lower() not in hay:
                    continue
            out.append(cert)
        return out

    def _acme_dns_context(dns_cred_id_raw: str | None):
        """Resolve a DNS credential usable for acme.sh DNS-01. Returns
        (row, provider, secrets, accountId). Raises ValueError on problems."""
        if not dns_cred_id_raw:
            raise ValueError("缺少 dnsCredentialId 参数（acme 签发需选择 DNS 凭证）")
        row = self._get_credential_row(uid, dns_cred_id_raw)
        if not row:
            raise ValueError("DNS 凭证不存在或无权访问")
        provider = str(row["provider"] or "").strip().lower()
        if provider not in acme_api.ACME_SUPPORTED_DNS_PROVIDERS:
            raise ValueError(f"acme.sh 暂不支持使用 {provider} 凭证进行 DNS 验证")
        secrets = self._credential_secrets(row)
        account_id = ""
        try:
            account_id = str(row["accountId"] or "")
        except Exception:
            account_id = ""
        return row, provider, secrets, account_id

    def _validate_acme_managed_domains(provider: str, secrets: Dict[str, Any], domains: List[str]) -> None:
        """Fail early when a credential with zone-list support cannot manage every SAN.

        Aliyun credentials remain supported by acme.sh, but this project has no
        AliDNS API client to enumerate their zones, so verification is delegated
        to acme.sh for that provider.
        """
        api_obj = None
        if provider == "cloudflare":
            token = str(secrets.get("apiToken") or "").strip()
            if token:
                api_obj = CloudflareApi(token)
        elif provider in ("dnspod", "dnspod_token"):
            api_obj = DnspodApi(secrets)
        if api_obj is None:
            return
        try:
            zones = []
            for page_no in range(1, 21):
                page_result = api_obj.list_zones(page_no, 200)
                batch = page_result.get("zones", [])
                if not isinstance(batch, list):
                    batch = []
                zones.extend(batch)
                try:
                    total = int(page_result.get("total") or len(zones))
                except Exception:
                    total = len(zones)
                if not batch or len(zones) >= total:
                    break
        except Exception as exc:
            raise ValueError(f"无法验证 DNS 凭证的域名管理范围: {exc}")
        zone_names = {
            str(zone.get("name") or "").strip().lower().rstrip(".")
            for zone in zones if isinstance(zone, dict)
        }
        unmanaged = []
        for domain_name in domains:
            host = str(domain_name or "").lower().lstrip("*.").rstrip(".")
            if not any(host == zone or host.endswith("." + zone) for zone in zone_names if zone):
                unmanaged.append(domain_name)
        if unmanaged:
            raise ValueError("所选 DNS 凭证无法管理以下域名: " + "、".join(unmanaged))

    def _ensure_deployment_events() -> None:
        """Create one idempotent deployment event for every deployable certificate.

        Only certs that are issued AND not actually past notAfter qualify —
        enqueueing a dead certificate just makes the site plugin fail checks.
        """
        ts = now_iso()
        with conn() as c:
            rows = c.execute(
                """SELECT provider, remoteCertId, credentialId, domain, notAfter
                   FROM ssl_certificates
                   WHERE userId = ? AND status = 'issued' AND TRIM(domain) != ''""",
                (uid,),
            ).fetchall()
            for row in rows:
                if certificate_is_expired(row["notAfter"] or ""):
                    # 过期证书不允许部署：只保留“删除/续费”两条路。已经排队的
                    # 事件同样作废，否则插件领取后仍会把过期证书推给站点。
                    c.execute(
                        """UPDATE ssl_deployment_events
                           SET status = 'skipped', error = ?, updatedAt = ?
                           WHERE userId = ? AND remoteCertId = ? AND status IN ('queued', 'running', 'failed')""",
                        ("证书已过期，禁止部署（请续期或删除）", ts, uid, row["remoteCertId"]),
                    )
                    continue
                source = "letsencrypt" if row["provider"] == "acme" else "tencent"
                c.execute(
                    """INSERT OR IGNORE INTO ssl_deployment_events
                       (userId, provider, remoteCertId, credentialId, domain, source, status, createdAt, updatedAt)
                       VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
                    (uid, row["provider"], row["remoteCertId"], row["credentialId"], row["domain"], source, ts, ts),
                )
                c.execute(
                    """UPDATE ssl_deployment_events SET credentialId = ?, domain = ?, source = ?
                       WHERE userId = ? AND provider = ? AND remoteCertId = ?""",
                    (row["credentialId"], row["domain"], source, uid, row["provider"], row["remoteCertId"]),
                )
            c.commit()

    def _ensure_site_bindings() -> None:
        """宝塔插件上报的「域名 → 站点 / 反代目标」快照表（幂等建表）。"""
        with conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS ssl_site_bindings (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     userId INTEGER NOT NULL,
                     domain TEXT NOT NULL,
                     siteNames TEXT NOT NULL DEFAULT '[]',
                     proxyTargets TEXT NOT NULL DEFAULT '[]',
                     serverIps TEXT NOT NULL DEFAULT '[]',
                     reportedAt DATETIME,
                     UNIQUE(userId, domain)
                   )"""
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_ssl_site_bindings_user ON ssl_site_bindings(userId, domain)")
            c.commit()

    try:
        if self.command == "GET" and sub == "/acme-cas":
            # CA choices for the ACME issuance form (Let's Encrypt / ZeroSSL /
            # Buypass + LE staging). EAB-capable CAs report requiresEab so the
            # form can demand the kid/hmac fields.
            cas = []
            for key, entry in acme_api.ACME_SUPPORTED_CAS.items():
                cas.append({
                    "value": key,
                    "label": entry.get("label") or key,
                    "requiresEab": key == "zerossl",
                })
            self._ok({"cas": cas, "default": "letsencrypt"}, "获取 CA 列表成功")
            return

        # GET /api/ssl/deployments/by-site — per-site deployment overview for
        # the task drawer trend view: latest event status/fingerprint/time plus
        # recent history per site.
        if self.command == "GET" and sub == "/deployments/by-site":
            _ensure_deployment_events()
            with conn() as c:
                rows = c.execute(
                    """SELECT * FROM ssl_deployment_events
                       WHERE userId = ?
                       ORDER BY COALESCE(completedAt, updatedAt, createdAt) DESC
                       LIMIT 1000""",
                    (uid,),
                ).fetchall()
            sites: Dict[str, Dict[str, Any]] = {}
            for row in rows:
                targets = [t.strip() for t in str(row["targetName"] or "").split(",") if t.strip()]
                if not targets:
                    targets = ["（未记录目标站点）"]
                fp_map: Dict[str, str] = {}
                try:
                    parsed_fp = json.loads(row["fingerprint"] or "{}")
                    if isinstance(parsed_fp, dict):
                        fp_map = {str(k): str(v) for k, v in parsed_fp.items() if v}
                except Exception:
                    fp_map = {}
                for site in targets:
                    entry = sites.get(site)
                    if entry is None:
                        entry = {
                            "site": site,
                            "latestStatus": row["status"],
                            "latestSource": row["source"],
                            "latestDomain": row["domain"],
                            "latestError": row["error"] or "",
                            "latestFingerprint": fp_map.get(site, ""),
                            "latestAt": row["completedAt"] or row["updatedAt"] or row["createdAt"],
                            "history": [],
                        }
                        sites[site] = entry
                    if len(entry["history"]) < 10:
                        entry["history"].append({
                            "eventId": row["id"],
                            "status": row["status"],
                            "domain": row["domain"],
                            "source": row["source"],
                            "attempts": row["attempts"],
                            "error": (row["error"] or "")[:200],
                            "at": row["completedAt"] or row["updatedAt"] or row["createdAt"],
                        })
            result = sorted(sites.values(), key=lambda x: str(x.get("latestAt") or ""), reverse=True)
            self._ok(result, f"获取 {len(result)} 个站点的部署概况")
            return

        if self.command == "GET" and sub == "/plugin-version":
            # The BaoTa plugin compares this with its own version and shows an
            # upgrade banner — syncing plugin updates was previously manual
            # and easy to miss.
            self._ok(
                {
                    "expectedVersion": PLUGIN_EXPECTED_VERSION,
                    "minVersion": PLUGIN_EXPECTED_VERSION,
                    "releaseNotes": "v2.1.0：同步时自动上报「域名 → 宝塔站点 / 反代 IP」清单，面板 SSL 页可查询当前域名绑定在哪个站点、被哪一个 IP 反代；修复若干问题。请升级插件后点「立即同步」生成快照",
                },
                "获取插件版本要求成功",
            )
            return

        if self.command == "GET" and sub == "/notification-settings":
            settings = _ssl_notification_settings(uid)
            self._ok(settings, "获取 SSL 通知设置成功")
            return

        if self.command == "POST" and sub == "/notification-settings":
            current = _ssl_notification_settings(uid)
            settings = {
                "enabled": bool(body.get("enabled", current.get("enabled"))),
                "emailEnabled": bool(body.get("emailEnabled", current.get("emailEnabled"))),
                "emailTo": str(body.get("emailTo", current.get("emailTo") or "")).strip(),
                "webhookEnabled": bool(body.get("webhookEnabled", current.get("webhookEnabled"))),
                "webhookUrl": str(body.get("webhookUrl", current.get("webhookUrl") or "")).strip(),
                "wecomEnabled": bool(body.get("wecomEnabled", current.get("wecomEnabled"))),
                "wecomWebhookUrl": str(body.get("wecomWebhookUrl", current.get("wecomWebhookUrl") or "")).strip(),
                "notifySuccessWebhook": bool(body.get("notifySuccessWebhook", current.get("notifySuccessWebhook"))),
                "retentionDays": body.get("retentionDays", current.get("retentionDays") or 30),
            }
            try:
                settings["retentionDays"] = max(1, min(365, int(settings["retentionDays"])))
            except Exception:
                self._err("任务保留天数应为 1-365 的整数", 400)
                return
            if settings["emailTo"]:
                recipients = _split_email_recipients(settings["emailTo"])
                if not recipients or any(not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", item) for item in recipients):
                    self._err("SSL 告警收件邮箱格式不正确", 400)
                    return
                settings["emailTo"] = ", ".join(recipients)
            try:
                if settings["webhookEnabled"] and settings["webhookUrl"]:
                    settings["webhookUrl"] = _validate_ssl_notification_url(settings["webhookUrl"])
                if settings["wecomEnabled"] and settings["wecomWebhookUrl"]:
                    settings["wecomWebhookUrl"] = _validate_ssl_notification_url(settings["wecomWebhookUrl"], wecom=True)
            except ValueError as ex:
                self._err(str(ex), 400)
                return
            _save_ssl_notification_settings(uid, settings)
            self._ok(settings, "SSL 通知与任务清理设置已保存")
            return

        if self.command == "POST" and sub == "/notification-settings/test":
            payload = {
                "event": "ssl_notification_test", "domain": "example.com", "source": "test",
                "reason": "这是一条测试消息，用于确认通知通道可用。", "generatedAt": now_iso(),
            }
            deliveries = _send_ssl_failure_notifications(uid, payload)
            if not deliveries:
                self._err("通知总开关未开启或没有启用任何通知通道", 400)
                return
            self._ok({"deliveries": deliveries}, "通知测试已执行")
            return

        if self.command == "POST" and sub == "/tasks/cleanup":
            count = _cleanup_ssl_task_history(uid)
            self._ok({"deleted": count}, f"已清理 {count} 条过期成功任务和日志")
            return

        if self.command == "GET" and sub in ("/task-logs", "/task-logs/download"):
            _cleanup_ssl_task_history(uid)
            task_type = str(first_or_none(q, "taskType") or "").strip().lower()
            status_filter = str(first_or_none(q, "status") or "").strip().lower()
            source_filter = str(first_or_none(q, "source") or "").strip().lower()
            domain_filter = str(first_or_none(q, "domain") or "").strip()
            if task_type and task_type not in ("acme", "deployment", "renewal", "cleanup"):
                self._err("无效任务类型", 400)
                return
            if status_filter and status_filter not in ("queued", "running", "success", "failed", "skipped", "cancelled", "retry"):
                self._err("无效任务状态", 400)
                return
            if source_filter and source_filter not in ("tencent", "letsencrypt", "acme"):
                self._err("无效任务来源", 400)
                return
            wheres = ["userId = ?"]
            params: List[Any] = [uid]
            for column, value in (("taskType", task_type), ("status", status_filter), ("source", source_filter)):
                if value:
                    wheres.append(f"{column} = ?")
                    params.append(value)
            if domain_filter:
                wheres.append("domain LIKE ?")
                params.append(f"%{domain_filter}%")
            where_sql = " AND ".join(wheres)
            with conn() as c:
                if sub.endswith("/download"):
                    rows = c.execute(
                        f"SELECT * FROM ssl_task_logs WHERE {where_sql} ORDER BY createdAt DESC LIMIT 10000", params,
                    ).fetchall()
                else:
                    page_no = p_int(first_or_none(q, "page") or "1", 1, 100000)
                    page_limit = p_int(first_or_none(q, "limit") or "50", 50, 500)
                    total = int(c.execute(f"SELECT COUNT(*) c FROM ssl_task_logs WHERE {where_sql}", params).fetchone()["c"])
                    rows = c.execute(
                        f"SELECT * FROM ssl_task_logs WHERE {where_sql} ORDER BY createdAt DESC LIMIT ? OFFSET ?",
                        params + [page_limit, (page_no - 1) * page_limit],
                    ).fetchall()
            if sub.endswith("/download"):
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["ID", "任务类型", "任务ID", "域名", "来源", "状态", "尝试次数", "目标", "消息", "时间"])
                for row in rows:
                    writer.writerow([row["id"], row["taskType"], row["taskId"], row["domain"], row["source"], row["status"], row["attempt"], row["targetName"], row["message"], row["createdAt"]])
                self._binary(("\ufeff" + output.getvalue()).encode("utf-8"), "ssl-task-logs.csv", "text/csv; charset=utf-8")
                return
            self._paged([dict(row) for row in rows], total, page_no, page_limit, "获取 SSL 任务日志成功")
            return

        if self.command == "GET" and sub == "/task-stats":
            _cleanup_ssl_task_history(uid)
            with conn() as c:
                status_rows = c.execute(
                    "SELECT status, COUNT(*) count FROM ssl_task_logs WHERE userId = ? GROUP BY status", (uid,),
                ).fetchall()
                source_rows = c.execute(
                    "SELECT source, COUNT(*) count FROM ssl_task_logs WHERE userId = ? GROUP BY source", (uid,),
                ).fetchall()
                reason_rows = c.execute(
                    """SELECT COALESCE(NULLIF(TRIM(message), ''), '未知原因') reason, COUNT(*) count
                       FROM ssl_task_logs WHERE userId = ? AND status = 'failed'
                       GROUP BY reason ORDER BY count DESC LIMIT 10""",
                    (uid,),
                ).fetchall()
            self._ok({
                "byStatus": {str(row["status"]): int(row["count"]) for row in status_rows},
                "bySource": {str(row["source"] or "unknown"): int(row["count"]) for row in source_rows},
                "failureReasons": [{"reason": row["reason"], "count": int(row["count"])} for row in reason_rows],
            }, "获取 SSL 任务统计成功")
            return

        # Deployment event queue consumed by site deployment plugins.
        if self.command == "GET" and sub == "/deployment-events":
            _ensure_deployment_events()
            status_filter = str(first_or_none(q, "status") or "").strip().lower()
            source_filter = str(first_or_none(q, "source") or "").strip().lower()
            domain_filter = str(first_or_none(q, "domain") or "").strip()
            if status_filter and status_filter not in ("queued", "running", "success", "failed", "skipped"):
                self._err("无效部署状态", 400)
                return
            if source_filter and source_filter not in ("tencent", "letsencrypt"):
                self._err("无效证书来源", 400)
                return
            page_no = p_int(first_or_none(q, "page") or "1", 1, 100000)
            page_limit = p_int(first_or_none(q, "limit") or "100", 100, 500)
            wheres = ["userId = ?"]
            params: List[Any] = [uid]
            if status_filter:
                wheres.append("status = ?")
                params.append(status_filter)
            if source_filter:
                wheres.append("source = ?")
                params.append(source_filter)
            if domain_filter:
                wheres.append("domain LIKE ?")
                params.append(f"%{domain_filter}%")
            where_sql = " AND ".join(wheres)
            with conn() as c:
                total = int(c.execute(f"SELECT COUNT(*) c FROM ssl_deployment_events WHERE {where_sql}", params).fetchone()["c"])
                rows = c.execute(
                    f"""SELECT * FROM ssl_deployment_events WHERE {where_sql}
                       ORDER BY createdAt DESC LIMIT ? OFFSET ?""",
                    params + [page_limit, (page_no - 1) * page_limit],
                ).fetchall()
            self._paged([dict(row) for row in rows], total, page_no, page_limit, "获取证书部署事件成功")
            return

        if self.command == "POST" and sub == "/deployment-events/claim":
            _ensure_deployment_events()
            with conn() as c:
                c.execute("BEGIN IMMEDIATE")
                c.execute(
                    """UPDATE ssl_deployment_events SET status = 'queued', error = '部署执行中断，已重新排队',
                         startedAt = NULL, updatedAt = ?
                       WHERE userId = ? AND status = 'running'
                         AND datetime(updatedAt) < datetime('now', '-10 minutes')""",
                    (now_iso(), uid),
                )
                row = c.execute(
                    """SELECT * FROM ssl_deployment_events
                       WHERE userId = ? AND status IN ('queued', 'failed') AND attempts < 5
                         AND (nextAttemptAt IS NULL OR datetime(nextAttemptAt) <= datetime('now'))
                       ORDER BY createdAt ASC LIMIT 1""",
                    (uid,),
                ).fetchone()
                if row is None:
                    c.commit()
                    self._ok(None, "暂无待部署证书")
                    return
                # 过期证书不允许部署：只能删除或续费。事件可能是过期前入队的，
                # 领取时再校验一次，避免部署已失效的证书。
                row_cert = c.execute(
                    "SELECT notAfter, status FROM ssl_certificates WHERE userId = ? AND remoteCertId = ? LIMIT 1",
                    (uid, row["remoteCertId"]),
                ).fetchone()
                if row_cert is not None and (
                    certificate_is_expired(row_cert["notAfter"] or "")
                    or str(row_cert["status"] or "") not in ("issued",)
                ):
                    c.execute(
                        """UPDATE ssl_deployment_events SET status = 'skipped', error = ?, updatedAt = ?
                           WHERE id = ?""",
                        (
                            "证书已过期或不可用，已拒绝部署（请续期或删除）",
                            now_iso(),
                            row["id"],
                        ),
                    )
                    c.commit()
                    _write_ssl_task_log(
                        uid, "deployment", row["id"], row["domain"], row["source"], "skipped",
                        message="证书已过期，跳过部署",
                    )
                    self._ok(None, "该证书已过期，已跳过部署（请续期或删除）")
                    return
                c.execute(
                    """UPDATE ssl_deployment_events SET status = 'running', attempts = attempts + 1,
                         startedAt = COALESCE(startedAt, ?), updatedAt = ?, error = NULL
                       WHERE id = ? AND status IN ('queued', 'failed')""",
                    (now_iso(), now_iso(), row["id"]),
                )
                if c.execute("SELECT changes()").fetchone()[0] != 1:
                    c.rollback()
                    self._ok(None, "部署事件已被其他执行器领取")
                    return
                c.commit()
            payload = dict(row)
            payload["attempts"] = int(row["attempts"] or 0) + 1
            _write_ssl_task_log(uid, "deployment", row["id"], row["domain"], row["source"], "running", payload["attempts"], message="部署事件已领取")
            self._ok(payload, "已领取证书部署事件")
            return

        m_deploy_retry = re.fullmatch(r"/deployment-events/(\d+)/retry", sub)
        if self.command == "POST" and m_deploy_retry:
            event_id = int(m_deploy_retry.group(1))
            with conn() as c:
                event = c.execute(
                    "SELECT id, status, domain, source FROM ssl_deployment_events WHERE id = ? AND userId = ?",
                    (event_id, uid),
                ).fetchone()
                if event is None:
                    self._err("部署事件不存在", 404)
                    return
                c.execute(
                    """UPDATE ssl_deployment_events SET status = 'queued', attempts = 0,
                         nextAttemptAt = NULL, targetName = NULL, fingerprint = NULL,
                         error = NULL, startedAt = NULL, completedAt = NULL, updatedAt = ?
                       WHERE id = ? AND userId = ? AND status IN ('failed', 'skipped', 'success')""",
                    (now_iso(), event_id, uid),
                )
                if c.execute("SELECT changes()").fetchone()[0] != 1:
                    c.rollback()
                    self._err("当前部署事件已在等待或执行中，无需重复排队", 409)
                    return
                c.commit()
            _write_ssl_task_log(uid, "deployment", event_id, event["domain"], event["source"], "retry", message="用户手动重新排队")
            self._ok({"id": event_id, "status": "queued"}, "部署事件已重新排队")
            return

        # POST /api/ssl/certificates/<id>/deploy — queue a (re)deployment of this
        # certificate. The BaoTa plugin claims the event on its next sync and
        # deploys to every matching whitelisted site; the event list shows the
        # outcome (target sites, per-site fingerprint, errors).
        if self.command == "POST" and sub == "/certificates/deploy":
            cert_id = str(body.get("certId") or "").strip()
            if not cert_id:
                self._err("缺少 certId 参数", 400)
                return
            with conn() as c:
                row = c.execute(
                    """SELECT provider, remoteCertId, credentialId, domain, status, notAfter
                       FROM ssl_certificates
                       WHERE userId = ? AND remoteCertId = ? LIMIT 1""",
                    (uid, cert_id),
                ).fetchone()
                if row is None:
                    self._err("证书不存在或尚未同步到本地，请先同步证书列表", 404)
                    return
                if str(row["status"] or "") != "issued":
                    self._err(f"当前证书状态（{row['status'] or '未知'}）不可部署", 400)
                    return
                if certificate_is_expired(row["notAfter"] or ""):
                    self._err("证书已过期，禁止部署（请先续期）", 400)
                    return
                source = "letsencrypt" if str(row["provider"] or "") == "acme" else "tencent"
                ts = now_iso()
                existing = c.execute(
                    """SELECT id, status, attempts FROM ssl_deployment_events
                       WHERE userId = ? AND provider = ? AND remoteCertId = ?""",
                    (uid, row["provider"], row["remoteCertId"]),
                ).fetchone()
                if existing is not None and str(existing["status"] or "") in ("queued", "running"):
                    self._ok({"id": existing["id"], "status": existing["status"]}, "该证书已在部署队列中")
                    return
                if existing is not None:
                    c.execute(
                        """UPDATE ssl_deployment_events SET status = 'queued', attempts = 0,
                             nextAttemptAt = NULL, targetName = NULL, fingerprint = NULL,
                             error = NULL, startedAt = NULL, completedAt = NULL, updatedAt = ?
                           WHERE id = ?""",
                        (ts, existing["id"]),
                    )
                    event_id = existing["id"]
                else:
                    c.execute(
                        """INSERT INTO ssl_deployment_events
                           (userId, provider, remoteCertId, credentialId, domain, source, status, createdAt, updatedAt)
                           VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
                        (uid, row["provider"], row["remoteCertId"], row["credentialId"], row["domain"], source, ts, ts),
                    )
                    event_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
                c.commit()
            _write_ssl_task_log(uid, "deployment", event_id, row["domain"], source, "queued", message="用户手动发起部署")
            self._ok(
                {"id": event_id, "status": "queued"},
                "已加入部署队列：宝塔插件下次同步（或每日自动任务）时自动部署到匹配站点",
            )
            return

        m_deploy_result = re.fullmatch(r"/deployment-events/(\d+)/result", sub)
        if self.command == "POST" and m_deploy_result:
            event_id = int(m_deploy_result.group(1))
            result_status = str(body.get("status") or "failed").strip().lower()
            if result_status not in ("success", "failed", "skipped"):
                self._err("无效部署结果状态", 400)
                return
            with conn() as c:
                event = c.execute(
                    "SELECT * FROM ssl_deployment_events WHERE id = ? AND userId = ?",
                    (event_id, uid),
                ).fetchone()
                if event is None:
                    self._err("部署事件不存在", 404)
                    return
                if str(event["status"] or "") != "running":
                    self._err("部署事件未处于执行中，拒绝重复或过期回执", 409)
                    return
                attempts = int(event["attempts"] or 0)
                error = str(body.get("error") or "")[:500]
                next_attempt = None
                stored_status = result_status
                if result_status == "failed" and attempts < 5:
                    delay = min(3600, 60 * (2 ** max(0, attempts - 1)))
                    next_attempt = (now() + timedelta(seconds=delay)).isoformat().replace("+00:00", "Z")
                c.execute(
                    """UPDATE ssl_deployment_events SET status = ?, targetName = ?, fingerprint = ?,
                         error = ?, nextAttemptAt = ?, completedAt = ?, updatedAt = ? WHERE id = ?""",
                    (
                        stored_status, str(body.get("targetName") or "")[:1000],
                        str(body.get("fingerprint") or "")[:1000], error, next_attempt,
                        now_iso() if result_status in ("success", "skipped") or attempts >= 5 else None,
                        now_iso(), event_id,
                    ),
                )
                c.commit()
            _write_ssl_task_log(
                uid, "deployment", event_id, event["domain"], event["source"], result_status,
                attempts, body.get("targetName"), error or ("部署完成" if result_status == "success" else "部署已跳过"),
            )
            # EdgeOne link: when a cert is deployed to an accelerated site,
            # bind the same cert to the matching EdgeOne acceleration domain so
            # the CDN edge stops serving a stale/expired certificate.
            edgeone_sync: Dict[str, Any] | None = None
            if result_status == "success":
                try:
                    cert_row = None
                    with conn() as c:
                        cert_row = c.execute(
                            """SELECT * FROM ssl_certificates
                               WHERE userId = ? AND provider = ? AND remoteCertId = ? LIMIT 1""",
                            (uid, event["provider"], event["remoteCertId"]),
                        ).fetchone()
                    if cert_row is not None and not certificate_is_expired(cert_row["notAfter"] or ""):
                        edgeone_sync = _sync_cert_to_edgeone(self, uid, cert_row)
                        if edgeone_sync and edgeone_sync.get("synced"):
                            _write_ssl_task_log(
                                uid, "deployment", event_id, event["domain"], event["source"], "success",
                                attempts, body.get("targetName"),
                                message=f"已同步证书到 CDN 加速域名 {edgeone_sync['synced']} 个",
                            )
                except Exception as exc:
                    edgeone_sync = {"synced": 0, "error": str(exc)[:200]}
            if result_status == "failed" and attempts >= 5:
                _send_ssl_failure_notifications(uid, {
                    "event": "ssl_deployment_failed", "taskId": event_id,
                    "domain": event["domain"], "source": event["source"],
                    "reason": error or "部署连续失败 5 次", "targetName": body.get("targetName"),
                    "generatedAt": now_iso(),
                })
            if result_status == "success":
                # External success-event push (opt-in webhook).
                try:
                    _push_ssl_success_event(
                        uid, "ssl_deployment_succeeded", str(event["domain"] or ""),
                        str(event["source"] or ""),
                        {"taskId": event_id, "targetName": body.get("targetName"),
                         "fingerprint": body.get("fingerprint"),
                         "accelSynced": (edgeone_sync or {}).get("synced", 0)},
                    )
                except Exception:
                    pass
            self._ok(
                {"id": event_id, "status": stored_status, "nextAttemptAt": next_attempt, "edgeoneSync": edgeone_sync},
                "部署结果已记录" + (f"（已同步 CDN 加速证书 {edgeone_sync['synced']} 个）" if edgeone_sync and edgeone_sync.get("synced") else ""),
            )
            return

        # ACME task management for visibility and manual recovery.
        if self.command == "GET" and sub == "/acme-jobs":
            _cleanup_ssl_task_history(uid)
            with conn() as c:
                rows = c.execute(
                    "SELECT * FROM ssl_acme_jobs WHERE userId = ? ORDER BY createdAt DESC LIMIT 100",
                    (uid,),
                ).fetchall()
            self._ok([dict(row) for row in rows], "获取 ACME 任务成功")
            return

        m_job_action = re.fullmatch(r"/acme-jobs/(\d+)/(retry|cancel)", sub)
        if self.command == "POST" and m_job_action:
            job_id = int(m_job_action.group(1))
            action = m_job_action.group(2)
            with conn() as c:
                job = c.execute("SELECT id, certificateId, operation, status, domain FROM ssl_acme_jobs WHERE id = ? AND userId = ?", (job_id, uid)).fetchone()
                if job is None:
                    self._err("ACME 任务不存在", 404)
                    return
                if action == "retry":
                    c.execute("UPDATE ssl_acme_jobs SET status = 'queued', attempts = 0, error = NULL, startedAt = NULL, completedAt = NULL, updatedAt = ? WHERE id = ? AND status IN ('failed', 'cancelled')", (now_iso(), job_id))
                else:
                    c.execute("UPDATE ssl_acme_jobs SET status = 'cancelled', completedAt = ?, updatedAt = ? WHERE id = ? AND status IN ('queued', 'failed')", (now_iso(), now_iso(), job_id))
                if c.execute("SELECT changes()").fetchone()[0] != 1:
                    c.rollback()
                    self._err("当前任务状态不允许" + ("重试" if action == "retry" else "取消"), 409)
                    return
                if action == "retry":
                    if str(job["operation"] or "issue") == "issue":
                        c.execute(
                            "UPDATE ssl_certificates SET status = 'applying', statusMsg = '任务已重新排队', renewError = '', updatedAt = ? WHERE id = ? AND userId = ?",
                            (now_iso(), job["certificateId"], uid),
                        )
                    else:
                        c.execute(
                            "UPDATE ssl_certificates SET renewError = '', updatedAt = ? WHERE id = ? AND userId = ?",
                            (now_iso(), job["certificateId"], uid),
                        )
                else:
                    c.execute(
                        "UPDATE ssl_certificates SET status = 'cancelled', statusMsg = '签发任务已取消', updatedAt = ? WHERE id = ? AND userId = ? AND status = 'applying' AND ? = 'issue'",
                        (now_iso(), job["certificateId"], uid, str(job["operation"] or "issue")),
                    )
                c.commit()
            _write_ssl_task_log(uid, "acme", job_id, job["domain"], "letsencrypt", "retry" if action == "retry" else "cancelled", message="用户手动操作")
            self._ok({"id": job_id, "status": "queued" if action == "retry" else "cancelled"}, "ACME 任务已" + ("重新排队" if action == "retry" else "取消"))
            return

        # Internal persisted ACME job runner. The app worker calls this endpoint;
        # queued/running rows remain in SQLite across restarts.
        if self.command == "POST" and sub == "/acme-jobs/process":
            if not u.get("_internal"):
                self._err("该接口仅供内部任务执行器调用", 403)
                return
            with conn() as c:
                c.execute("BEGIN IMMEDIATE")
                c.execute(
                    """UPDATE ssl_acme_jobs SET status = 'queued', error = '任务中断，已自动重新排队',
                         startedAt = NULL, updatedAt = ?
                       WHERE userId = ? AND status = 'running'
                         AND datetime(updatedAt) < datetime('now', '-20 minutes')""",
                    (now_iso(), uid),
                )
                job = c.execute(
                    """SELECT j.*, s.status AS certificateStatus
                       FROM ssl_acme_jobs j
                       LEFT JOIN ssl_certificates s ON s.id = j.certificateId
                       WHERE j.userId = ? AND j.status = 'queued' AND j.attempts < 3
                       ORDER BY j.createdAt ASC LIMIT 1""",
                    (uid,),
                ).fetchone()
                if job is None:
                    c.commit()
                    self._ok(None, "暂无待处理 ACME 任务")
                    return
                c.execute(
                    """UPDATE ssl_acme_jobs SET status = 'running', attempts = attempts + 1,
                         startedAt = COALESCE(startedAt, ?), updatedAt = ?, error = NULL
                         WHERE id = ? AND status = 'queued'""",
                    (now_iso(), now_iso(), job["id"]),
                )
                if c.execute("SELECT changes()").fetchone()[0] != 1:
                    c.rollback()
                    self._ok(None, "任务已被其他执行器领取")
                    return
                c.commit()

            attempts = int(job["attempts"] or 0) + 1
            _write_ssl_task_log(uid, "acme", job["id"], job["domain"], "letsencrypt", "running", attempts, message="ACME 任务开始执行")
            try:
                dns_row, dns_provider, dns_secrets, account_id = _acme_dns_context(str(job["dnsCredentialId"]))
                domains = json.loads(job["domains"] or "[]")
                if not isinstance(domains, list) or not domains:
                    domains = [job["domain"]]
                job_keys = job.keys()
                job_ca = str(job["ca"] or "") if "ca" in job_keys else ""
                job_eab_kid = str(job["eabKid"] or "") if "eabKid" in job_keys else ""
                job_eab_hmac = str(job["eabHmac"] or "") if "eabHmac" in job_keys else ""
                svc = acme_api.AcmeService(
                    key_length=str(job["keyLength"] or "2048"),
                    ca=job_ca, eab_kid=job_eab_kid, eab_hmac=job_eab_hmac,
                )
                if str(job["operation"] or "issue") == "renew":
                    meta = svc.renew(str(job["domain"] or domains[0]), dns_provider, dns_secrets, account_id, domains=domains)
                else:
                    meta = svc.issue(domains, dns_provider, dns_secrets, account_id)
                ts = now_iso()
                with conn() as c:
                    c.execute(
                        """UPDATE ssl_certificates SET status = 'issued', statusMsg = '',
                             notBefore = ?, notAfter = ?, san = ?, issuer = ?, lastRenewedAt = ?,
                             renewError = '', syncedAt = ?, updatedAt = ? WHERE id = ?""",
                        (
                            meta.get("notBefore", ""), meta.get("notAfter", ""),
                            json.dumps(meta.get("san") or domains, ensure_ascii=False),
                            meta.get("issuer", "Let's Encrypt"), ts, ts, ts, job["certificateId"],
                        ),
                    )
                    c.execute(
                        """UPDATE ssl_acme_jobs SET status = 'success', completedAt = ?, updatedAt = ?, error = NULL
                           WHERE id = ?""",
                        (ts, ts, job["id"]),
                    )
                    c.execute(
                        """UPDATE ssl_deployment_events SET status = 'queued', attempts = 0, error = NULL,
                             nextAttemptAt = NULL, targetName = NULL, fingerprint = NULL,
                             startedAt = NULL, completedAt = NULL, updatedAt = ?
                           WHERE userId = ? AND provider = 'acme' AND remoteCertId = ?""",
                        (ts, uid, job["domain"]),
                    )
                    c.commit()
                _write_ssl_task_log(uid, "acme", job["id"], job["domain"], "letsencrypt", "success", attempts, message="证书签发成功")
                cache_delete_pattern(f"ssl:certs:all:user:{uid}:*")
                # Bind the freshly issued/renewed cert to any EdgeOne
                # acceleration domain right away, so the edge serves the new
                # cert even before the site plugin redeploys. Best-effort.
                edgeone_sync = None
                try:
                    with conn() as c:
                        fresh = c.execute(
                            "SELECT * FROM ssl_certificates WHERE id = ? LIMIT 1",
                            (job["certificateId"],),
                        ).fetchone()
                    if fresh is not None:
                        edgeone_sync = _sync_cert_to_edgeone(self, uid, fresh)
                except Exception:
                    edgeone_sync = None
                # 新证书同步到已部署过的第三方平台（七牛云/又拍云）。Best-effort。
                platform_sync = None
                try:
                    if fresh is not None:
                        platform_sync = _sync_cert_to_platforms(self, uid, fresh)
                except Exception:
                    platform_sync = None
                # External success-event push (opt-in webhook).
                try:
                    _push_ssl_success_event(
                        uid,
                        "ssl_renewal_succeeded" if str(job["operation"] or "issue") == "renew" else "ssl_issue_succeeded",
                        str(job["domain"] or ""), "letsencrypt",
                        {"notAfter": (fresh["notAfter"] if fresh is not None else ""), "jobId": job["id"]},
                    )
                except Exception:
                    pass
                sync_note = ""
                if platform_sync and platform_sync.get("synced"):
                    sync_note = f"，已重传平台证书 {platform_sync['synced']} 个"
                self._ok(
                    {"jobId": job["id"], "certificateId": job["certificateId"], "edgeoneSync": edgeone_sync, "platformSync": platform_sync},
                    "ACME 任务处理成功" + (f"（已同步加速证书 {edgeone_sync['synced']} 个）" if edgeone_sync and edgeone_sync.get("synced") else "") + sync_note,
                )
                return
            except Exception as ex:
                final = attempts >= 3
                next_status = "failed" if final else "queued"
                operation = str(job["operation"] or "issue")
                # A failed renewal must not turn a previously issued/expired
                # certificate into an issuance failure. Keep its real state so
                # the next scheduler pass can retry it safely.
                cert_status = "failed" if operation == "issue" and final else (str(job["certificateStatus"] or "expired") if operation == "renew" else "applying")
                msg = str(ex)[:500]
                with conn() as c:
                    c.execute(
                        "UPDATE ssl_acme_jobs SET status = ?, error = ?, updatedAt = ?, completedAt = ? WHERE id = ?",
                        (next_status, msg, now_iso(), now_iso() if final else None, job["id"]),
                    )
                    c.execute(
                        "UPDATE ssl_certificates SET status = ?, statusMsg = ?, renewError = ?, updatedAt = ? WHERE id = ?",
                        (cert_status, (msg if final else (f"续期失败，等待自动重试（{attempts}/3）：{msg}" if operation == 'renew' else f"签发失败，等待自动重试（{attempts}/3）：{msg}")), msg, now_iso(), job["certificateId"]),
                    )
                    c.commit()
                _write_ssl_task_log(uid, "acme", job["id"], job["domain"], "letsencrypt", "failed" if final else "retry", attempts, message=msg)
                if final:
                    _send_ssl_failure_notifications(uid, {
                        "event": "ssl_issue_failed" if str(job["operation"] or "issue") == "issue" else "ssl_renewal_failed",
                        "taskId": job["id"], "domain": job["domain"], "source": "letsencrypt",
                        "reason": msg, "generatedAt": now_iso(),
                    })
                self._ok({"jobId": job["id"], "retrying": not final}, "ACME 任务失败，已重试排队" if not final else "ACME 任务失败")
                return

        # GET/POST /api/ssl/auto-renew — auto-renewal toggle + status
        if sub in ("/auto-renew", "/auto-renew/"):
            if self.command == "GET":
                self._ok({
                    "enabled": get_system_setting("sslAutoRenewEnabled", "1") == "1",
                    "days": int(get_system_setting("sslAutoRenewDays", "30") or 30),
                    "lastRunAt": get_system_setting("sslAutoRenewLastRunAt", ""),
                    "lastResult": get_system_setting("sslAutoRenewLastResult", ""),
                }, "获取自动续期设置成功")
                return
            if self.command == "POST":
                enabled = bool(body.get("enabled"))
                days = body.get("days")
                set_system_setting("sslAutoRenewEnabled", "1" if enabled else "0")
                if days is not None:
                    try:
                        set_system_setting("sslAutoRenewDays", str(max(1, min(60, int(days)))))
                    except Exception:
                        pass
                self._ok({
                    "enabled": enabled,
                    "days": int(get_system_setting("sslAutoRenewDays", "30") or 30),
                }, "自动续期已" + ("开启" if enabled else "关闭"))
                return

        # GET /api/ssl/credentials — list credentials usable for SSL
        if self.command == "GET" and sub in ("/credentials", "/credentials/"):
            with conn() as c:
                rows = c.execute(
                    "SELECT id, name, provider, secrets, createdAt FROM dns_credentials WHERE userId = ? AND provider IN ('dnspod', 'tencent_ssl') ORDER BY provider ASC, createdAt ASC",
                    (uid,),
                ).fetchall()
            result = []
            for r in rows:
                secrets = self._credential_secrets(r)
                has_keys = bool(secrets.get("secretId") and secrets.get("secretKey"))
                if has_keys:
                    result.append({
                        "id": r["id"],
                        "name": r["name"],
                        "provider": r["provider"],
                        "createdAt": r["createdAt"],
                    })
            self._ok(result, "获取 SSL 可用凭证成功")
            return

        # POST /api/ssl/credentials — add SSL-specific credential
        if self.command == "POST" and sub in ("/credentials", "/credentials/"):
            name = str(body.get("name") or "").strip()
            secret_id = str(body.get("secretId") or "").strip()
            secret_key = str(body.get("secretKey") or "").strip()
            if not name:
                self._err("缺少凭证名称", 400)
                return
            if not secret_id or not secret_key:
                self._err("缺少 SecretId 或 SecretKey", 400)
                return
            secrets_json = json.dumps({"secretId": secret_id, "secretKey": secret_key}, ensure_ascii=False)
            encrypted = encrypt_text(secrets_json)
            with conn() as c:
                c.execute(
                    "INSERT INTO dns_credentials (userId, name, provider, secrets, isDefault, createdAt, updatedAt) VALUES (?, ?, 'tencent_ssl', ?, 0, ?, ?)",
                    (uid, name, encrypted, now_iso(), now_iso()),
                )
                c.commit()
                new_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
            self._ok({"id": new_id}, "SSL 凭证已创建", 201)
            return

        # PUT /api/ssl/credentials/<id> — update SSL credential
        m_cred = re.fullmatch(r"/credentials/(\d+)", sub)
        if self.command == "PUT" and m_cred:
            cred_id = int(m_cred.group(1))
            row = self._get_credential_row(uid, cred_id)
            if not row:
                self._err("凭证不存在或无权访问", 404)
                return
            if str(row["provider"] or "") != "tencent_ssl":
                self._err("只能编辑 SSL 专属凭证，DNS 共用凭证请在设置中管理", 403)
                return
            name = str(body.get("name") or "").strip()
            secret_id = str(body.get("secretId") or "").strip()
            secret_key = str(body.get("secretKey") or "").strip()
            updates = []
            params = []
            if name:
                updates.append("name = ?")
                params.append(name)
            if secret_id and secret_key:
                secrets_json = json.dumps({"secretId": secret_id, "secretKey": secret_key}, ensure_ascii=False)
                updates.append("secrets = ?")
                params.append(encrypt_text(secrets_json))
            if not updates:
                self._err("没有可更新的字段", 400)
                return
            updates.append("updatedAt = ?")
            params.append(now_iso())
            params.append(cred_id)
            with conn() as c:
                c.execute(f"UPDATE dns_credentials SET {', '.join(updates)} WHERE id = ?", params)
                c.commit()
            self._ok(None, "SSL 凭证已更新")
            return

        # DELETE /api/ssl/credentials/<id> — delete SSL credential
        if self.command == "DELETE" and m_cred:
            cred_id = int(m_cred.group(1))
            row = self._get_credential_row(uid, cred_id)
            if not row:
                self._err("凭证不存在或无权访问", 404)
                return
            if str(row["provider"] or "") != "tencent_ssl":
                self._err("只能删除 SSL 专属凭证，DNS 共用凭证请在设置中管理", 403)
                return
            with conn() as c:
                cert_rows = c.execute(
                    "SELECT * FROM ssl_certificates WHERE userId = ? AND credentialId = ?",
                    (uid, cred_id),
                ).fetchall()
            # Remove temp certs the panel uploaded into acceleration accounts
            # for these certs (also drops their binding rows). Best-effort so
            # a cloud hiccup never blocks credential deletion.
            for cert_row in cert_rows:
                try:
                    _cleanup_edgeone_cert_for_cert(self, uid, cert_row)
                except Exception:
                    pass
            with conn() as c:
                # Drop residual acceleration-cert bindings for every cert under
                # this credential before removing the certs themselves.
                c.execute(
                    """DELETE FROM acceleration_cert_bindings WHERE userId = ? AND certRemoteId IN (
                         SELECT remoteCertId FROM ssl_certificates WHERE userId = ? AND credentialId = ?
                       )""",
                    (uid, uid, cred_id),
                )
                c.execute("DELETE FROM ssl_certificates WHERE userId = ? AND credentialId = ?", (uid, cred_id))
                c.execute("DELETE FROM dns_credentials WHERE id = ? AND userId = ?", (cred_id, uid))
                c.commit()
            _invalidate(cred_id)
            self._ok(None, "SSL 凭证及关联证书已删除")
            return

        # GET /api/ssl/certificates — list
        if self.command == "GET" and sub in ("/certificates", "/certificates/"):
            cred_id_raw = _get_cred_id(first_or_none(q, "credentialId"))
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return

            page_num = max(1, int(first_or_none(q, "page") or "1"))
            limit = min(100, max(1, int(first_or_none(q, "limit") or "20")))
            search = first_or_none(q, "search") or ""
            filter_cred = first_or_none(q, "filterCredentialId") or ""
            status_filter = (first_or_none(q, "status") or "").strip().lower()
            source_filter = (first_or_none(q, "source") or "").strip().lower()
            if source_filter not in ("", "tencent", "letsencrypt"):
                self._err("无效的证书来源筛选", 400)
                return

            # ── Aggregated multi-credential view (parallel fetch + short cache) ──
            if cred_id_raw == "all":
                # Cache the full aggregated set (pre-pagination) so different pages
                # of the same query reuse a single round of upstream calls.
                agg_cache_k = ssl_certs_all_key(uid, search=search, filter_cred=filter_cred)
                agg_cached = cache_get(agg_cache_k)
                if agg_cached is not None:
                    all_certs = agg_cached.get("certs", [])
                    errors = agg_cached.get("errors", [])
                else:
                    with conn() as c:
                        cred_rows = c.execute(
                            "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ? AND provider IN ('dnspod', 'tencent_ssl')",
                            (uid,),
                        ).fetchall()

                    # Resolve target credentials and their decrypted secrets up front.
                    fetch_rows: list = []
                    for cr in cred_rows:
                        cr_secrets = self._credential_secrets(cr)
                        sid = str(cr_secrets.get("secretId") or "").strip()
                        skey = str(cr_secrets.get("secretKey") or "").strip()
                        if not sid or not skey:
                            continue
                        if filter_cred and str(cr["id"]) != filter_cred:
                            continue
                        fetch_rows.append((cr, sid, skey))

                    def _fetch_one(args):
                        cr, sid, skey = args
                        try:
                            cr_api = TencentSslApi(sid, skey)
                            certificates: list = []
                            offset = 0
                            while True:
                                r = cr_api.list_certificates(offset=offset, limit=100, search_key=search or None)
                                batch = r.get("certificates", [])
                                for cert in batch:
                                    cert["credentialId"] = cr["id"]
                                    cert["credentialName"] = cr["name"]
                                    cert["provider"] = "tencent_ssl"
                                    cert["source"] = "tencent"
                                    cert.update(_decorate_certificate(cert))
                                certificates.extend(batch)
                                total_count = int(r.get("totalCount") or len(certificates))
                                if len(batch) < 100 or len(certificates) >= total_count:
                                    break
                                offset += 100
                            return certificates, None
                        except Exception as ex:
                            return [], {"credentialId": cr["id"], "name": cr["name"], "error": str(ex)}

                    all_certs = []
                    errors = []
                    if fetch_rows:
                        workers = min(len(fetch_rows), 8)
                        with ThreadPoolExecutor(max_workers=workers) as pool:
                            for certs, err in pool.map(_fetch_one, fetch_rows):
                                if err is not None:
                                    errors.append(err)
                                all_certs.extend(certs)
                    agg_ttl = 10 if any(c.get("status") in ("applying", "validating") for c in all_certs) else 60
                    cache_set(agg_cache_k, {"certs": all_certs, "errors": errors}, agg_ttl)

                # Merge locally-stored acme certs (not backed by a cloud list API).
                try:
                    all_certs = list(all_certs) + _list_acme_certs(search=search, filter_cred=filter_cred)
                except Exception:
                    pass

                summarized = _ssl_filter_and_summarize(all_certs, status_filter, source_filter)
                all_certs = summarized["certs"]
                all_certs.sort(key=lambda x: x.get("remoteCreatedAt", ""), reverse=True)
                total = len(all_certs)
                offset = (page_num - 1) * limit
                paged = all_certs[offset:offset + limit]
                resp_body: Dict[str, Any] = {
                    "success": True,
                    "message": "获取证书列表成功（聚合·缓存）" if agg_cached is not None else "获取证书列表成功（聚合）",
                    "data": paged,
                    "statusSummary": summarized["statusSummary"],
                    "sourceSummary": summarized["sourceSummary"],
                    "credentialSummary": summarized.get("credentialSummary", []),
                    "pagination": {
                        "total": total,
                        "page": page_num,
                        "limit": limit,
                        "pages": int((total + limit - 1) // limit) if limit > 0 else 0,
                    },
                }
                if errors:
                    resp_body["errors"] = errors
                self._json(200, resp_body)
                return

            # ── Single credential view ──
            cred_row, api = _ssl_api(cred_id_raw)
            cred_id = int(cred_row["id"])
            offset = (page_num - 1) * limit

            cache_k = ssl_certs_key(cred_id, page=page_num, limit=limit, search=search)
            cached = cache_get(cache_k)
            if cached:
                certs_out = []
                for cert in cached.get("certificates", []):
                    c2 = dict(cert)
                    c2["credentialId"] = cred_row["id"]
                    c2["credentialName"] = cred_row["name"]
                    c2["provider"] = "tencent_ssl"
                    c2["source"] = "tencent"
                    certs_out.append(c2)
                self._paged(certs_out, cached["totalCount"], page_num, limit, "获取证书列表成功（缓存）")
                return

            result = api.list_certificates(offset=offset, limit=limit, search_key=search or None)
            _sync_to_db(cred_id, "tencent_ssl", result["certificates"])
            certs_out = []
            for cert in result.get("certificates", []):
                c2 = dict(cert)
                c2["credentialId"] = cred_row["id"]
                c2["credentialName"] = cred_row["name"]
                c2["provider"] = "tencent_ssl"
                c2["source"] = "tencent"
                c2 = _decorate_certificate(c2)
                certs_out.append(c2)
            result_ttl = 10 if any(c.get("status") in ("applying", "validating") for c in result.get("certificates", [])) else 120
            cache_set(cache_k, result, result_ttl)
            self._paged(certs_out, result["totalCount"], page_num, limit, "获取证书列表成功")
            return

        # GET /api/ssl/certificates/<id> — detail
        m = re.fullmatch(r"/certificates/([^/]+)", sub)
        if self.command == "GET" and m:
            cert_id = urllib.parse.unquote(m.group(1))
            cred_id_raw = _get_cred_id(first_or_none(q, "credentialId"))
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return

            # Let's Encrypt certificates are stored locally and their
            # credentialId points to a DNS credential, not a Tencent SSL API
            # credential. Return the local detail before entering _ssl_api().
            with conn() as c:
                acme_row = c.execute(
                    """SELECT s.*, d.name AS credentialName
                       FROM ssl_certificates s
                       LEFT JOIN dns_credentials d ON d.id = s.credentialId
                       WHERE s.userId = ? AND s.provider = 'acme'
                         AND s.remoteCertId = ?
                       LIMIT 1""",
                    (uid, cert_id),
                ).fetchone()
            if acme_row is not None:
                detail = _acme_row_to_cert(acme_row)
                detail["dvAuths"] = []
                detail["deployedResources"] = []
                self._ok(detail, "获取 Let's Encrypt 证书详情成功")
                return

            cred_row, api = _ssl_api(cred_id_raw)
            cred_id = int(cred_row["id"])

            cache_k = ssl_cert_detail_key(cred_id, cert_id)
            cached = cache_get(cache_k)
            if cached:
                self._ok(cached, "获取证书详情成功（缓存）")
                return

            detail = api.get_certificate(cert_id)
            cache_set(cache_k, detail, 60)
            self._ok(detail, "获取证书详情成功")
            return

        # POST /api/ssl/certificates/apply — apply free DV
        if self.command == "POST" and sub == "/certificates/apply":
            cred_id_raw = _get_cred_id()
            domain = str(body.get("domain") or "").strip()
            dv_auth = str(body.get("dvAuthMethod") or "DNS").strip()
            dns_credential_id = body.get("dnsCredentialId")
            old_certificate_id = str(body.get("oldCertificateId") or "").strip() or None
            auto_dns = bool(body.get("autoDnsRecord", True))
            auto_match_dns = bool(body.get("autoMatchDns", False))
            # Belt-and-suspenders: if auto_dns is on but no specific cred, always auto-match
            if auto_dns and not dns_credential_id:
                auto_match_dns = True
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            if not domain:
                self._err("缺少 domain 参数", 400)
                return
            if dv_auth not in ("DNS_AUTO", "DNS", "FILE"):
                self._err(f"不支持的验证方式: {dv_auth}", 400)
                return
            cred_row, api = _ssl_api(cred_id_raw)
            result = api.apply_certificate(domain, dv_auth, old_certificate_id=old_certificate_id)
            cert_id = result.get("CertificateId", "")

            dns_records_added: list = []
            dns_errors: list = []

            if auto_dns and cert_id and dv_auth == "DNS":
                import time as _time
                # Build list of DNS APIs to try
                apply_dns_apis: list = []  # (api_obj, provider_name, zones)

                if dns_credential_id:
                    # Use the specific DNS credential
                    dns_cred_row = self._get_credential_row(uid, dns_credential_id)
                    if dns_cred_row:
                        dns_secrets = self._credential_secrets(dns_cred_row)
                        dns_provider = str(dns_cred_row["provider"] or "").strip().lower()
                        dns_api_obj = None
                        if dns_provider == "cloudflare":
                            token = str(dns_secrets.get("apiToken") or "").strip()
                            if token:
                                dns_api_obj = CloudflareApi(token)
                        elif dns_provider in ("dnspod", "dnspod_token"):
                            dns_api_obj = DnspodApi(dns_secrets)

                        if dns_api_obj:
                            try:
                                zones_result = dns_api_obj.list_zones(1, 200)
                                apply_dns_apis.append((dns_api_obj, dns_provider, zones_result.get("zones", [])))
                            except Exception as e:
                                dns_errors.append({"error": f"DNS 凭证获取域名列表失败: {e}"})
                                # fallback to auto-match when list-zones fails
                                auto_match_dns = True
                        else:
                            dns_errors.append({"error": "所选 DNS 凭证不支持自动添加验证记录（仅 Cloudflare / DNSPod 支持）"})
                            # fallback to auto-match if a wrong credential was selected
                            auto_match_dns = True
                    else:
                        dns_errors.append({"error": "所选 DNS 凭证不存在或无权访问"})
                        auto_match_dns = True

                if auto_match_dns and not apply_dns_apis:
                    # Auto-match: try all DNS credentials the user has
                    with conn() as c:
                        all_dns_rows = c.execute(
                            "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ?",
                            (uid,),
                        ).fetchall()
                    for dcr in all_dns_rows:
                        dp = str(dcr["provider"] or "").strip().lower()
                        try:
                            ds = self._credential_secrets(dcr)
                            d_api = None
                            if dp == "cloudflare":
                                tk = str(ds.get("apiToken") or "").strip()
                                if tk:
                                    d_api = CloudflareApi(tk)
                            elif dp in ("dnspod", "dnspod_token"):
                                d_api = DnspodApi(ds)
                            if d_api:
                                dzones = d_api.list_zones(1, 200).get("zones", [])
                                apply_dns_apis.append((d_api, dp, dzones))
                        except Exception:
                            pass

                def _find_zone(check_domain: str):
                    ck = check_domain.lower()
                    for (a, p, zs) in apply_dns_apis:
                        for z in zs:
                            zn = str(z.get("name") or "").lower()
                            if ck == zn or ck.endswith("." + zn):
                                return a, p, z
                    return None, None, None

                # Poll DV auth info (it may not be immediately available right after ApplyCertificate)
                dv_auths: list = []
                for attempt in range(15):
                    try:
                        detail = api.get_certificate(cert_id)
                        dv_auths = detail.get("dvAuths") or []
                    except Exception:
                        dv_auths = []
                    if dv_auths:
                        break
                    _time.sleep(1.0 + attempt * 0.3)

                if not dv_auths:
                    dns_errors.append({"error": "未获取到域名验证信息，可能还在生成中；请稍后在证书详情中查看并手动添加"})
                elif not apply_dns_apis:
                    dns_errors.append({"error": "未找到可用的 DNS 凭证，无法自动添加验证记录（请在设置中添加 Cloudflare / DNSPod 凭证）"})
                else:
                    all_dv_added = True
                    for dv in dv_auths:
                        dv_domain = str(dv.get("domain") or "").strip()
                        dv_key = str(dv.get("key") or "").strip().rstrip(".")
                        dv_value = str(dv.get("value") or "").strip()
                        dv_type_raw = str(dv.get("type") or "").strip().upper()
                        if not dv_key or not dv_value:
                            continue

                        rec_type = "CNAME" if "CNAME" in dv_type_raw else "TXT"
                        dv_api, dv_prov, target_zone = _find_zone(dv_domain or domain)

                        if not target_zone:
                            dns_errors.append({"key": dv_key, "error": f"未找到域名 {dv_domain or domain} 对应的 DNS 区域"})
                            all_dv_added = False
                            continue

                        zone_id = str(target_zone.get("id") or "")
                        try:
                            rec_name = dv_key
                            rec_value = dv_value
                            if dv_prov == "cloudflare":
                                if rec_type == "TXT":
                                    rec_value = self._normalize_txt_for_cf("TXT", rec_value)
                                dv_api.create_record(zone_id, {
                                    "type": rec_type,
                                    "name": rec_name,
                                    "content": rec_value,
                                    "ttl": 600,
                                })
                            else:
                                dv_api.create_record(zone_id, {
                                    "type": rec_type,
                                    "name": rec_name,
                                    "value": rec_value,
                                    "ttl": 600,
                                })
                            dns_records_added.append({
                                "zone": target_zone.get("name"),
                                "type": rec_type,
                                "name": rec_name,
                                "value": dv_value,
                            })
                        except Exception as dns_ex:
                            dns_errors.append({"key": dv_key, "error": str(dns_ex)})
                            all_dv_added = False

                    # Auto-submit domain validation if all DNS records added
                    if dns_records_added and all_dv_added:
                        _time.sleep(3)
                        try:
                            api.complete_certificate(cert_id)
                        except Exception:
                            pass

            _invalidate(int(cred_row["id"]))
            resp_data: Dict[str, Any] = {**result}
            if dns_records_added:
                resp_data["dnsRecordsAdded"] = dns_records_added
            if dns_errors:
                resp_data["dnsErrors"] = dns_errors
            msg = "免费证书申请已提交"
            if dns_records_added:
                msg += f"，已自动添加 {len(dns_records_added)} 条 DNS 验证记录"
            self._ok(resp_data, msg, 201)
            return

        # POST /api/ssl/certificates/issue-acme — issue a Let's Encrypt cert via
        # acme.sh (DNS-01). Long-running (waits for DNS propagation), so we insert
        # an 'applying' row, return immediately, and finish in a background thread.
        if self.command == "POST" and sub == "/certificates/issue-acme":
            if not _require_api_scope("ssl:issue"):
                return
            if not acme_api.acme_available():
                self._err("acme.sh 未安装，签发功能仅在 Docker 部署环境可用", 503)
                return
            domain = acme_api.validate_domain(str(body.get("domain") or ""))
            dns_cred_id_raw = _get_cred_id(body.get("dnsCredentialId"))
            key_length = str(body.get("keyLength") or "2048").strip() or "2048"
            ca_key = str(body.get("ca") or "").strip().lower()
            if ca_key and ca_key not in acme_api.ACME_SUPPORTED_CAS and not ca_key.startswith("https://"):
                self._err(f"不支持的 CA: {ca_key}", 400)
                return
            eab_kid = str(body.get("eabKid") or "").strip()
            eab_hmac = str(body.get("eabHmac") or "").strip()
            if bool(eab_kid) != bool(eab_hmac):
                self._err("EAB 凭据需同时提供 eabKid 和 eabHmac", 400)
                return
            ca_label = acme_api.ACME_SUPPORTED_CAS.get(ca_key, {}).get("label") if ca_key else ""
            extra = body.get("altNames") if isinstance(body.get("altNames"), list) else []
            if not domain:
                self._err("缺少 domain 参数", 400)
                return
            try:
                dns_row, _dns_provider, _dns_secrets, _account_id = _acme_dns_context(dns_cred_id_raw)
            except ValueError as ve:
                self._err(str(ve), 400)
                return
            dns_cred_id = int(dns_row["id"])
            if len(extra) > 99:
                self._err("单张证书最多支持 100 个域名", 400)
                return
            domains = [domain] + [acme_api.validate_domain(str(d)) for d in extra]
            # De-dup while preserving order (primary first).
            seen: set = set()
            domains = [d for d in domains if not (d in seen or seen.add(d))]
            try:
                _validate_acme_managed_domains(_dns_provider, _dns_secrets, domains)
            except ValueError as ve:
                self._err(str(ve), 400)
                return
            san_json = json.dumps(domains, ensure_ascii=False)
            ts = now_iso()

            # Upsert an 'applying' placeholder row (remoteCertId = primary domain).
            with conn() as c:
                existing = c.execute(
                    "SELECT id FROM ssl_certificates WHERE userId = ? AND provider = 'acme' AND remoteCertId = ?",
                    (uid, domain),
                ).fetchone()
                if existing:
                    c.execute(
                        """UPDATE ssl_certificates SET credentialId = ?, domain = ?, san = ?,
                             status = 'applying', statusMsg = '正在通过 acme.sh 签发', renewError = '',
                             certType = ?, productName = ?, issuer = ?, acmeCa = ?,
                             autoRenew = 1, updatedAt = ? WHERE id = ?""",
                        (dns_cred_id, domain, san_json, key_length,
                         ca_label or "Let's Encrypt", ca_label or "Let's Encrypt", ca_key, ts, existing["id"]),
                    )
                    cert_row_id = existing["id"]
                else:
                    c.execute(
                        """INSERT INTO ssl_certificates
                             (userId, credentialId, provider, remoteCertId, domain, san, certType,
                              productName, status, statusMsg, issuer, dvAuthMethod, isUploaded,
                              autoRenew, acmeCa, syncedAt, createdAt, updatedAt)
                           VALUES (?, ?, 'acme', ?, ?, ?, ?, ?, 'applying',
                              '正在通过 acme.sh 签发', ?, 'DNS', 0, 1, ?, ?, ?, ?)""",
                        (uid, dns_cred_id, domain, domain, san_json, key_length,
                         ca_label or "Let's Encrypt", ca_label or "Let's Encrypt", ca_key, ts, ts, ts),
                    )
                    cert_row_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
                c.commit()

            with conn() as c:
                active_job = c.execute(
                    """SELECT id FROM ssl_acme_jobs
                       WHERE userId = ? AND certificateId = ? AND status IN ('queued', 'running')
                       ORDER BY id DESC LIMIT 1""",
                    (uid, cert_row_id),
                ).fetchone()
                if active_job is None:
                    c.execute(
                        """INSERT INTO ssl_acme_jobs
                           (userId, certificateId, dnsCredentialId, domain, domains, keyLength,
                            ca, eabKid, eabHmac, operation, status, attempts, createdAt, updatedAt)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'issue', 'queued', 0, ?, ?)""",
                        (uid, cert_row_id, dns_cred_id, domain, san_json, key_length,
                         ca_key, eab_kid, eab_hmac, ts, ts),
                    )
                    job_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
                else:
                    job_id = active_job["id"]
                c.commit()
            self._ok(
                {"id": cert_row_id, "jobId": job_id, "domain": domain, "status": "applying", "provider": "acme", "ca": ca_key or "letsencrypt"},
                "已加入 " + (ca_label or "Let's Encrypt") + " 持久化签发队列，服务重启后会自动继续处理",
                201,
            )
            return

        # POST /api/ssl/certificates/<id>/auto-renew — per-certificate renewal
        # toggle. ACME certs flip a local flag; Tencent-issued certs call the
        # cloud's own SetAutoRenewFlag so the cloud console and panel agree.
        m_auto_renew = re.fullmatch(r"/certificates/([^/]+)/auto-renew", sub)
        if self.command == "POST" and m_auto_renew:
            cert_id = urllib.parse.unquote(m_auto_renew.group(1))
            enabled = bool(body.get("enabled"))
            with conn() as c:
                row = c.execute(
                    """SELECT id, provider, credentialId, isUploaded FROM ssl_certificates
                       WHERE userId = ? AND remoteCertId = ? LIMIT 1""",
                    (uid, cert_id),
                ).fetchone()
            if row is None:
                self._err("证书不存在", 404)
                return
            if str(row["provider"] or "") == "acme":
                with conn() as c:
                    c.execute(
                        "UPDATE ssl_certificates SET autoRenew = ?, updatedAt = ? WHERE id = ?",
                        (1 if enabled else 0, now_iso(), row["id"]),
                    )
                    c.commit()
                cache_delete_pattern(f"ssl:certs:all:user:{uid}:*")
                self._ok({"enabled": enabled}, "该证书自动续期已" + ("开启" if enabled else "关闭"))
                return
            # Tencent certificate → cloud-side auto-renew flag.
            if row["isUploaded"]:
                self._err("上传证书不支持开启腾讯云自动续费", 400)
                return
            cred_row, api = _ssl_api(str(row["credentialId"]))
            try:
                api.set_auto_renew_flag(cert_id, enabled)
            except TencentSslApiError as ex:
                # Free DV certs may reject the flag; surface the cloud reason
                # instead of pretending the toggle worked.
                self._err(f"腾讯云自动续费设置失败：{ex}", int(getattr(ex, "status", 400) or 400))
                return
            with conn() as c:
                c.execute(
                    "UPDATE ssl_certificates SET autoRenew = ?, updatedAt = ? WHERE id = ?",
                    (1 if enabled else 0, now_iso(), row["id"]),
                )
                c.commit()
            _invalidate(int(cred_row["id"]))
            self._ok({"enabled": enabled}, "腾讯云自动续费已" + ("开启" if enabled else "关闭"))
            return

        # POST /api/ssl/certificates/<id>/complete — complete DV validation
        m = re.fullmatch(r"/certificates/([^/]+)/complete", sub)
        if self.command == "POST" and m:
            cert_id = urllib.parse.unquote(m.group(1))
            cred_id_raw = _get_cred_id()
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            cred_row, api = _ssl_api(cred_id_raw)
            result = api.complete_certificate(cert_id)
            _invalidate(int(cred_row["id"]))
            self._ok(result, "域名验证已提交")
            return

        # POST /api/ssl/certificates/<id>/auto-dns — auto-add DNS records for existing cert
        m = re.fullmatch(r"/certificates/([^/]+)/auto-dns", sub)
        if self.command == "POST" and m:
            import time as _time
            cert_id = urllib.parse.unquote(m.group(1))
            cred_id_raw = _get_cred_id()
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            cred_row, api = _ssl_api(cred_id_raw)

            # Fetch cert detail to get dvAuths
            detail = api.get_certificate(cert_id)
            dv_auths = detail.get("dvAuths") or []
            cert_domain = detail.get("domain") or ""

            if not dv_auths:
                self._err("未获取到域名验证信息，证书可能已签发或还在生成中", 400)
                return

            # Collect all DNS credentials for zone matching
            auto_dns_apis: list = []
            with conn() as c:
                all_dns_rows = c.execute(
                    "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ?",
                    (uid,),
                ).fetchall()
            for dcr in all_dns_rows:
                dp = str(dcr["provider"] or "").strip().lower()
                try:
                    ds = self._credential_secrets(dcr)
                    d_api = None
                    if dp == "cloudflare":
                        tk = str(ds.get("apiToken") or "").strip()
                        if tk:
                            d_api = CloudflareApi(tk)
                    elif dp in ("dnspod", "dnspod_token"):
                        d_api = DnspodApi(ds)
                    if d_api:
                        dzones = d_api.list_zones(1, 200).get("zones", [])
                        auto_dns_apis.append((d_api, dp, dzones))
                except Exception:
                    pass

            def _find_zone_auto(check_domain: str):
                ck = check_domain.lower()
                for (a, p, zs) in auto_dns_apis:
                    for z in zs:
                        zn = str(z.get("name") or "").lower()
                        if ck == zn or ck.endswith("." + zn):
                            return a, p, z
                return None, None, None

            dns_records_added: list = []
            dns_errors: list = []
            all_dv_added = True

            for dv in dv_auths:
                dv_domain = str(dv.get("domain") or "").strip()
                dv_key = str(dv.get("key") or "").strip().rstrip(".")
                dv_value = str(dv.get("value") or "").strip()
                dv_type_raw = str(dv.get("type") or "").strip().upper()
                if not dv_key or not dv_value:
                    continue

                rec_type = "CNAME" if "CNAME" in dv_type_raw else "TXT"
                dv_api, dv_prov, target_zone = _find_zone_auto(dv_domain or cert_domain)

                if not target_zone:
                    dns_errors.append({"key": dv_key, "error": f"未找到域名 {dv_domain or cert_domain} 对应的 DNS 区域"})
                    all_dv_added = False
                    continue

                zone_id = str(target_zone.get("id") or "")
                try:
                    rec_value = dv_value
                    if dv_prov == "cloudflare":
                        if rec_type == "TXT":
                            rec_value = self._normalize_txt_for_cf("TXT", rec_value)
                        dv_api.create_record(zone_id, {
                            "type": rec_type, "name": dv_key, "content": rec_value, "ttl": 600,
                        })
                    else:
                        dv_api.create_record(zone_id, {
                            "type": rec_type, "name": dv_key, "value": rec_value, "ttl": 600,
                        })
                    dns_records_added.append({
                        "zone": target_zone.get("name"),
                        "type": rec_type, "name": dv_key, "value": dv_value,
                    })
                except Exception as dns_ex:
                    dns_errors.append({"key": dv_key, "error": str(dns_ex)})
                    all_dv_added = False

            # Auto-complete if all DNS records added
            completed = False
            if dns_records_added and all_dv_added:
                _time.sleep(3)
                try:
                    api.complete_certificate(cert_id)
                    completed = True
                except Exception:
                    pass

            _invalidate(int(cred_row["id"]))
            resp_data: Dict[str, Any] = {
                "dnsRecordsAdded": dns_records_added,
                "dnsErrors": dns_errors,
                "completed": completed,
            }
            msg = f"已添加 {len(dns_records_added)} 条 DNS 验证记录"
            if dns_errors:
                msg += f"，{len(dns_errors)} 条失败"
            if completed:
                msg += "，已自动提交验证"
            self._ok(resp_data, msg)
            return

        # POST /api/ssl/certificates/<id>/cleanup-dns — delete DV auth DNS records after issuance
        m = re.fullmatch(r"/certificates/([^/]+)/cleanup-dns", sub)
        if self.command == "POST" and m:
            cert_id = urllib.parse.unquote(m.group(1))
            cred_id_raw = _get_cred_id()
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            cred_row, api = _ssl_api(cred_id_raw)

            detail = api.get_certificate(cert_id)
            dv_auths = detail.get("dvAuths") or []
            cert_domain = detail.get("domain") or ""

            if not dv_auths:
                self._err("未找到域名验证记录信息", 400)
                return

            # Collect all DNS credentials
            cleanup_dns_apis: list = []
            with conn() as c:
                all_dns_rows = c.execute(
                    "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ?",
                    (uid,),
                ).fetchall()
            for dcr in all_dns_rows:
                dp = str(dcr["provider"] or "").strip().lower()
                try:
                    ds = self._credential_secrets(dcr)
                    d_api = None
                    if dp == "cloudflare":
                        tk = str(ds.get("apiToken") or "").strip()
                        if tk:
                            d_api = CloudflareApi(tk)
                    elif dp in ("dnspod", "dnspod_token"):
                        d_api = DnspodApi(ds)
                    if d_api:
                        dzones = d_api.list_zones(1, 200).get("zones", [])
                        cleanup_dns_apis.append((d_api, dp, dzones))
                except Exception:
                    pass

            def _find_zone_cleanup(check_domain: str):
                ck = check_domain.lower()
                for (a, p, zs) in cleanup_dns_apis:
                    for z in zs:
                        zn = str(z.get("name") or "").lower()
                        if ck == zn or ck.endswith("." + zn):
                            return a, p, z
                return None, None, None

            deleted_records: list = []
            cleanup_errors: list = []

            for dv in dv_auths:
                dv_domain = str(dv.get("domain") or "").strip()
                dv_key = str(dv.get("key") or "").strip().rstrip(".")
                dv_type_raw = str(dv.get("type") or "").strip().upper()
                if not dv_key:
                    continue

                rec_type = "CNAME" if "CNAME" in dv_type_raw else "TXT"
                dv_api, dv_prov, target_zone = _find_zone_cleanup(dv_domain or cert_domain)

                if not target_zone:
                    cleanup_errors.append({"key": dv_key, "error": f"未找到 {dv_domain or cert_domain} 对应的 DNS 区域"})
                    continue

                zone_id = str(target_zone.get("id") or "")
                zone_name = str(target_zone.get("name") or "")
                try:
                    if dv_prov == "cloudflare":
                        # Cloudflare: list records matching name + type, then delete
                        recs = dv_api.list_records(zone_id, filters={"name": dv_key, "type": rec_type})
                        for rec in (recs.get("records") or []):
                            rec_id = str(rec.get("id") or "")
                            if rec_id:
                                dv_api.delete_record(zone_id, rec_id)
                                deleted_records.append({"zone": zone_name, "type": rec_type, "name": dv_key})
                    else:
                        # DNSPod: list records by subDomain + type, then delete
                        recs = dv_api.list_records(zone_id, filters={"subDomain": dv_key, "type": rec_type})
                        for rec in (recs.get("records") or []):
                            rec_name = str(rec.get("name") or "")
                            # Match by name (relative record name)
                            if rec_name and (dv_key.endswith("." + zone_name) or dv_key == rec_name or rec_name == dv_key.replace("." + zone_name, "")):
                                rec_id = str(rec.get("id") or "")
                                if rec_id:
                                    dv_api.delete_record(zone_id, rec_id)
                                    deleted_records.append({"zone": zone_name, "type": rec_type, "name": dv_key})
                except Exception as e:
                    cleanup_errors.append({"key": dv_key, "error": str(e)})

            msg = f"已清理 {len(deleted_records)} 条 DNS 验证记录"
            if cleanup_errors:
                msg += f"，{len(cleanup_errors)} 条失败"
            self._ok({"deleted": deleted_records, "errors": cleanup_errors}, msg)
            return

        # GET /api/ssl/certificates/<id>/download — download zip
        m = re.fullmatch(r"/certificates/([^/]+)/download", sub)
        if self.command == "GET" and m:
            cert_id = urllib.parse.unquote(m.group(1))
            # acme certs: their "remoteCertId" is the primary domain and the
            # PEM lives in panel-managed files, not on a cloud API. Previously
            # this fell through to the Tencent API which answered "证书不存在"
            # for a perfectly valid Let's Encrypt certificate.
            with conn() as c:
                acme_row = c.execute(
                    "SELECT domain, certType FROM ssl_certificates WHERE userId = ? AND provider = 'acme' AND remoteCertId = ? LIMIT 1",
                    (uid, cert_id),
                ).fetchone()
            if acme_row is not None:
                try:
                    pem = acme_api.AcmeService(key_length=str(acme_row["certType"] or "2048")).read_pem(acme_row["domain"] or cert_id)
                except acme_api.AcmeApiError as ae:
                    self._err(str(ae), getattr(ae, "status", 502))
                    return
                import zipfile as _zf
                import io as _io
                buf = _io.BytesIO()
                with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as zf:
                    zf.writestr("fullchain.pem", pem["publicKey"])
                    zf.writestr("privkey.pem", pem["privateKey"])
                safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(acme_row["domain"] or cert_id)).strip("._") or "acme-cert"
                try:
                    create_log(user_id=uid, action="READ_PRIVATE_KEY", resource_type="SSL_CERTIFICATE", status="SUCCESS", record_name=cert_id, ip_address=self._client_ip())
                except Exception:
                    pass
                self._binary(buf.getvalue(), f"{safe_name}.zip", "application/zip")
                return
            cred_id_raw = _get_cred_id(first_or_none(q, "credentialId"))
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            cred_row, api = _ssl_api(cred_id_raw)
            result = api.download_certificate(cert_id)
            content_b64 = result.get("Content", "")
            if not content_b64:
                self._err("证书内容为空", 404)
                return
            import base64
            raw_bytes = base64.b64decode(content_b64)
            self._binary(raw_bytes, f"{cert_id}.zip", "application/zip")
            return

        # GET /api/ssl/certificates/<id>/view — public certificate content for
        # online viewing (no download). Returns the public PEM plus parsed
        # metadata (subject/issuer/SAN/validity/serial/fingerprint). Works for
        # both channels: acme certs read local files; Tencent certs decode the
        # download zip in memory. The private key is never included.
        m = re.fullmatch(r"/certificates/([^/]+)/view", sub)
        if self.command == "GET" and m:
            cert_id = urllib.parse.unquote(m.group(1))
            with conn() as c:
                acme_row = c.execute(
                    "SELECT domain, certType FROM ssl_certificates WHERE userId = ? AND provider = 'acme' AND remoteCertId = ? LIMIT 1",
                    (uid, cert_id),
                ).fetchone()
            public_pem = ""
            if acme_row is not None:
                try:
                    pem = acme_api.AcmeService(key_length=str(acme_row["certType"] or "2048")).read_pem(acme_row["domain"] or cert_id)
                except acme_api.AcmeApiError as ae:
                    self._err(str(ae), getattr(ae, "status", 502))
                    return
                public_pem = pem["publicKey"]
            else:
                cred_id_raw = _get_cred_id(first_or_none(q, "credentialId"))
                if not cred_id_raw:
                    self._err("缺少 credentialId 参数", 400)
                    return
                cred_row, api = _ssl_api(cred_id_raw)
                result = api.download_certificate(cert_id)
                content_b64 = result.get("Content", "")
                if not content_b64:
                    self._err("证书内容为空", 404)
                    return
                import base64 as _b64
                import zipfile as _zf
                import io as _io
                raw_bytes = _b64.b64decode(content_b64)
                try:
                    with _zf.ZipFile(_io.BytesIO(raw_bytes)) as z:
                        files = {}
                        for name in z.namelist():
                            if name.endswith("/"):
                                continue
                            files[name] = z.read(name).decode("utf-8", errors="replace")
                        root_pem = [n for n in files if "/" not in n and n.lower().endswith(".pem")]
                        bundle = [n for n in files if n.lower().endswith((".crt", ".pem")) and "bundle" in n.lower()]
                        any_cert = [n for n in files if n.lower().endswith((".crt", ".pem")) and not n.lower().endswith(".csr")]
                        if root_pem:
                            public_pem = files[root_pem[0]]
                        elif bundle:
                            public_pem = files[max(bundle, key=lambda n: len(files[n]))]
                        elif any_cert:
                            public_pem = files[max(any_cert, key=lambda n: len(files[n]))]
                except Exception:
                    public_pem = raw_bytes.decode("utf-8", errors="replace")
            if not public_pem or "-----BEGIN CERTIFICATE-----" not in public_pem:
                self._err("无法读取证书内容", 502)
                return
            try:
                meta = acme_api.parse_cert_pem(public_pem)
            except acme_api.AcmeApiError:
                meta = {}
            self._ok({"certId": cert_id, "publicKey": public_pem, "meta": meta}, "获取证书内容成功")
            return

        # GET /api/ssl/certificates/<id>/pem — return PEM text (for BaoTa plugin)
        m = re.fullmatch(r"/certificates/([^/]+)/pem", sub)
        if self.command == "GET" and m:
            if not _require_api_scope("ssl:pem"):
                return
            if not self._check_sensitive_rate_limit(f"ssl-pem:{uid}:{self._client_ip() or 'unknown'}"):
                return
            cert_id = urllib.parse.unquote(m.group(1))
            cred_id_raw = _get_cred_id(first_or_none(q, "credentialId"))
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            # acme certs: identified by a DB row (remoteCertId = primary domain).
            # Their PEM lives on disk, not on a cloud API, and their credentialId
            # is a DNS credential — so short-circuit before the tencent path.
            with conn() as c:
                acme_row = c.execute(
                    "SELECT domain, certType FROM ssl_certificates WHERE userId = ? AND provider = 'acme' AND remoteCertId = ? LIMIT 1",
                    (uid, cert_id),
                ).fetchone()
            if acme_row is not None:
                try:
                    pem = acme_api.AcmeService(key_length=str(acme_row["certType"] or "2048")).read_pem(acme_row["domain"] or cert_id)
                except acme_api.AcmeApiError as ae:
                    self._err(str(ae), getattr(ae, "status", 502))
                    return
                try:
                    create_log(user_id=uid, action="READ_PRIVATE_KEY", resource_type="SSL_CERTIFICATE", status="SUCCESS", record_name=cert_id, ip_address=self._client_ip())
                except Exception:
                    pass
                self._sensitive_ok({"publicKey": pem["publicKey"], "privateKey": pem["privateKey"], "certId": cert_id}, "获取证书 PEM 成功")
                return
            cred_row, api = _ssl_api(cred_id_raw)
            result = api.download_certificate(cert_id)
            content_b64 = result.get("Content", "")
            if not content_b64:
                self._err("证书内容为空", 404)
                return
            import base64 as _b64
            import zipfile as _zf
            import io as _io
            raw_bytes = _b64.b64decode(content_b64)
            public_pem = ""
            private_pem = ""
            try:
                with _zf.ZipFile(_io.BytesIO(raw_bytes)) as z:
                    files = {}
                    for name in z.namelist():
                        if name.endswith("/"):
                            continue
                        files[name] = z.read(name).decode("utf-8", errors="replace")

                    def _is_root(n: str) -> bool:
                        return "/" not in n

                    # Private key: a real *.key file. Exclude keystorePass.txt etc.
                    # (their names contain "key" but are not PEM keys). Prefer the
                    # root-level key, then the shortest path.
                    key_files = [n for n in files if n.lower().endswith(".key")]
                    key_files.sort(key=lambda n: (not _is_root(n), len(n)))
                    if key_files:
                        private_pem = files[key_files[0]]

                    # Public cert: prefer the full chain. Tencent puts the fullchain
                    # at the root *.pem; otherwise a *bundle* file; otherwise the
                    # largest .crt/.pem (fullchain is bigger than a bare leaf cert).
                    root_pem = [n for n in files if _is_root(n) and n.lower().endswith(".pem")]
                    bundle = [n for n in files if n.lower().endswith((".crt", ".pem")) and "bundle" in n.lower()]
                    any_cert = [
                        n for n in files
                        if n.lower().endswith((".crt", ".pem")) and not n.lower().endswith(".csr")
                    ]
                    if root_pem:
                        public_pem = files[root_pem[0]]
                    elif bundle:
                        public_pem = files[max(bundle, key=lambda n: len(files[n]))]
                    elif any_cert:
                        public_pem = files[max(any_cert, key=lambda n: len(files[n]))]
            except Exception:
                # Not a zip — treat as raw PEM
                public_pem = raw_bytes.decode("utf-8", errors="replace")
            if not private_pem or not public_pem:
                self._err("证书包中缺少有效的公钥或私钥文件", 502)
                return
            try:
                create_log(user_id=uid, action="READ_PRIVATE_KEY", resource_type="SSL_CERTIFICATE", status="SUCCESS", record_name=cert_id, ip_address=self._client_ip())
            except Exception:
                pass
            self._sensitive_ok({"publicKey": public_pem, "privateKey": private_pem, "certId": cert_id}, "获取证书 PEM 成功")
            return

        # POST /api/ssl/certificates/upload — upload third-party cert
        #
        # Guarded: the SAME certificate is never stored twice (重复只保留一个),
        # and a replacement for a name set that already has a usable certificate
        # is only accepted inside the last REPLACE_UPLOAD_WINDOW_DAYS days of
        # that certificate's life (or once it has expired), and only when the
        # uploaded PEM is a genuinely NEW issuance (newer NotBefore).
        if self.command == "POST" and sub == "/certificates/upload":
            cred_id_raw = _get_cred_id()
            pub_key = str(body.get("publicKey") or "").strip()
            priv_key = str(body.get("privateKey") or "").strip()
            alias = str(body.get("alias") or "").strip() or None
            force = bool(body.get("force"))
            # When API tokens are used, a write may omit credentialId and let
            # the panel pick the only available SSL account. The UI already
            # resolves the visible account; this fallback keeps direct API and
            # older clients working instead of failing with a false "missing
            # credential" error before the upload is even attempted.
            if not cred_id_raw:
                with conn() as c:
                    candidates = c.execute(
                        """SELECT id FROM dns_credentials
                           WHERE userId = ? AND provider IN ('tencent_ssl', 'dnspod')
                           ORDER BY isDefault DESC, createdAt ASC""",
                        (uid,),
                    ).fetchall()
                if len(candidates) == 1:
                    cred_id_raw = str(candidates[0]["id"])
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            if not pub_key or not priv_key:
                self._err("缺少证书公钥或私钥", 400)
                return
            try:
                parsed_status = acme_api.parse_cert_pem(pub_key)
            except Exception as ex:
                self._err(f"无法解析证书内容：{ex}", 400)
                return
            incoming_names = [
                _norm_host(x) for x in ((parsed_status.get("san") or []) + [parsed_status.get("subjectCN") or ""])
                if _norm_host(x)
            ]
            seen_names: set = set()
            incoming_names = [n for n in incoming_names if not (n in seen_names or seen_names.add(n))]
            verdict = _needs_replacement_upload(uid, {
                "names": incoming_names,
                "notBefore": parsed_status.get("notBefore"),
                "notAfter": parsed_status.get("notAfter"),
            })
            if not verdict.get("allowed") and not force:
                self._err(verdict.get("reason") or "该证书不允许上传", 409)
                return
            cred_row, api = _ssl_api(cred_id_raw)
            result = api.upload_certificate(pub_key, priv_key, alias)
            _invalidate(int(cred_row["id"]))
            # The upload replaced the previous certificate for these names: drop
            # the superseded copies so the panel keeps exactly one usable cert.
            cleanup: Dict[str, Any] = {"removed": [], "errors": []}
            cert_id = str(result.get("CertificateId") or result.get("CertId") or "").strip()
            if cert_id:
                try:
                    _sync_uploaded_cert_row(uid, cred_row, result, parsed_status, alias)
                except Exception:
                    pass
                try:
                    with conn() as c:
                        new_row = c.execute(
                            """SELECT * FROM ssl_certificates
                               WHERE userId = ? AND credentialId = ? AND remoteCertId = ? LIMIT 1""",
                            (uid, int(cred_row["id"]), cert_id),
                        ).fetchone()
                    if new_row is not None:
                        cleanup = _prune_superseded_rows(uid, new_row, delete_cloud=True)
                        # 手动上传替换的新证书同步到已部署过的第三方平台。
                        try:
                            _sync_cert_to_platforms(self, uid, new_row)
                        except Exception:
                            pass
                except Exception:
                    cleanup = {"removed": [], "errors": []}
            # A recovery upload also retires cloud-side dead certs for the names
            # it just covered, so the account does not accumulate stale copies.
            message = "证书上传成功"
            if verdict.get("mode") == "renewal":
                message += "（续期证书已替换原证书）"
            removed_n = len(cleanup.get("removed") or [])
            if removed_n:
                message += f"，已清理重复证书 {removed_n} 张"
            self._ok({**result, "uploadCheck": verdict, "cleanup": cleanup}, message, 201)
            return

        # DELETE /api/ssl/certificates/<id> — delete
        m = re.fullmatch(r"/certificates/([^/]+)", sub)
        if self.command == "DELETE" and m:
            cert_id = urllib.parse.unquote(m.group(1))
            cred_id_raw = _get_cred_id(first_or_none(q, "credentialId"))
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return

            # acme certs live only in our DB; their credentialId is a DNS
            # credential, so _ssl_api can't handle them. Match by remoteCertId
            # and remove via acme.sh (--remove + delete local files) + DB row.
            with conn() as c:
                acme_row = c.execute(
                    "SELECT id, credentialId, certType, remoteCertId, provider FROM ssl_certificates WHERE userId = ? AND provider = 'acme' AND remoteCertId = ? LIMIT 1",
                    (uid, cert_id),
                ).fetchone()
            if acme_row is not None:
                # Clean up any temp cert the panel uploaded to acceleration
                # accounts for this acme cert before dropping the row.
                edgeone_cleanup = {"removedEdgeCerts": [], "errors": []}
                try:
                    edgeone_cleanup = _cleanup_edgeone_cert_for_cert(self, uid, acme_row)
                except Exception:
                    pass
                try:
                    acme_api.AcmeService(key_length=str(acme_row["certType"] or "2048")).remove(cert_id)
                except Exception:
                    pass  # best effort — never block DB cleanup on acme.sh
                with conn() as c:
                    c.execute(
                        "DELETE FROM ssl_certificates WHERE userId = ? AND provider = 'acme' AND remoteCertId = ?",
                        (uid, cert_id),
                    )
                    c.commit()
                cache_delete_pattern(f"ssl:certs:all:user:{uid}:*")
                n = len(edgeone_cleanup.get("removedEdgeCerts") or [])
                self._ok({"edgeoneCleanup": edgeone_cleanup}, "证书已删除" + (f"，并清理加速账号临时证书 {n} 张" if n else ""))
                return

            cred_row, api = _ssl_api(cred_id_raw)
            # Snapshot the row (for the cleanup helper) before deleting.
            with conn() as c:
                cert_row_for_cleanup = c.execute(
                    "SELECT * FROM ssl_certificates WHERE userId = ? AND credentialId = ? AND remoteCertId = ? LIMIT 1",
                    (uid, int(cred_row["id"]), cert_id),
                ).fetchone()
            edgeone_cleanup = {"removedEdgeCerts": [], "errors": []}
            if cert_row_for_cleanup is not None:
                try:
                    edgeone_cleanup = _cleanup_edgeone_cert_for_cert(self, uid, cert_row_for_cleanup)
                except Exception:
                    pass
            api.delete_certificate(cert_id)
            cred_id = int(cred_row["id"])
            with conn() as c:
                c.execute(
                    "DELETE FROM ssl_certificates WHERE userId = ? AND credentialId = ? AND remoteCertId = ?",
                    (uid, cred_id, cert_id),
                )
                c.commit()
            _invalidate(cred_id)
            n = len(edgeone_cleanup.get("removedEdgeCerts") or [])
            self._ok({"edgeoneCleanup": edgeone_cleanup}, "证书已删除" + (f"，并清理加速账号临时证书 {n} 张" if n else ""))
            return

        # POST /api/ssl/certificates/sync — force sync from remote
        if self.command == "POST" and sub == "/certificates/sync":
            cred_id_raw = _get_cred_id()
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            cred_row, api = _ssl_api(cred_id_raw)
            cred_id = int(cred_row["id"])

            all_certs: list = []
            offset = 0
            batch = 100
            while True:
                result = api.list_certificates(offset=offset, limit=batch)
                batch_certs = result.get("certificates") or []
                all_certs.extend(batch_certs)
                if len(batch_certs) < batch or len(all_certs) >= result.get("totalCount", 0):
                    break
                offset += batch

            sync_result = _sync_to_db(cred_id, "tencent_ssl", all_certs, prune_missing=True)
            _invalidate(cred_id)
            self._ok({"synced": len(all_certs), **sync_result}, f"同步完成，共 {len(all_certs)} 个证书，清理 {sync_result.get('removed', 0)} 个失效本地记录")
            return

        # POST /api/ssl/certificates/renew-expired — auto-renew expiring certs
        if self.command == "POST" and sub == "/certificates/renew-expired":
            from datetime import datetime, timedelta
            import time as _time
            renew_days = int(body.get("renewDays") or 30)
            dns_credential_id = body.get("dnsCredentialId")
            now_dt = datetime.now(timezone.utc)
            threshold_dt = now_dt + timedelta(days=renew_days)

            with conn() as c:
                cred_rows = c.execute(
                    "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ? AND provider IN ('dnspod', 'tencent_ssl')",
                    (uid,),
                ).fetchall()

            renewed: list = []
            failed: list = []
            skipped: list = []

            # Resolve DNS APIs — collect ALL DNS credentials when dnsCredentialId given,
            # or auto-collect all available DNS credentials for zone matching
            all_dns_apis: list = []  # list of (dns_api_obj, dns_provider_name, dns_zones)
            if dns_credential_id:
                dns_cred_row = self._get_credential_row(uid, dns_credential_id)
                if dns_cred_row:
                    dns_secrets = self._credential_secrets(dns_cred_row)
                    dns_provider_name = str(dns_cred_row["provider"] or "").strip().lower()
                    dns_api_obj = None
                    if dns_provider_name == "cloudflare":
                        token = str(dns_secrets.get("apiToken") or "").strip()
                        if token:
                            dns_api_obj = CloudflareApi(token)
                    elif dns_provider_name in ("dnspod", "dnspod_token"):
                        dns_api_obj = DnspodApi(dns_secrets)
                    if dns_api_obj:
                        try:
                            dns_zones = dns_api_obj.list_zones(1, 200).get("zones", [])
                        except Exception:
                            dns_zones = []
                        all_dns_apis.append((dns_api_obj, dns_provider_name, dns_zones))
            else:
                # Auto-collect all DNS credentials for auto-matching
                with conn() as c:
                    all_dns_cred_rows = c.execute(
                        "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ?",
                        (uid,),
                    ).fetchall()
                for dcr in all_dns_cred_rows:
                    dp = str(dcr["provider"] or "").strip().lower()
                    try:
                        ds = self._credential_secrets(dcr)
                        d_api = None
                        if dp == "cloudflare":
                            tk = str(ds.get("apiToken") or "").strip()
                            if tk:
                                d_api = CloudflareApi(tk)
                        elif dp in ("dnspod", "dnspod_token"):
                            d_api = DnspodApi(ds)
                        if d_api:
                            dzones = d_api.list_zones(1, 200).get("zones", [])
                            all_dns_apis.append((d_api, dp, dzones))
                    except Exception:
                        pass

            def _find_dns_for_domain(check_domain: str):
                """Find matching DNS API + zone for a domain across all DNS credentials."""
                check = check_domain.lower()
                for (d_api, d_prov, d_zones) in all_dns_apis:
                    for z in d_zones:
                        zname = str(z.get("name") or "").lower()
                        if check == zname or check.endswith("." + zname):
                            return d_api, d_prov, z
                return None, None, None

            # Healthy ACME (Let's Encrypt) certs act as standing coverage: a
            # domain covered by a valid wildcard LE cert should NOT trigger a
            # fresh Tencent application — that duplicate used to spawn a new
            # cert pair which the plugin may then deploy over the LE one
            # (the "CN shows account.shifuf.com" wildcard mix-up).
            acme_coverage: list = []
            with conn() as c:
                for row in c.execute(
                    "SELECT domain, san, notAfter FROM ssl_certificates WHERE userId = ? AND provider = 'acme' AND status = 'issued'",
                    (uid,),
                ).fetchall():
                    try:
                        names = json.loads(row["san"] or "[]")
                    except Exception:
                        names = []
                    if not isinstance(names, list) or not names:
                        names = [row["domain"]]
                    expires_at = parse_certificate_datetime(row["notAfter"] or "")
                    if expires_at is None or expires_at <= now_dt:
                        continue
                    acme_coverage.append({"names": [str(n).lower() for n in names if str(n).strip()], "expiresAt": expires_at})

            def _acme_covers(check_domain: str) -> bool:
                """Whether a healthy ACME cert already covers this Tencent domain.

                Exact names must match exactly; a literal wildcard domain
                (``*.example.com``) is only covered by the identical wildcard
                name, while a concrete host is covered by a wildcard exactly
                one label above it (never by the apex-style bare name).
                """
                raw = (check_domain or "").strip().lower().rstrip(".")
                if not raw:
                    return False
                is_wildcard = raw.startswith("*.")
                host = raw[2:] if is_wildcard else raw
                if not host:
                    return False
                for item in acme_coverage:
                    if item["expiresAt"] <= threshold_dt:
                        continue  # coverage too close to expiry to rely on
                    for name in item["names"]:
                        if is_wildcard:
                            if name == raw:
                                return True
                            continue
                        if name.startswith("*."):
                            bare = name[2:]
                            if host.endswith("." + bare) and host.count(".") == bare.count(".") + 1:
                                return True
                        elif host == name:
                            return True
                return False

            for cr in cred_rows:
                cr_secrets = self._credential_secrets(cr)
                sid = str(cr_secrets.get("secretId") or "").strip()
                skey = str(cr_secrets.get("secretKey") or "").strip()
                if not sid or not skey:
                    continue
                try:
                    cr_api = TencentSslApi(sid, skey)
                    all_certs_page: list = []
                    off = 0
                    while True:
                        r = cr_api.list_certificates(offset=off, limit=100)
                        batch = r.get("certificates") or []
                        all_certs_page.extend(batch)
                        if len(batch) < 100 or len(all_certs_page) >= r.get("totalCount", 0):
                            break
                        off += 100

                    # Group by domain: find the latest ISSUED cert per domain
                    domain_latest: Dict[str, Any] = {}
                    for cert in all_certs_page:
                        d = cert.get("domain", "")
                        if not d:
                            continue
                        status = cert.get("status", "")
                        # Only consider issued/expired certs for renewal grouping
                        if status not in ("issued", "expired"):
                            continue
                        existing = domain_latest.get(d)
                        if not existing or (cert.get("notAfter") or "") > (existing.get("notAfter") or ""):
                            domain_latest[d] = cert

                    # Also track if domain has an in-progress application
                    domain_in_progress: Dict[str, str] = {}
                    for cert in all_certs_page:
                        d = cert.get("domain", "")
                        s = cert.get("status", "")
                        if d and s in ("applying", "validating"):
                            domain_in_progress[d] = s

                    for domain, cert in domain_latest.items():
                        not_after = cert.get("notAfter", "")
                        status = cert.get("status", "")
                        old_cert_id = cert.get("remoteCertId", "")
                        if cert.get("autoRenew") and status == "issued":
                            # Tencent's own auto-renew is ON. Trust it for most
                            # of the window, but act as a safety net when the
                            # cert gets within 5 days of expiry (or is already
                            # expired) and Tencent still hasn't re-issued —
                            # otherwise a failed cloud renewal silently kills
                            # the domain's HTTPS.
                            remaining = certificate_days_remaining(not_after)
                            safety_days = min(5, max(1, renew_days))
                            if remaining is None or remaining > safety_days:
                                skipped.append({
                                    "domain": domain, "credential": cr["name"],
                                    "reason": "腾讯云自动续费已开启，由腾讯云托管续期" + (f"（剩余 {remaining} 天）" if remaining is not None else ""),
                                    "source": "tencent",
                                })
                                continue
                            # Fall through: panel-side re-application as fallback.
                        if not not_after:
                            continue
                        not_after_dt = parse_certificate_datetime(not_after)
                        # Never compare Tencent date strings lexicographically:
                        # the API mixes space-separated and ISO-8601 timestamps.
                        # Treat malformed dates as actionable so the user sees a
                        # failed/diagnostic result instead of a silent skip.
                        if not_after_dt is None:
                            failed.append({"domain": domain, "credential": cr["name"], "error": f"证书到期时间无法解析: {not_after}"})
                            continue
                        # Skip if not expired / not expiring within threshold.
                        if not_after_dt > threshold_dt and status == "issued":
                            continue
                        # Never create a SECOND certificate for a name set that is
                        # already covered by a live certificate (重复只保留一个).
                        # Only an already-expired certificate bypasses this —
                        # reviving it is the whole point of the run.
                        if _coverage_allows(domain, certificate_days_remaining(not_after, now_dt)):
                            pass
                        else:
                            skipped.append({
                                "domain": domain, "credential": cr["name"],
                                "reason": "已被有效证书覆盖，跳过申请以避免重复证书",
                                "source": "tencent",
                            })
                            continue
                        # Covered by a healthy Let's Encrypt cert → no cloud re-issue.
                        if _acme_covers(domain):
                            skipped.append({"domain": domain, "credential": cr["name"], "reason": "已被有效的 Let's Encrypt 证书覆盖，跳过腾讯云续期", "source": "tencent"})
                            continue
                        # Skip if already applying/validating
                        if domain in domain_in_progress:
                            skipped.append({"domain": domain, "credential": cr["name"], "reason": f"已有进行中的申请（{domain_in_progress[domain]}）"})
                            continue

                        try:
                            # Determine DNS method: try to find a matching DNS credential
                            match_api, match_prov, match_zone = _find_dns_for_domain(domain)
                            # Prefer DNS (manual/record-based) over DNS_AUTO to avoid DNSPod-only constraints.
                            dv_method = "DNS"
                            # For official renewal flow, pass OldCertificateId only when still issued and expiring soon.
                            use_old_id = ""
                            if old_cert_id and status == "issued" and not_after_dt <= threshold_dt:
                                # If already expired, OldCertificateId renewal is not supported.
                                if not_after_dt >= now_dt:
                                    use_old_id = str(old_cert_id)
                            result = cr_api.apply_certificate(domain, dv_method, old_certificate_id=use_old_id or None)
                            new_cert_id = result.get("CertificateId", "")
                            dns_ok = False
                            renew_dns_errors: list = []

                            if match_api and new_cert_id and dv_method == "DNS":
                                try:
                                    dv_auths: list = []
                                    for attempt in range(15):
                                        try:
                                            detail = cr_api.get_certificate(new_cert_id)
                                            dv_auths = detail.get("dvAuths") or []
                                        except Exception:
                                            dv_auths = []
                                        if dv_auths:
                                            break
                                        _time.sleep(1.0 + attempt * 0.3)
                                    all_dv_ok = True
                                    for dv in dv_auths:
                                        dv_key = str(dv.get("key") or "").strip()
                                        dv_key = dv_key.rstrip(".")
                                        dv_value = str(dv.get("value") or "").strip()
                                        dv_domain = str(dv.get("domain") or "").strip()
                                        dv_type_raw = str(dv.get("type") or "").upper()
                                        if not dv_key or not dv_value:
                                            continue
                                        rec_type = "CNAME" if "CNAME" in dv_type_raw else "TXT"
                                        # Find the right DNS API for this specific dv_domain
                                        dv_api, dv_prov, dv_zone = _find_dns_for_domain(dv_domain or domain)
                                        if not dv_api or not dv_zone:
                                            all_dv_ok = False
                                            continue
                                        zone_id = str(dv_zone.get("id") or "")
                                        rec_value = dv_value
                                        try:
                                            if dv_prov == "cloudflare":
                                                if rec_type == "TXT":
                                                    rec_value = self._normalize_txt_for_cf("TXT", rec_value)
                                                dv_api.create_record(zone_id, {
                                                    "type": rec_type, "name": dv_key, "content": rec_value, "ttl": 600,
                                                })
                                            else:
                                                dv_api.create_record(zone_id, {
                                                    "type": rec_type, "name": dv_key, "value": rec_value, "ttl": 600,
                                                })
                                        except Exception as dns_ex_inner:
                                            all_dv_ok = False
                                            renew_dns_errors.append({"key": dv_key, "error": str(dns_ex_inner)})
                                    dns_ok = all_dv_ok and len(dv_auths) > 0

                                    # Auto-submit domain validation if DNS records were added
                                    if dns_ok:
                                        _time.sleep(3)
                                        try:
                                            cr_api.complete_certificate(new_cert_id)
                                        except Exception:
                                            pass
                                except Exception as dns_outer_ex:
                                    renew_dns_errors.append({"error": str(dns_outer_ex)})

                            renew_item: Dict[str, Any] = {
                                "domain": domain,
                                "credential": cr["name"],
                                "newCertId": new_cert_id,
                                "dnsRecordAdded": dns_ok,
                            }
                            if renew_dns_errors:
                                renew_item["dnsErrors"] = renew_dns_errors
                            renewed.append(renew_item)
                            _invalidate(int(cr["id"]))
                        except Exception as ex:
                            failed.append({"domain": domain, "credential": cr["name"], "error": str(ex)})
                except Exception as ex:
                    failed.append({"domain": "*", "credential": cr["name"], "error": str(ex)})

            # ── Cloud-side certificate inventory (shared with the ACME pass) ──
            # The ACME renewal pass below MUST NOT queue a new Let's Encrypt
            # certificate while a cloud copy covering the same domain still has
            # plenty of life left — that is exactly how duplicate wildcard
            # certificates were created on every daily run. One inventory,
            # both passes.
            tencent_coverage: list = []
            for _cr in cred_rows:
                try:
                    _sec = self._credential_secrets(_cr)
                    _sid = str(_sec.get("secretId") or "").strip()
                    _skey = str(_sec.get("secretKey") or "").strip()
                    if not _sid or not _skey:
                        continue
                    _inv_api = TencentSslApi(_sid, _skey)
                    _off = 0
                    while _off <= 1000:
                        _page = _inv_api.list_certificates(offset=_off, limit=100)
                        _batch = _page.get("certificates") or []
                        for _cert in _batch:
                            if str(_cert.get("status") or "") not in ("issued", ""):
                                continue
                            _names = [_norm_host(_cert.get("domain"))]
                            for _alt in (_cert.get("subjectAltName") or []):
                                _names.append(_norm_host(_alt))
                            _names = [n for n in _names if n]
                            if not _names:
                                continue
                            _remaining = certificate_days_remaining(_cert.get("notAfter") or "", now_dt)
                            if _remaining is None or _remaining <= 0:
                                continue
                            tencent_coverage.append({"names": _names, "days": int(_remaining)})
                        if len(_batch) < 100:
                            break
                        _off += 100
                except Exception:
                    continue

            def _tencent_covers(check_domain: str, min_days: int) -> bool:
                """Whether a live Tencent certificate already covers `check_domain`.

                Only certificates with MORE than `min_days` of life count, so a
                hand-uploaded replacement inside the pre-expiry window never
                blocks the renewal it was meant to perform.
                """
                raw = _norm_host(check_domain)
                if not raw:
                    return False
                is_wildcard = raw.startswith("*.")
                host = raw[2:] if is_wildcard else raw
                if not host:
                    return False
                for item in tencent_coverage:
                    if int(item.get("days") or 0) <= max(0, int(min_days)):
                        continue
                    for name in item["names"]:
                        if is_wildcard:
                            if name == raw:
                                return True
                            continue
                        if name.startswith("*."):
                            bare = name[2:]
                            if host.endswith("." + bare) and host.count(".") == bare.count(".") + 1:
                                return True
                        elif host == name:
                            return True
                return False

            def _coverage_allows(domain: str, days_left: Any) -> bool:
                """Whether a renewal / re-issue for `domain` is still needed.

                An ALREADY EXPIRED certificate must always be re-issued: Tencent
                refuses OldCertificateId once it lapsed and acme.sh cannot re-use
                a dead profile, so a fresh application is the only way back —
                even when a replacement was uploaded but not deployed yet.
                """
                try:
                    if days_left is not None and int(days_left) < 0:
                        return True
                except Exception:
                    pass
                return not _tencent_covers(domain, RENEWAL_TRIGGER_DAYS)

            # ── acme.sh certificates: queue renewals ──
            # DNS-01 renewal can take several minutes. Never execute acme.sh in
            # the request thread: persist a renew job and let the same durable
            # worker used by initial issuance process it across restarts.
            if acme_api.acme_available():
                with conn() as c:
                    acme_rows = c.execute(
                        """SELECT s.*, d.provider AS dnsProvider, d.name AS dnsName
                           FROM ssl_certificates s
                           LEFT JOIN dns_credentials d ON d.id = s.credentialId
                           WHERE s.userId = ? AND s.provider = 'acme'""",
                        (uid,),
                    ).fetchall()
                for ar in acme_rows:
                    domain = str(ar["domain"] or "").strip()
                    if not ar["autoRenew"]:
                        skipped.append({"domain": domain, "credential": ar["dnsName"] or "acme", "reason": "自动续期已关闭", "source": "letsencrypt"})
                        continue
                    not_after = str(ar["notAfter"] or "")
                    not_after_dt = parse_certificate_datetime(not_after)
                    if not_after_dt is None:
                        failed.append({"domain": domain, "credential": ar["dnsName"] or "acme", "error": f"证书到期时间无法解析: {not_after}", "source": "letsencrypt"})
                        continue
                    if not_after_dt > threshold_dt:
                        # Still comfortable: Let's Encrypt certificates are only
                        # renewed inside the renewal window (RENEWAL_TRIGGER_DAYS,
                        # 30 days by default), never earlier — that is what kept
                        # minting fresh duplicates on every daily run.
                        continue
                    acme_days_left = certificate_days_remaining(not_after, now_dt)
                    if _coverage_allows(domain, acme_days_left):
                        pass
                    else:
                        skipped.append({
                            "domain": domain, "credential": ar["dnsName"] or "acme",
                            "reason": "已被有效证书覆盖，跳过续期以避免重复证书",
                            "source": "letsencrypt",
                        })
                        continue
                    if not ar["dnsProvider"]:
                        failed.append({"domain": domain, "credential": "acme", "error": "关联的 DNS 凭证已不存在，无法续期", "source": "letsencrypt"})
                        continue
                    try:
                        raw_domains = json.loads(ar["san"] or "[]") if ar["san"] else []
                        domains = raw_domains if isinstance(raw_domains, list) and raw_domains else [domain]
                    except Exception:
                        domains = [domain]
                    with conn() as c:
                        active = c.execute(
                            """SELECT id FROM ssl_acme_jobs
                               WHERE userId = ? AND certificateId = ? AND operation = 'renew'
                                 AND status IN ('queued', 'running') LIMIT 1""",
                            (uid, ar["id"]),
                        ).fetchone()
                        if active is None:
                            ts = now_iso()
                            # Preserve the certificate's original CA across renewals.
                            renew_ca = ""
                            try:
                                renew_ca = str(ar["acmeCa"] or "")
                            except Exception:
                                renew_ca = ""
                            c.execute(
                                """INSERT INTO ssl_acme_jobs
                                   (userId, certificateId, dnsCredentialId, domain, domains, keyLength,
                                    ca, operation, status, attempts, createdAt, updatedAt)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, 'renew', 'queued', 0, ?, ?)""",
                                (uid, ar["id"], ar["credentialId"], domain, json.dumps(domains, ensure_ascii=False),
                                 str(ar["certType"] or "2048"), renew_ca, ts, ts),
                            )
                            c.execute(
                                "UPDATE ssl_certificates SET statusMsg = '续期任务已排队', renewError = '', updatedAt = ? WHERE id = ?",
                                (ts, ar["id"]),
                            )
                            c.commit()
                            renewed.append({"domain": domain, "credential": ar["dnsName"] or "acme", "newCertId": domain, "dnsRecordAdded": True, "source": "letsencrypt", "status": "queued"})
                        else:
                            skipped.append({"domain": domain, "credential": ar["dnsName"] or "acme", "reason": "已有续期任务执行中", "source": "letsencrypt"})

            total_renewed = len(renewed)
            for item in renewed:
                _write_ssl_task_log(uid, "renewal", None, item.get("domain"), item.get("source") or "tencent", "queued" if item.get("status") == "queued" else "success", message="证书续期任务已排队" if item.get("status") == "queued" else "证书续期已完成")
                # External success-event push (opt-in webhook). ACME renewals
                # fire from the job worker once the cert actually issues;
                # Tencent renewals complete inline (newCertId issued now).
                if item.get("status") != "queued":
                    try:
                        _push_ssl_success_event(
                            uid, "ssl_renewal_succeeded", str(item.get("domain") or ""),
                            str(item.get("source") or "tencent"),
                            {"newCertId": item.get("newCertId"), "credential": item.get("credential")},
                        )
                    except Exception:
                        pass
            for item in failed:
                failure_source = str(item.get("source") or "tencent")
                failure_domain = str(item.get("domain") or "*")
                failure_reason = str(item.get("error") or "续期失败")
                _write_ssl_task_log(uid, "renewal", None, failure_domain, failure_source, "failed", message=failure_reason)
                _send_ssl_failure_notifications(uid, {
                    "event": "ssl_renewal_failed", "domain": failure_domain,
                    "source": failure_source, "reason": failure_reason, "generatedAt": now_iso(),
                })
            msg = f"续期检查完成：{total_renewed} 个已续期或排队"
            if failed:
                msg += f"，{len(failed)} 个失败"
            if skipped:
                msg += f"，{len(skipped)} 个跳过"
            self._ok({"renewed": renewed, "failed": failed, "skipped": skipped}, msg)
            return

        # POST /api/ssl/certificates/reconcile — refresh Tencent state and
        # remove local rows whose remote certificate was deleted/expired.
        if self.command == "POST" and sub == "/certificates/reconcile":
            cred_id_raw = _get_cred_id()
            if cred_id_raw and cred_id_raw != "all":
                targets = []
                row = self._get_credential_row(uid, cred_id_raw)
                if row is not None:
                    targets = [row]
            else:
                # Any credential that carries Tencent SecretId/SecretKey owns
                # certificates — a DNSPod/DNS credential is routinely also the
                # SSL account, and restricting this to provider='tencent_ssl'
                # silently skipped those accounts (their certificates never made
                # it into the local table, so dedup/renewal saw nothing).
                with conn() as c:
                    targets = c.execute(
                        "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ?",
                        (uid,),
                    ).fetchall()
            results = []
            for cr in targets:
                try:
                    sec = self._credential_secrets(cr)
                    sid = str(sec.get("secretId") or "").strip()
                    skey = str(sec.get("secretKey") or "").strip()
                    if not sid or not skey:
                        raise ValueError("腾讯云凭证缺少 SecretId / SecretKey")
                    api = TencentSslApi(sid, skey)
                    fetched = []
                    offset = 0
                    complete = False
                    while True:
                        page_result = api.list_certificates(offset=offset, limit=100)
                        batch = page_result.get("certificates") or []
                        fetched.extend(batch)
                        total = int(page_result.get("totalCount") or len(fetched))
                        if len(batch) < 100 or len(fetched) >= total:
                            complete = True
                            break
                        offset += len(batch)
                    sync = _sync_to_db(int(cr["id"]), "tencent_ssl", fetched, prune_missing=complete)
                    _invalidate(int(cr["id"]))
                    results.append({"credentialId": cr["id"], "name": cr["name"], "fetched": len(fetched), **sync})
                except Exception as ex:
                    results.append({"credentialId": cr["id"], "name": cr["name"], "error": str(ex)})
            failures = [x for x in results if x.get("error")]
            self._ok({"results": results, "failed": len(failures)}, "腾讯云证书状态检查完成")
            return

        # POST /api/ssl/certificates/batch-deploy — queue deployments for many
        # certificates at once (same semantics as the single-cert deploy).
        if self.command == "POST" and sub == "/certificates/batch-deploy":
            cert_ids = body.get("certIds") if isinstance(body.get("certIds"), list) else []
            cert_ids = [str(x).strip() for x in cert_ids if str(x).strip()][:200]
            if not cert_ids:
                self._err("缺少 certIds 参数", 400)
                return
            queued: list = []
            skipped: list = []
            errors: list = []
            for cert_id in cert_ids:
                with conn() as c:
                    row = c.execute(
                        """SELECT provider, remoteCertId, credentialId, domain, status, notAfter
                           FROM ssl_certificates WHERE userId = ? AND remoteCertId = ? LIMIT 1""",
                        (uid, cert_id),
                    ).fetchone()
                if row is None:
                    errors.append({"certId": cert_id, "error": "证书不存在或尚未同步到本地"})
                    continue
                if str(row["status"] or "") != "issued":
                    skipped.append({"certId": cert_id, "domain": row["domain"], "reason": f"状态 {row['status'] or '未知'} 不可部署"})
                    continue
                if certificate_is_expired(row["notAfter"] or ""):
                    skipped.append({"certId": cert_id, "domain": row["domain"], "reason": "证书已过期"})
                    continue
                source = "letsencrypt" if str(row["provider"] or "") == "acme" else "tencent"
                ts = now_iso()
                with conn() as c:
                    existing = c.execute(
                        """SELECT id, status FROM ssl_deployment_events
                           WHERE userId = ? AND provider = ? AND remoteCertId = ?""",
                        (uid, row["provider"], row["remoteCertId"]),
                    ).fetchone()
                    if existing is not None and str(existing["status"] or "") in ("queued", "running"):
                        skipped.append({"certId": cert_id, "domain": row["domain"], "reason": "已在部署队列中"})
                        continue
                    if existing is not None:
                        c.execute(
                            """UPDATE ssl_deployment_events SET status = 'queued', attempts = 0,
                                 nextAttemptAt = NULL, targetName = NULL, fingerprint = NULL,
                                 error = NULL, startedAt = NULL, completedAt = NULL, updatedAt = ?
                               WHERE id = ?""",
                            (ts, existing["id"]),
                        )
                        event_id = existing["id"]
                    else:
                        c.execute(
                            """INSERT INTO ssl_deployment_events
                               (userId, provider, remoteCertId, credentialId, domain, source, status, createdAt, updatedAt)
                               VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
                            (uid, row["provider"], row["remoteCertId"], row["credentialId"], row["domain"], source, ts, ts),
                        )
                        event_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
                    c.commit()
                queued.append({"certId": cert_id, "domain": row["domain"], "eventId": event_id})
                _write_ssl_task_log(uid, "deployment", event_id, row["domain"], source, "queued", message="用户批量发起部署")
            self._ok(
                {"queued": queued, "skipped": skipped, "errors": errors},
                f"批量部署：{len(queued)} 个已入队"
                + (f"，{len(skipped)} 个跳过" if skipped else "")
                + (f"，{len(errors)} 个失败" if errors else ""),
            )
            return

        # POST /api/ssl/certificates/batch-auto-renew — enable/disable per-cert
        # renewal for many certs. ACME certs flip the local flag; Tencent certs
        # call SetAutoRenewFlag on the cloud.
        if self.command == "POST" and sub == "/certificates/batch-auto-renew":
            enabled = bool(body.get("enabled"))
            cert_ids = body.get("certIds") if isinstance(body.get("certIds"), list) else []
            cert_ids = [str(x).strip() for x in cert_ids if str(x).strip()][:200]
            if not cert_ids:
                self._err("缺少 certIds 参数", 400)
                return
            updated: list = []
            skipped: list = []
            errors: list = []
            for cert_id in cert_ids:
                with conn() as c:
                    row = c.execute(
                        """SELECT id, provider, remoteCertId, domain, credentialId, isUploaded
                           FROM ssl_certificates WHERE userId = ? AND remoteCertId = ? LIMIT 1""",
                        (uid, cert_id),
                    ).fetchone()
                if row is None:
                    errors.append({"certId": cert_id, "error": "证书不存在或尚未同步到本地"})
                    continue
                if str(row["provider"] or "") == "acme":
                    with conn() as c:
                        c.execute(
                            "UPDATE ssl_certificates SET autoRenew = ?, updatedAt = ? WHERE id = ?",
                            (1 if enabled else 0, now_iso(), row["id"]),
                        )
                        c.commit()
                    updated.append({"certId": cert_id, "domain": row["domain"], "provider": "acme"})
                    continue
                if row["isUploaded"]:
                    skipped.append({"certId": cert_id, "domain": row["domain"], "reason": "上传证书不支持腾讯云自动续费"})
                    continue
                try:
                    cred_row, api = _ssl_api(str(row["credentialId"]))
                    api.set_auto_renew_flag(cert_id, enabled)
                except (TencentSslApiError, ValueError) as ex:
                    errors.append({"certId": cert_id, "domain": row["domain"], "error": str(ex)[:300]})
                    continue
                with conn() as c:
                    c.execute(
                        "UPDATE ssl_certificates SET autoRenew = ?, updatedAt = ? WHERE id = ?",
                        (1 if enabled else 0, now_iso(), row["id"]),
                    )
                    c.commit()
                _invalidate(int(row["credentialId"]))
                updated.append({"certId": cert_id, "domain": row["domain"], "provider": "tencent"})
            cache_delete_pattern(f"ssl:certs:all:user:{uid}:*")
            action = "开启" if enabled else "关闭"
            self._ok(
                {"updated": updated, "skipped": skipped, "errors": errors},
                f"批量{action}自动续费：{len(updated)} 个成功"
                + (f"，{len(skipped)} 个跳过" if skipped else "")
                + (f"，{len(errors)} 个失败" if errors else ""),
            )
            return

        # POST /api/ssl/certificates/check-expiry — run the expiry-alert scan
        # now (same logic the daily worker uses). Useful for verifying the
        # notification channels are wired up.
        if self.command == "POST" and sub == "/certificates/check-expiry":
            outcome = _check_ssl_expiry_notifications(uid)
            self._ok(
                outcome,
                f"到期检查完成：检查 {outcome['checked']} 个证书，已推送 {outcome['notified']} 条提醒"
                + (f"（含已过期 {outcome['expired']} 个）" if outcome.get("expired") else ""),
            )
            return

        # POST /api/ssl/certificates/repair-acceleration — re-point every
        # accelerated host whose edge certificate is missing / stale / expired
        # at the best VALID certificate for that domain (exact root domain
        # first, wildcard second). Also driven by the daily worker.
        if self.command == "POST" and sub == "/certificates/repair-acceleration":
            dry_run_flag = bool(body.get("dryRun"))
            outcome = _repair_acceleration_certificates(uid, dry_run=dry_run_flag)
            self._ok(
                outcome,
                ("预览：" if dry_run_flag else "")
                + "加速证书检测完成：检查 " + str(outcome["checked"]) + " 个加速域名，"
                + ("可修复 " if dry_run_flag else "已修复 ") + str(outcome["totalRepaired"]) + " 个"
                + ("，" + str(len(outcome["errors"])) + " 个失败" if outcome.get("errors") else ""),
            )
            return

        # POST /api/ssl/certificates/dedup — collapse duplicate certificate rows
        # (identical copies / already-replaced renewals) down to ONE per domain.
        if self.command == "POST" and sub == "/certificates/dedup":
            dry_run_flag = bool(body.get("dryRun"))
            outcome = _dedup_certificates(uid, delete_cloud=not bool(body.get("keepCloud")), dry_run=dry_run_flag)
            self._ok(
                outcome,
                ("预览：" if dry_run_flag else "")
                + "找到 " + str(outcome["groups"]) + " 组重复证书，"
                + ("可清理 " if dry_run_flag else "已清理 ") + str(outcome["removedCount"]) + " 张",
            )
            return

        # GET /api/ssl/acceleration-certificates — edge certificate state for every
        # accelerated host. This is what the BaoTa plugin reads for its
        # 加速证书检测 tab (previously it queried a per-provider endpoint that
        # needed a siteId, so it always came back empty).
        if self.command == "GET" and sub == "/acceleration-certificates":
            raw_domains = first_or_none(q, "domains") or ""
            wanted = [_norm_host(x) for x in str(raw_domains).split(",") if _norm_host(x)]
            items: List[Dict[str, Any]] = []
            try:
                _refresh_ssl_rows_from_cloud(uid)
            except Exception:
                pass
            panel_rows = _ssl_candidate_rows(uid)
            for target in _acceleration_repair_targets(uid):
                if wanted and not any(
                    w == target["domainName"]
                    or _wildcard_covers(target["domainName"], w)
                    or _wildcard_covers(w, target["domainName"])
                    for w in wanted
                ):
                    continue
                entry: Dict[str, Any] = {
                    "host": target["domainName"],
                    "domainName": target["domainName"],
                    "names": [target["domainName"]],
                    "provider": target["provider"],
                    "credentialId": target["credentialId"],
                    "siteId": target["siteId"],
                    "cname": "",
                    "supported": True,
                    "bindable": False,
                    "certId": "",
                    "panelDomain": "",
                    "panelExpireTime": "",
                    "panelIssuer": "",
                    "panelFingerprint": "",
                    "accelCertificateId": "",
                    "accelStatus": "",
                    "accelExpireTime": "",
                    "accelIssuer": "",
                    "accelEffectiveTime": "",
                    "accelFingerprint": "",
                    "accelDaysRemaining": None,
                    "message": "",
                }
                try:
                    accel_ctx = _SSL_MAINTENANCE_HANDLER_ACCEL(uid, int(target["credentialId"] or 0))
                    api = accel_ctx.get("api") if isinstance(accel_ctx, dict) else None
                except Exception as ex:
                    api = None
                    entry["supported"] = False
                    entry["message"] = str(ex)[:200]
                if api is not None and not hasattr(api, "modify_hosts_certificate"):
                    entry["supported"] = False
                    entry["message"] = "当前加速插件不支持证书绑定"
                edge = _acceleration_edge_state(self, uid, api, target) if api is not None else {}
                # Which certificate SHOULD serve this host is decided from the
                # panel's own certificate inventory (exact root domain first,
                # wildcard second) and stays available even when the acceleration
                # credential is temporarily unusable.
                best = _effective_cert_for_host(uid, target["domainName"], panel_rows)
                if best is not None:
                    entry["certId"] = str(best["remoteCertId"] or "")
                    entry["certDomain"] = str(best["domain"] or "")
                    entry["panelDomain"] = str(best["domain"] or "")
                    entry["panelExpireTime"] = str(best["notAfter"] or "")
                    entry["panelIssuer"] = str(best["issuer"] or "")
                    entry["bindable"] = not certificate_is_expired(best["notAfter"] or "")
                entry["accelCertificateId"] = edge.get("certificateId") or ""
                entry["accelStatus"] = edge.get("status") or ""
                entry["accelExpireTime"] = edge.get("expireTime") or ""
                entry["accelDaysRemaining"] = edge.get("daysRemaining")
                if not entry["accelCertificateId"]:
                    entry["status"] = "missing"
                elif isinstance(entry["accelDaysRemaining"], int) and entry["accelDaysRemaining"] < 0:
                    entry["status"] = "expired"
                elif isinstance(entry["accelDaysRemaining"], int) and entry["accelDaysRemaining"] <= PRE_EXPIRY_DEPLOY_DAYS:
                    entry["status"] = "expiring"
                else:
                    entry["status"] = "ok"
                if best is not None:
                    entry["upToDate"] = bool(
                        entry["accelCertificateId"]
                        and entry["status"] == "ok"
                        and str(best["remoteCertId"] or "") == str(entry["accelCertificateId"] or "")
                    )
                items.append(entry)
            self._ok(
                {"items": items, "total": len(items), "domains": wanted},
                "获取加速证书检测结果 " + str(len(items)) + " 条",
            )
            return

        # POST /api/ssl/certificates/sync-edgeone — manually bind a panel
        # certificate to its matching EdgeOne acceleration domain(s). Accepts a
        # single certId, or a list, or "all" to reconcile every issued cert
        # against its acceleration bindings. dryRun previews.
        if self.command == "POST" and sub == "/certificates/sync-edgeone":
            dry_run = bool(body.get("dryRun"))
            cert_id = str(body.get("certId") or "").strip()
            cert_ids = body.get("certIds") if isinstance(body.get("certIds"), list) else []
            results: List[Dict[str, Any]] = []
            if cert_id or cert_ids:
                targets = [cert_id] if cert_id else [str(x).strip() for x in cert_ids if str(x).strip()]
                for cid in targets[:200]:
                    with conn() as c:
                        row = c.execute(
                            "SELECT * FROM ssl_certificates WHERE userId = ? AND remoteCertId = ? LIMIT 1",
                            (uid, cid),
                        ).fetchone()
                    if row is None:
                        results.append({"certId": cid, "synced": 0, "error": "证书不存在"})
                        continue
                    if str(row["status"] or "") != "issued" or certificate_is_expired(row["notAfter"] or ""):
                        results.append({"certId": cid, "domain": row["domain"], "synced": 0, "error": "证书非有效已签发状态"})
                        continue
                    outcome = _sync_cert_to_edgeone(self, uid, row, dry_run=dry_run)
                    results.append({"certId": cid, "domain": row["domain"], **outcome})
            else:
                with conn() as c:
                    rows = c.execute(
                        """SELECT * FROM ssl_certificates
                           WHERE userId = ? AND status = 'issued'
                           ORDER BY notAfter DESC LIMIT 500""",
                        (uid,),
                    ).fetchall()
                # Only bind the BEST cert per domain: with several issued certs
                # for the same domain, syncing every one would let an older
                # cert overwrite a newer binding on the edge.
                seen_domains = set()
                for row in rows:
                    if certificate_is_expired(row["notAfter"] or ""):
                        continue
                    domain_key = _norm_host(row["domain"])
                    if not domain_key or domain_key in seen_domains:
                        continue
                    seen_domains.add(domain_key)
                    outcome = _sync_cert_to_edgeone(self, uid, row, dry_run=dry_run)
                    if outcome.get("synced") or outcome.get("results"):
                        results.append({"certId": row["remoteCertId"], "domain": row["domain"], **outcome})
            total_synced = sum(int(r.get("synced") or 0) for r in results)
            self._ok(
                {"results": results, "totalSynced": total_synced, "dryRun": dry_run},
                ("预览：" if dry_run else "") + f"CDN 加速证书同步完成，共 {total_synced} 个加速域名已绑定",
            )
            return

        # POST /api/ssl/certificates/reconcile-edge — ensure every accelerated
        # host ends up bound to the best VALID panel certificate it can get
        # (exact root domain first, wildcard second), and drop binding rows whose
        # acceleration no longer exists. Shared by the daily worker and the
        # BaoTa plugin sync, so "续期完成后 EdgeOne 还是旧证书" cannot happen.
        if self.command == "POST" and sub == "/certificates/reconcile-edge":
            dry_run_flag = bool(body.get("dryRun"))
            repair = _repair_acceleration_certificates(uid, dry_run=dry_run_flag)
            sweep = _sync_issued_certs_to_acceleration(uid, dry_run=dry_run_flag)
            self._ok(
                {"repair": repair, "sweep": sweep, "dryRun": dry_run_flag},
                ("预览：" if dry_run_flag else "")
                + "加速证书校验完成：修复 " + str(repair["totalRepaired"]) + " 个，续绑 " + str(sweep.get("synced") or 0) + " 个",
            )
            return

        # GET /api/ssl/acceleration-bindings — SHARED view for the BaoTa plugin:
        # every accelerated host this panel knows about together with the edge
        # certificate state and the certificate that should be bound to it.
        # (The plugin previously queried /api/accelerations/certificates, which
        # requires a siteId, so its 加速证书检测 tab always came back empty.)
        if self.command == "GET" and sub == "/acceleration-bindings":
            # Hosts are cheap; the certificate side is what needs the cloud mirror
            # so "应绑定证书" matches the certificate page exactly.
            try:
                _refresh_ssl_rows_from_cloud(uid)
            except Exception:
                pass
            raw_domains = first_or_none(q, "domains") or ""
            wanted = [_norm_host(x) for x in str(raw_domains).split(",") if _norm_host(x)]
            items: List[Dict[str, Any]] = []
            panel_rows = _ssl_candidate_rows(uid)
            for target in _acceleration_repair_targets(uid):
                if wanted and not any(
                    w == target["domainName"]
                    or _wildcard_covers(target["domainName"], w)
                    or _wildcard_covers(w, target["domainName"])
                    for w in wanted
                ):
                    continue
                entry: Dict[str, Any] = {
                    "host": target["domainName"],
                    "domainName": target["domainName"],
                    "names": [target["domainName"]],
                    "provider": target["provider"],
                    "credentialId": target["credentialId"],
                    "siteId": target["siteId"],
                    "cname": "",
                    "supported": True,
                    "bindable": False,
                    "certId": "",
                    "panelDomain": "",
                    "panelExpireTime": "",
                    "panelIssuer": "",
                    "panelFingerprint": "",
                    "accelCertificateId": "",
                    "accelStatus": "",
                    "accelExpireTime": "",
                    "accelIssuer": "",
                    "accelEffectiveTime": "",
                    "accelFingerprint": "",
                    "accelDaysRemaining": None,
                    "status": "",
                    "message": "",
                    "upToDate": None,
                }
                try:
                    accel_ctx = _SSL_MAINTENANCE_HANDLER_ACCEL(uid, int(target["credentialId"] or 0))
                    api = accel_ctx.get("api") if isinstance(accel_ctx, dict) else None
                except Exception as ex:
                    api = None
                    entry["supported"] = False
                    entry["message"] = str(ex)[:200]
                if api is not None and not hasattr(api, "modify_hosts_certificate"):
                    entry["supported"] = False
                    entry["message"] = "当前加速插件不支持证书绑定"
                edge = _acceleration_edge_state(self, uid, api, target) if api is not None else {}
                best = _effective_cert_for_host(uid, target["domainName"], panel_rows)
                if best is not None:
                    entry["certId"] = str(best["remoteCertId"] or "")
                    entry["certDomain"] = str(best["domain"] or "")
                    entry["panelDomain"] = str(best["domain"] or "")
                    entry["panelExpireTime"] = str(best["notAfter"] or "")
                    entry["panelIssuer"] = str(best["issuer"] or "")
                    entry["bindable"] = not certificate_is_expired(best["notAfter"] or "")
                entry["accelCertificateId"] = edge.get("certificateId") or ""
                entry["accelStatus"] = edge.get("status") or ""
                entry["accelExpireTime"] = edge.get("expireTime") or ""
                entry["accelDaysRemaining"] = edge.get("daysRemaining")
                edge_days = edge.get("daysRemaining")
                if not entry["accelCertificateId"]:
                    entry["status"] = "missing"
                elif isinstance(edge_days, int) and edge_days < 0:
                    entry["status"] = "expired"
                elif isinstance(edge_days, int) and edge_days <= PRE_EXPIRY_DEPLOY_DAYS:
                    entry["status"] = "expiring"
                else:
                    entry["status"] = "ok"
                if best is not None:
                    entry["upToDate"] = bool(
                        entry["accelCertificateId"]
                        and (entry["status"] == "ok")
                        and str(best["remoteCertId"] or "") == str(entry["accelCertificateId"] or "")
                    )
                items.append(entry)
            with conn() as c:
                bindings = c.execute(
                    "SELECT * FROM acceleration_cert_bindings WHERE userId = ? ORDER BY updatedAt DESC LIMIT 500",
                    (uid,),
                ).fetchall()
            self._ok(
                {"items": items, "bindings": [dict(row) for row in bindings], "total": len(items)},
                "获取加速证书绑定 " + str(len(items)) + " 条",
            )
            return
        # GET /api/ssl/edgeone-bindings — list tracked acceleration certificate
        # bindings with drift info (whether the bound fingerprint still matches
        # the current panel certificate).
        if self.command == "GET" and sub == "/edgeone-bindings":
            with conn() as c:
                rows = c.execute(
                    "SELECT * FROM acceleration_cert_bindings WHERE userId = ? ORDER BY updatedAt DESC LIMIT 500",
                    (uid,),
                ).fetchall()
                issued_rows = c.execute(
                    """SELECT * FROM ssl_certificates
                       WHERE userId = ? AND status = 'issued' AND TRIM(domain) != ''
                       ORDER BY notAfter DESC""",
                    (uid,),
                ).fetchall()
            out = [_accel_binding_drift_view(uid, dict(row), issued_rows) for row in rows]
            self._ok(out, f"获取 {len(out)} 条加速证书绑定")
            return

        # POST /api/ssl/certificates/clean-expired — delete dead Tencent certs
        # (expired / revoked / failed / cancelled) from the cloud account.
        # Guard: a dead cert for a domain that has NO issued certificate at all
        # is still kept — deleting it would remove the remaining issuance /
        # renewal trail, and it costs nothing on Tencent's side. Pass
        # dryRun=true to preview, staleDays to only touch certs dead that long.
        if self.command == "POST" and sub == "/certificates/clean-expired":
            from datetime import datetime, timedelta
            dry_run = bool(body.get("dryRun"))
            try:
                stale_days = max(0, min(365, int(body.get("staleDays") or 0)))
            except Exception:
                stale_days = 0
            only_domain = str(body.get("domain") or "").strip().lower()
            now_dt = datetime.now(timezone.utc)
            dead_statuses = ("expired", "revoked", "failed", "cancelled")

            with conn() as c:
                # Every credential holding Tencent keys owns certificates (see
                # the reconcile note) — a DNS credential is often the SSL account.
                cred_rows = c.execute(
                    "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ?",
                    (uid,),
                ).fetchall()

            cleaned: list = []
            kept: list = []
            errors: list = []
            for cr in cred_rows:
                s = self._credential_secrets(cr)
                sid = str(s.get("secretId") or "").strip()
                skey = str(s.get("secretKey") or "").strip()
                if not sid or not skey:
                    continue
                try:
                    api = TencentSslApi(sid, skey)
                    certs: list = []
                    off = 0
                    while True:
                        r = api.list_certificates(offset=off, limit=100)
                        batch = r.get("certificates") or []
                        certs.extend(batch)
                        if len(batch) < 100 or len(certs) >= r.get("totalCount", 0):
                            break
                        off += 100
                except Exception as ex:
                    errors.append({"credential": cr["name"], "error": str(ex)})
                    continue

                domains_with_issued = {
                    (x.get("domain") or "").strip().lower()
                    for x in certs if x.get("status") == "issued"
                }
                for cert in certs:
                    status = _certificate_status(dict(cert, source="tencent"))
                    if status not in dead_statuses:
                        continue
                    domain = (cert.get("domain") or "").strip().lower()
                    if not domain or (only_domain and domain != only_domain):
                        continue
                    cert_id = str(cert.get("remoteCertId") or "")
                    if not cert_id:
                        continue
                    if domain in domains_with_issued:
                        # Superseded siblings also expire over time; a newer
                        # issued cert exists, so removing the dead one is safe.
                        pass
                    elif stale_days <= 0:
                        kept.append({"domain": domain, "certId": cert_id, "status": status, "reason": "该域名暂无有效证书，保留过期证书作记录"})
                        continue
                    else:
                        end_dt = parse_certificate_datetime(cert.get("notAfter"))
                        if end_dt is None or (now_dt - end_dt).days < stale_days:
                            kept.append({"domain": domain, "certId": cert_id, "status": status, "reason": f"失效未满 {stale_days} 天"})
                            continue
                    if dry_run:
                        cleaned.append({"domain": domain, "certId": cert_id, "status": status, "dryRun": True})
                        continue
                    try:
                        api.delete_certificate(cert_id)
                        with conn() as c:
                            c.execute(
                                "DELETE FROM ssl_certificates WHERE userId = ? AND credentialId = ? AND remoteCertId = ?",
                                (uid, int(cr["id"]), cert_id),
                            )
                            c.commit()
                        # Dead cert is gone — also clean up any temp cert the
                        # panel uploaded into acceleration accounts for it
                        # (which also drops its binding rows) so those don't
                        # accumulate. Best-effort.
                        try:
                            _cleanup_edgeone_cert_for_cert(
                                self, uid, {"remoteCertId": cert_id, "provider": "tencent_ssl"}
                            )
                        except Exception:
                            pass
                        _invalidate(int(cr["id"]))
                        cleaned.append({"domain": domain, "certId": cert_id, "status": status})
                        _write_ssl_task_log(uid, "cleanup", None, domain, "tencent", "success", message=f"已删除云端失效证书（{status}）")
                    except Exception as ex:
                        errors.append({"domain": domain, "certId": cert_id, "error": str(ex)})
                        _write_ssl_task_log(uid, "cleanup", None, domain, "tencent", "failed", message=str(ex))

            verb = "预览：将清理 " if dry_run else "已清理 "
            self._ok(
                {"cleaned": cleaned, "kept": kept, "errors": errors, "dryRun": dry_run},
                verb + f"{len(cleaned)} 个失效证书" + (f"，{len(kept)} 个保留" if kept else "") + (f"，{len(errors)} 个失败" if errors else ""),
            )
            return

        # POST /api/ssl/certificates/prune-superseded — delete expiring/expired
        # certs that already have a NEWER healthy cert for the same domain, and
        # clean up their leftover DV (_dnsauth) validation DNS records. This is
        # what removes the duplicate _dnsauth.* records that pile up over time.
        # Guard: never deletes a domain's only/best cert. Pass dryRun=true to
        # preview. Used by the BaoTa plugin after a successful deploy.
        if self.command == "POST" and sub == "/certificates/prune-superseded":
            from datetime import datetime, timedelta
            keep_days = int(body.get("keepDays") or 7)
            dry_run = bool(body.get("dryRun"))
            only_domain = str(body.get("domain") or "").strip().lower()
            cleanup_validation = body.get("cleanupValidation", True)
            now_dt = datetime.now(timezone.utc)

            with conn() as c:
                cred_rows = c.execute(
                    "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ? AND provider IN ('dnspod','tencent_ssl')",
                    (uid,),
                ).fetchall()
                dns_rows = c.execute(
                    "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ?",
                    (uid,),
                ).fetchall()

            # DNS APIs for DV record cleanup
            prune_dns_apis: list = []
            for dcr in dns_rows:
                dp = str(dcr["provider"] or "").strip().lower()
                try:
                    ds = self._credential_secrets(dcr)
                    d_api = None
                    if dp == "cloudflare":
                        tk = str(ds.get("apiToken") or "").strip()
                        if tk:
                            d_api = CloudflareApi(tk)
                    elif dp in ("dnspod", "dnspod_token"):
                        d_api = DnspodApi(ds)
                    if d_api:
                        prune_dns_apis.append((d_api, dp, d_api.list_zones(1, 200).get("zones", [])))
                except Exception:
                    pass

            def _prune_find_zone(check: str):
                ck = (check or "").lower()
                for (a, p, zs) in prune_dns_apis:
                    for z in zs:
                        zn = str(z.get("name") or "").lower()
                        if ck == zn or ck.endswith("." + zn):
                            return a, p, z
                return None, None, None

            def _remaining_days(not_after: str) -> int:
                remaining = certificate_days_remaining(not_after, now_dt)
                return int(remaining) if remaining is not None else -99999

            def _cleanup_dv(api_obj, cert_id: str, dry: bool = False) -> int:
                """Old-cert path: remove DV records via the cert's dvAuths (used
                when a cert is being deleted and may still expose them)."""
                cleaned = 0
                try:
                    detail = api_obj.get_certificate(cert_id)
                except Exception:
                    return 0
                for dv in (detail.get("dvAuths") or []):
                    dv_key = str(dv.get("key") or "").strip().rstrip(".")
                    dv_dom = str(dv.get("domain") or "").strip()
                    rec_type = "CNAME" if "CNAME" in str(dv.get("type") or "").upper() else "TXT"
                    if not dv_key:
                        continue
                    a, p, z = _prune_find_zone(dv_dom or detail.get("domain"))
                    if not z:
                        continue
                    zid = str(z.get("id") or "")
                    try:
                        if p == "cloudflare":
                            recs = a.list_records(zid, filters={"name": dv_key, "type": rec_type})
                        else:
                            recs = a.list_records(zid, filters={"subDomain": dv_key, "type": rec_type})
                        for rec in (recs.get("records") or []):
                            rid = str(rec.get("id") or "")
                            if rid:
                                if not dry:
                                    a.delete_record(zid, rid)
                                cleaned += 1
                    except Exception:
                        pass
                return cleaned

            def _cleanup_validation_records(domain: str, dry: bool = False) -> int:
                """Issued certs no longer expose dvAuths, so scan the zone for the
                deterministic validation host `_dnsauth.<domain>` and remove the
                leftover TXT/CNAME records (matching FQDN or relative name)."""
                base = (domain or "").lower().lstrip("*.").lstrip(".")
                if not base:
                    return 0
                host = "_dnsauth." + base
                a, p, z = _prune_find_zone(base)
                if not z:
                    return 0
                zid = str(z.get("id") or "")
                zname = str(z.get("name") or "").lower()
                relative = host[: -(len(zname) + 1)] if host.endswith("." + zname) else host
                removed = 0
                try:
                    recs = a.list_records(zid, 1, 500, {})
                    for rec in (recs.get("records") or []):
                        name = str(rec.get("name") or "").rstrip(".").lower()
                        rtype = str(rec.get("type") or "").upper()
                        if rtype in ("TXT", "CNAME") and name in (host, relative):
                            rid = str(rec.get("id") or "")
                            if rid:
                                if not dry:
                                    a.delete_record(zid, rid)
                                removed += 1
                except Exception:
                    pass
                return removed

            pruned: list = []
            kept: list = []
            validation_cleaned: list = []
            for cr in cred_rows:
                s = self._credential_secrets(cr)
                sid = str(s.get("secretId") or "").strip()
                skey = str(s.get("secretKey") or "").strip()
                if not sid or not skey:
                    continue
                api = TencentSslApi(sid, skey)
                certs: list = []
                off = 0
                while True:
                    r = api.list_certificates(offset=off, limit=100)
                    batch = r.get("certificates") or []
                    certs.extend(batch)
                    if len(batch) < 100 or len(certs) >= r.get("totalCount", 0):
                        break
                    off += 100

                by_domain: Dict[str, list] = {}
                for c2 in certs:
                    d = (c2.get("domain") or "").strip().lower()
                    if not d or (only_domain and d != only_domain):
                        continue
                    by_domain.setdefault(d, []).append(c2)

                for d, lst in by_domain.items():
                    issued = [x for x in lst if x.get("status") == "issued"]
                    if not issued:
                        continue
                    best = max(issued, key=lambda x: parse_certificate_datetime(x.get("notAfter")) or datetime.min.replace(tzinfo=timezone.utc))
                    best_rem = _remaining_days(best.get("notAfter"))

                    # Remove leftover _dnsauth validation records — but only when
                    # the domain has no in-progress application that still needs them.
                    in_progress = any(x.get("status") in ("applying", "validating") for x in lst)
                    if cleanup_validation and not in_progress:
                        n = _cleanup_validation_records(d, dry=dry_run)
                        if n:
                            validation_cleaned.append({"domain": d, "records": n, "dryRun": dry_run})

                    # Safety: only prune sibling certs when this best cert is healthy.
                    if best_rem <= keep_days:
                        kept.append({"domain": d, "reason": f"最佳证书仅剩 {best_rem} 天，跳过"})
                        continue
                    for x in lst:
                        if x.get("remoteCertId") == best.get("remoteCertId"):
                            continue
                        rem = _remaining_days(x.get("notAfter"))
                        if rem >= keep_days:
                            continue  # still healthy — keep it
                        cid = str(x.get("remoteCertId") or "")
                        if not cid:
                            continue
                        if dry_run:
                            pruned.append({"domain": d, "certId": cid, "remaining": rem, "dryRun": True})
                            continue
                        cleaned = _cleanup_dv(api, cid)
                        try:
                            api.delete_certificate(cid)
                            with conn() as c:
                                c.execute(
                                    "DELETE FROM ssl_certificates WHERE userId = ? AND credentialId = ? AND remoteCertId = ?",
                                    (uid, int(cr["id"]), cid),
                                )
                                c.commit()
                            # Also remove any temp cert uploaded to acceleration
                            # accounts for the pruned cert (drops bindings too).
                            try:
                                _cleanup_edgeone_cert_for_cert(
                                    self, uid, {"remoteCertId": cid, "provider": "tencent_ssl"}
                                )
                            except Exception:
                                pass
                            _invalidate(int(cr["id"]))
                            pruned.append({"domain": d, "certId": cid, "remaining": rem, "dvRecordsCleaned": cleaned})
                        except Exception as ex:
                            pruned.append({"domain": d, "certId": cid, "error": str(ex)})

            ok_count = len([p for p in pruned if not p.get("error")])
            val_total = sum(int(v.get("records") or 0) for v in validation_cleaned)
            verb = "预览：将清理 " if dry_run else "已清理 "
            self._ok(
                {"pruned": pruned, "kept": kept, "validationCleaned": validation_cleaned, "dryRun": dry_run},
                verb + f"{ok_count} 个过期证书，{val_total} 条验证记录",
            )
            return

        # ── Third-party platform (七牛云 / 又拍云) certificate deployment ──

        # GET /api/ssl/platform-credentials — qiniu/upyun credentials
        if self.command == "GET" and sub in ("/platform-credentials", "/platform-credentials/"):
            placeholders = ",".join("?" for _ in SUPPORTED_CERT_UPLOAD_PROVIDER_TYPES)
            with conn() as c:
                rows = c.execute(
                    f"SELECT id, name, provider, createdAt FROM dns_credentials WHERE userId = ? AND provider IN ({placeholders}, 'tencent_ssl', 'dnspod') ORDER BY createdAt ASC",
                    (uid, *SUPPORTED_CERT_UPLOAD_PROVIDER_TYPES),
                ).fetchall()
            items = []
            for r in rows:
                item = dict(r)
                # 腾讯云平台复用 tencent_ssl / dnspod 凭证，统一归一化为 'tencent'。
                if str(item.get("provider") or "") in TENCENT_PLATFORM_SOURCE_PROVIDERS:
                    item["provider"] = "tencent"
                items.append(item)
            self._ok({"credentials": items}, "获取平台凭证成功")
            return

        # POST /api/ssl/platform-credentials/test — connectivity check WITHOUT saving
        if self.command == "POST" and sub == "/platform-credentials/test":
            provider = str(body.get("provider") or "").strip().lower()
            if provider not in PLATFORM_UPLOAD_PROVIDERS:
                self._err("不支持的平台，仅支持 qiniu / upyun / tencent", 400)
                return
            if provider == "tencent":
                try:
                    _, _, secrets = _platform_credential_row(self, uid, body.get("credentialId"))
                except ValueError as exc:
                    self._err(str(exc), 400)
                    return
                test_api = _build_platform_api(provider, secrets)
                try:
                    total = test_api.test_connection()
                    self._ok({"ok": True, "certCount": total}, "腾讯云连接成功（SecretId/SecretKey 有效）")
                except Exception as exc:
                    self._err(f"连接失败: {exc}", 400)
                return
            secrets = body.get("secrets") if isinstance(body.get("secrets"), dict) else {}
            clean: Dict[str, str] = {}
            if provider == "qiniu":
                clean["accessKey"] = str(secrets.get("accessKey") or "").strip()
                clean["secretKey"] = str(secrets.get("secretKey") or "").strip()
                if not clean["accessKey"] or not clean["secretKey"]:
                    self._err("请填写 AccessKey / SecretKey", 400)
                    return
            else:
                clean["username"] = str(secrets.get("username") or "").strip()
                clean["password"] = str(secrets.get("password") or "").strip()
                if not clean["username"] or not clean["password"]:
                    self._err("请填写登录账号 / 密码", 400)
                    return
            try:
                api = _build_platform_api(provider, clean)
                if provider == "qiniu":
                    certs = api.list_certs(limit=1)
                    self._ok({"ok": True, "certCount": len(certs or [])}, "七牛云连接成功（证书 API 可用）")
                else:
                    # UpyunConsoleApi(auto_login) 构造时即完成登录校验。
                    self._ok({"ok": True}, "又拍云登录成功")
            except (QiniuApiError, UpyunConsoleError) as exc:
                self._err(f"连接失败: {exc}", int(getattr(exc, "status", 400) or 400))
            except Exception as exc:
                self._err(f"连接失败: {exc}", 400)
            return

        # POST /api/ssl/platform-credentials — add qiniu/upyun credential
        if self.command == "POST" and sub in ("/platform-credentials", "/platform-credentials/"):
            name = str(body.get("name") or "").strip()
            provider = str(body.get("provider") or "").strip().lower()
            secrets = body.get("secrets") if isinstance(body.get("secrets"), dict) else {}
            if not name:
                self._err("缺少凭证名称", 400)
                return
            if provider not in ("qiniu", "upyun"):
                self._err("不支持的平台，仅支持 qiniu / upyun（腾讯云直接复用已有腾讯云凭证，无需创建）", 400)
                return
            clean: Dict[str, str] = {}
            if provider == "qiniu":
                clean["accessKey"] = str(secrets.get("accessKey") or "").strip()
                clean["secretKey"] = str(secrets.get("secretKey") or "").strip()
                if not clean["accessKey"] or not clean["secretKey"]:
                    self._err("七牛云凭证需要 AccessKey / SecretKey", 400)
                    return
            else:
                clean["username"] = str(secrets.get("username") or "").strip()
                clean["password"] = str(secrets.get("password") or "").strip()
                if not clean["username"] or not clean["password"]:
                    self._err("又拍云凭证需要登录账号 / 密码", 400)
                    return
            # 建凭证前先做一次连通性校验（又拍云为登录，七牛为列证书）。
            try:
                _build_platform_api(provider, clean)
                if provider == "qiniu":
                    QiniuCdnApi(clean["accessKey"], clean["secretKey"]).list_certs(limit=1)
                else:
                    UpyunConsoleApi(clean["username"], clean["password"])
            except (QiniuApiError, UpyunConsoleError) as exc:
                self._err(f"凭证校验失败: {exc}", 400)
                return
            except Exception as exc:
                self._err(f"凭证校验失败: {exc}", 400)
                return
            encrypted = encrypt_text(json.dumps(clean, ensure_ascii=False))
            with conn() as c:
                c.execute(
                    "INSERT INTO dns_credentials (userId, name, provider, secrets, isDefault, createdAt, updatedAt) VALUES (?, ?, ?, ?, 0, ?, ?)",
                    (uid, name, provider, encrypted, now_iso(), now_iso()),
                )
                c.commit()
                new_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
            self._ok({"id": new_id}, "平台凭证已创建", 201)
            return

        # DELETE /api/ssl/platform-credentials/<id>
        m_pc = re.fullmatch(r"/platform-credentials/(\d+)", sub)
        if self.command == "DELETE" and m_pc:
            cred_id = int(m_pc.group(1))
            row = self._get_credential_row(uid, cred_id)
            if not row or str(row["provider"] or "").lower() not in PLATFORM_UPLOAD_PROVIDERS:
                self._err("平台凭证不存在", 404)
                return
            with conn() as c:
                c.execute("DELETE FROM ssl_platform_deployments WHERE userId = ? AND credentialId = ?", (uid, cred_id))
                c.execute("DELETE FROM dns_credentials WHERE id = ? AND userId = ?", (cred_id, uid))
                c.commit()
            self._ok(None, "平台凭证及其部署记录已删除")
            return

        # GET /api/ssl/platform-credentials/<id>/secrets — 查看已保存的
        # 七牛云 / 又拍云平台凭证明文密钥（AccessKey/SecretKey 或 账号/密码）。
        m_pc_secret = re.fullmatch(r"/platform-credentials/(\d+)/secrets", sub)
        if self.command == "GET" and m_pc_secret:
            try:
                row, provider, secrets = _platform_credential_row(self, uid, m_pc_secret.group(1))
            except ValueError as exc:
                self._err(str(exc), 400)
                return
            if provider == "qiniu":
                clean = {
                    "accessKey": str(secrets.get("accessKey") or ""),
                    "secretKey": str(secrets.get("secretKey") or ""),
                }
            elif provider == "upyun":
                clean = {
                    "username": str(secrets.get("username") or ""),
                    "password": str(secrets.get("password") or ""),
                }
            else:
                self._err("腾讯云凭证请在 SSL 凭证管理中查看", 400)
                return
            self._ok({"id": row["id"], "name": row["name"], "provider": provider, "secrets": clean}, "获取平台凭证密钥成功")
            return

        # ── 宝塔站点绑定快照（插件上报） ─────────────────────────
        # GET /api/ssl/site-bindings — 前端查询：当前域名绑定了哪个站点、
        # 在哪一个 IP 反代。数据由宝塔插件在同步时上报。
        if self.command == "GET" and sub in ("/site-bindings", "/site-bindings/"):
            _ensure_site_bindings()
            domain_filter = str(first_or_none(q, "domain") or "").strip().lower()
            with conn() as c:
                if domain_filter:
                    rows = c.execute(
                        "SELECT * FROM ssl_site_bindings WHERE userId = ? AND domain LIKE ? ORDER BY domain ASC LIMIT 500",
                        (uid, f"%{domain_filter}%"),
                    ).fetchall()
                else:
                    rows = c.execute(
                        "SELECT * FROM ssl_site_bindings WHERE userId = ? ORDER BY domain ASC LIMIT 500",
                        (uid,),
                    ).fetchall()
            items = []
            for r in rows:
                try:
                    site_names = json.loads(r["siteNames"] or "[]")
                except Exception:
                    site_names = []
                try:
                    proxy_targets = json.loads(r["proxyTargets"] or "[]")
                except Exception:
                    proxy_targets = []
                try:
                    server_ips = json.loads(r["serverIps"] or "[]")
                except Exception:
                    server_ips = []
                items.append({
                    "id": r["id"],
                    "domain": r["domain"],
                    "siteNames": site_names if isinstance(site_names, list) else [],
                    "proxyTargets": proxy_targets if isinstance(proxy_targets, list) else [],
                    "serverIps": server_ips if isinstance(server_ips, list) else [],
                    "reportedAt": r["reportedAt"],
                })
            self._ok({"bindings": items, "reportedAt": max((i["reportedAt"] or "" for i in items), default="")}, "获取宝塔站点绑定成功")
            return

        # POST /api/ssl/site-bindings/report — 宝塔插件上报站点绑定快照。
        # 全量替换该用户的快照（每次同步上报完整清单，天然自愈）。
        if self.command == "POST" and sub == "/site-bindings/report":
            _ensure_site_bindings()
            raw_bindings = body.get("bindings") if isinstance(body.get("bindings"), list) else []
            server_ips_in = body.get("serverIps") if isinstance(body.get("serverIps"), list) else []
            clean_server_ips = []
            for ip in server_ips_in[:10]:
                text = str(ip or "").strip()
                if text and text not in clean_server_ips:
                    clean_server_ips.append(text[:64])
            grouped: Dict[str, Dict[str, Any]] = {}
            for entry in raw_bindings[:500]:
                if not isinstance(entry, dict):
                    continue
                domain = _norm_host(entry.get("domain"))
                if not domain:
                    continue
                site_name = str(entry.get("siteName") or "").strip()[:200]
                if not site_name:
                    continue
                targets_in = entry.get("proxyTargets") if isinstance(entry.get("proxyTargets"), list) else []
                clean_targets: List[str] = []
                for t in targets_in[:20]:
                    text = str(t or "").strip()[:500]
                    if text and text not in clean_targets:
                        clean_targets.append(text)
                bucket = grouped.setdefault(domain, {"siteNames": [], "proxyTargets": []})
                if site_name not in bucket["siteNames"]:
                    bucket["siteNames"].append(site_name)
                for t in clean_targets:
                    if t not in bucket["proxyTargets"]:
                        bucket["proxyTargets"].append(t)
            ts = now_iso()
            with conn() as c:
                c.execute("DELETE FROM ssl_site_bindings WHERE userId = ?", (uid,))
                for domain, info in grouped.items():
                    c.execute(
                        """INSERT INTO ssl_site_bindings
                             (userId, domain, siteNames, proxyTargets, serverIps, reportedAt)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            uid, domain,
                            json.dumps(info["siteNames"][:10], ensure_ascii=False),
                            json.dumps(info["proxyTargets"][:20], ensure_ascii=False),
                            json.dumps(clean_server_ips, ensure_ascii=False),
                            ts,
                        ),
                    )
                c.commit()
            _write_ssl_task_log(
                uid, "site-bindings", None, "", "baota", "success",
                message=f"宝塔插件上报站点绑定：{len(grouped)} 个域名，{len(clean_server_ips)} 个服务器 IP",
            )
            self._ok({"domains": len(grouped)}, "站点绑定已上报")
            return

        # POST /api/ssl/platform-deployments — upload a panel cert to
        # 七牛云/又拍云 and bind the given CDN domains.
        if self.command == "POST" and sub in ("/platform-deployments", "/platform-deployments/"):
            provider = str(body.get("provider") or "").strip().lower()
            if provider not in PLATFORM_UPLOAD_PROVIDERS:
                self._err("不支持的平台，仅支持 qiniu / upyun / tencent", 400)
                return
            domains_raw = body.get("domains")
            if isinstance(domains_raw, str):
                domains = [_norm_host(x) for x in domains_raw.replace("，", ",").split(",")]
            elif isinstance(domains_raw, list):
                domains = [_norm_host(x) for x in domains_raw]
            else:
                domains = []
            domains = [d for d in domains if d]
            # 又拍云域名只能绑定账号下已接入的 CDN 域名；未填时自动发现全部域名。
            auto_discovered = False
            if not domains and provider == "upyun":
                try:
                    cred_row_probe, _, secrets_probe = _platform_credential_row(self, uid, body.get("credentialId"))
                    api_probe = _build_platform_api(provider, secrets_probe)
                    discovered = api_probe.list_account_domains()
                    domains = sorted({item["domain"] for item in discovered if item.get("domain")})
                    auto_discovered = True
                except Exception:
                    pass
            if not domains:
                self._err("缺少要绑定的域名（又拍云只能绑定账号下已接入的域名，请先在又拍云控制台绑定域名）", 400)
                return
            cert_row_id = body.get("certRowId")
            cert_remote_id = str(body.get("certId") or "").strip()
            with conn() as c:
                if cert_row_id:
                    cert_row = c.execute(
                        "SELECT * FROM ssl_certificates WHERE userId = ? AND id = ? LIMIT 1",
                        (uid, int(cert_row_id)),
                    ).fetchone()
                elif cert_remote_id:
                    cert_row = c.execute(
                        "SELECT * FROM ssl_certificates WHERE userId = ? AND remoteCertId = ? ORDER BY id DESC LIMIT 1",
                        (uid, cert_remote_id),
                    ).fetchone()
                else:
                    cert_row = None
            if cert_row is None:
                self._err("未找到面板证书（需先在面板签发/上传证书）", 404)
                return
            if str(cert_row["status"] or "") != "issued":
                self._err("只有已签发（issued）的证书才能上传平台", 400)
                return
            if certificate_is_expired(cert_row["notAfter"] or "") and not body.get("force"):
                self._err("证书已过期，请先续期再上传", 409)
                return
            cert_names = _cert_all_names(cert_row)
            invalid = [d for d in domains if d not in cert_names]
            if invalid:
                hint = "（又拍云域名必须同时满足：已接入你的又拍云账号 + 在证书覆盖范围内）" if provider == "upyun" else ""
                self._err(f"以下域名不在证书覆盖范围内: {', '.join(invalid)} {hint}", 400)
                return
            cred_row, cred_provider, secrets = _platform_credential_row(self, uid, body.get("credentialId"))
            if cred_provider != provider:
                self._err("凭证与所选平台不匹配", 400)
                return
            try:
                pem = _panel_cert_pem(self, uid, cert_row)
                result = _deploy_pem_to_platform(self, uid, provider, cred_row, secrets, cert_row, pem, domains)
            except (QiniuApiError, UpyunConsoleError) as exc:
                self._err(str(exc), int(getattr(exc, "status", 400) or 400))
                return
            except ValueError as exc:
                self._err(str(exc), 400)
                return
            ok_n = len([r for r in result["results"] if r.get("ok")])
            message = f"已上传到{PLATFORM_PROVIDER_LABELS.get(provider, provider)}"
            if ok_n < len(domains):
                failed = [r for r in result["results"] if not r.get("ok")]
                message += f"，{ok_n}/{len(domains)} 个域名绑定成功"
                if failed:
                    message += "：" + failed[0].get("error", "")
            else:
                message += f"并绑定 {ok_n} 个域名"
            self._ok(result, message, 201)
            return

        # GET /api/ssl/platform-deployments — deployment records for visualization
        if self.command == "GET" and sub in ("/platform-deployments", "/platform-deployments/"):
            with conn() as c:
                rows = c.execute(
                    """SELECT d.*, cr.name AS credentialName, cr.provider AS credProvider,
                              s.domain AS certDomain, s.san AS certSan, s.status AS certStatus
                         FROM ssl_platform_deployments d
                         LEFT JOIN dns_credentials cr ON cr.id = d.credentialId
                         LEFT JOIN ssl_certificates s ON s.id = d.certRowId
                        WHERE d.userId = ?
                        ORDER BY d.updatedAt DESC, d.id DESC""",
                    (uid,),
                ).fetchall()
            items: List[Dict[str, Any]] = []
            for r in rows:
                item = dict(r)
                item["daysRemaining"] = certificate_days_remaining(item.get("notAfter") or "")
                item["isExpired"] = certificate_is_expired(item.get("notAfter") or "")
                item["providerLabel"] = PLATFORM_PROVIDER_LABELS.get(str(item.get("provider") or ""), item.get("provider"))
                try:
                    san_val = json.loads(item.get("certSan") or "[]") if item.get("certSan") else []
                except Exception:
                    san_val = []
                item["certSan"] = san_val if isinstance(san_val, list) else []
                items.append(item)
            # 概览聚合：按平台统计 + 即将过期 + 失败数。
            overview: Dict[str, Any] = {
                "total": len(items),
                "byProvider": {},
                "expiringSoon": 0,
                "failed": 0,
                "expired": 0,
            }
            for it in items:
                p = str(it.get("provider") or "")
                bucket = overview["byProvider"].setdefault(p, {"total": 0, "failed": 0, "expiringSoon": 0, "expired": 0, "domains": []})
                bucket["total"] += 1
                bucket["domains"].append({"domain": it.get("domain"), "notAfter": it.get("notAfter"), "status": it.get("status")})
                days = it.get("daysRemaining")
                if it.get("status") == "failed":
                    overview["failed"] += 1
                    bucket["failed"] += 1
                if isinstance(days, int) and 0 <= days <= 30:
                    overview["expiringSoon"] += 1
                    bucket["expiringSoon"] += 1
                if it.get("isExpired"):
                    overview["expired"] += 1
                    bucket["expired"] += 1
            # 又拍云：附带账号下的域名清单（供前端绑定域快选）。
            # covered 标志预计算好通配符匹配，前端不用自己展开 *.domain。
            upyun_domains: List[Dict[str, Any]] = []
            try:
                upyun_cred = next((r for r in rows if str(r["provider"] or "").lower() == "upyun"), None)
                if upyun_cred is not None:
                    cred_row_d, _, secrets_d = _platform_credential_row(self, uid, upyun_cred["credentialId"])
                    upyun_domains = _build_platform_api("upyun", secrets_d).list_account_domains()
                    # 用所有已签发证书的名字集合判断覆盖。
                    with conn() as _c3:
                        issued_rows_d = _c3.execute(
                            "SELECT domain, san FROM ssl_certificates WHERE userId = ? AND status = 'issued'",
                            (uid,),
                        ).fetchall()
                    all_names_d: set = set()
                    for ir in issued_rows_d:
                        try:
                            san_val = json.loads(ir["san"] or "[]") if ir["san"] else []
                        except Exception:
                            san_val = []
                        if isinstance(san_val, list):
                            for s in san_val:
                                all_names_d.add(_norm_host(s))
                        all_names_d.add(_norm_host(ir["domain"]))
                    for ud in upyun_domains:
                        dn = _norm_host(ud.get("domain") or "")
                        covered = any(_wildcard_covers(n, dn) for n in all_names_d if n)
                        ud["covered"] = covered
            except Exception:
                upyun_domains = []
            # EdgeOne 加速绑定并入同一视图（provider=edgeone）。
            # 绑定状态以 EdgeOne API 实时读取为准（acceleration_cert_bindings
            # 会被证书去重/清理任务维护，不可靠），所以这里直接扫描账号下
            # 所有 EdgeOne 凭证的站点/域名，匹配证书 ID 生成实时条目。
            edgeone_items: List[Dict[str, Any]] = []
            eo_seen_domains: set = set()
            try:
                with conn() as c:
                    eo_cred_rows = c.execute(
                        "SELECT id, name, secrets FROM dns_credentials WHERE userId = ?",
                        (uid,),
                    ).fetchall()
                for eo_cred in eo_cred_rows:
                    try:
                        eo_secrets = self._credential_secrets(eo_cred)
                        eo_sid = str(eo_secrets.get("secretId") or "").strip()
                        eo_skey = str(eo_secrets.get("secretKey") or "").strip()
                        if not eo_sid or not eo_skey:
                            continue
                        from modules.tencent_edgeone_api import TencentEdgeOneApi as _EoApi
                        eo_api = _EoApi(eo_sid, eo_skey)
                        for zone in (eo_api.list_zones(offset=0, limit=100).get("zones") or []):
                            zone_id = str(zone.get("zoneId") or zone.get("id") or "").strip()
                            if not zone_id:
                                continue
                            try:
                                listing = eo_api.list_acceleration_domains(zone_id)
                            except Exception:
                                continue
                            for entry in (listing.get("items") or []):
                                domain_name = str(entry.get("domainName") or "").strip().strip(".").lower()
                                cert_id = str(entry.get("certificateId") or "").strip()
                                if not domain_name or not cert_id or domain_name in eo_seen_domains:
                                    continue
                                eo_seen_domains.add(domain_name)
                                # 找面板证书行（同账号 remoteCertId 匹配）。
                                cert_row_eo = None
                                try:
                                    with conn() as _c2:
                                        cert_row_eo = _c2.execute(
                                            "SELECT remoteCertId, notAfter FROM ssl_certificates WHERE userId = ? AND remoteCertId = ? LIMIT 1",
                                            (uid, cert_id),
                                        ).fetchone()
                                except Exception:
                                    cert_row_eo = None
                                edgeone_items.append({
                                    "id": -len(edgeone_items) - 1,
                                    "provider": "edgeone",
                                    "providerLabel": "腾讯云 EdgeOne",
                                    "credentialId": int(eo_cred["id"]),
                                    "credentialName": str(eo_cred["name"] or "EdgeOne"),
                                    "certRemoteId": cert_id,
                                    "domain": domain_name,
                                    "platformCertId": cert_id,
                                    "platformCertName": "",
                                    "notBefore": "",
                                    "notAfter": str(entry.get("certificateExpireTime") or (cert_row_eo["notAfter"] if cert_row_eo else "") or ""),
                                    "status": "synced" if str(entry.get("certificateStatus") or "") == "deployed" else str(entry.get("certificateStatus") or "unknown"),
                                    "lastError": "",
                                    "uploadedAt": "",
                                    "syncedAt": "",
                                    "updatedAt": now_iso(),
                                    "isEdgeOne": True,
                                })
                    except Exception:
                        continue
            except Exception:
                edgeone_items = []
            # 保留 acceleration_cert_bindings 里 EdgeOne 也认到的（补充实时未覆盖的）。
            try:
                with conn() as c:
                    eo_rows = c.execute(
                        "SELECT * FROM acceleration_cert_bindings WHERE userId = ? AND provider = 'edgeone' ORDER BY updatedAt DESC LIMIT 500",
                        (uid,),
                    ).fetchall()
                for row in eo_rows:
                    edgeone_items.append({
                        "id": -int(row["id"] or 0),
                        "provider": "edgeone",
                        "providerLabel": "腾讯云 EdgeOne",
                        "credentialId": int(row["accelerationCredentialId"] or 0),
                        "credentialName": "EdgeOne 加速",
                        "certRemoteId": str(row["certRemoteId"] or ""),
                        "domain": str(row["domainName"] or ""),
                        "platformCertId": str(row["edgeCertId"] or ""),
                        "notBefore": "",
                        "notAfter": str(row["notAfter"] or ""),
                        "status": str(row["status"] or ""),
                        "lastError": str(row["lastError"] or ""),
                        "uploadedAt": str(row["syncedAt"] or ""),
                        "syncedAt": str(row["syncedAt"] or ""),
                        "updatedAt": str(row["updatedAt"] or ""),
                        "isEdgeOne": True,
                    })
            except Exception:
                edgeone_items = []
            for it in edgeone_items:
                it["daysRemaining"] = certificate_days_remaining(it.get("notAfter") or "")
                it["isExpired"] = certificate_is_expired(it.get("notAfter") or "")
            items = items + edgeone_items
            # 概览聚合包含 EdgeOne。
            for it in edgeone_items:
                p = "edgeone"
                bucket = overview["byProvider"].setdefault(p, {"total": 0, "failed": 0, "expiringSoon": 0, "expired": 0, "domains": []})
                bucket["total"] += 1
                bucket["domains"].append({"domain": it.get("domain"), "notAfter": it.get("notAfter"), "status": it.get("status")})
                days = it.get("daysRemaining")
                if it.get("status") == "failed":
                    overview["failed"] += 1
                    bucket["failed"] += 1
                if isinstance(days, int) and 0 <= days <= 30:
                    overview["expiringSoon"] += 1
                    bucket["expiringSoon"] += 1
                if it.get("isExpired"):
                    overview["expired"] += 1
                    bucket["expired"] += 1
            overview["total"] = len(items)
            PLATFORM_PROVIDER_LABELS.setdefault("edgeone", "腾讯云 EdgeOne")
            self._ok({
                "deployments": items,
                "overview": overview,
                "upyunDomains": upyun_domains,
            }, "获取平台部署记录成功")
            return

        # POST /api/ssl/platform-deployments/check — live binding status check
        #
        # Queries each platform for the CURRENT binding of every recorded
        # domain and compares it with the panel's deployment record, so the
        # user can see: uploaded? bound? which cert? when does it expire? and
        # whether the platform side drifted (someone swapped the cert there).
        if self.command == "POST" and sub == "/platform-deployments/check":
            checks: List[Dict[str, Any]] = []
            # ── EdgeOne 加速绑定（腾讯云 EdgeOne）也纳入检查 ──
            # 实时扫描 EdgeOne 站点域名（绑定状态以 API 为准）。
            eo_checks: List[Dict[str, Any]] = []
            try:
                with conn() as c:
                    eo_cred_rows_c = c.execute(
                        "SELECT id, name, secrets FROM dns_credentials WHERE userId = ?",
                        (uid,),
                    ).fetchall()
                for eo_cred in eo_cred_rows_c:
                    try:
                        eo_secrets = self._credential_secrets(eo_cred)
                        eo_sid = str(eo_secrets.get("secretId") or "").strip()
                        eo_skey = str(eo_secrets.get("secretKey") or "").strip()
                        if not eo_sid or not eo_skey:
                            continue
                        from modules.tencent_edgeone_api import TencentEdgeOneApi as _EoApi
                        eo_api = _EoApi(eo_sid, eo_skey)
                        for zone in (eo_api.list_zones(offset=0, limit=100).get("zones") or []):
                            zone_id = str(zone.get("zoneId") or zone.get("id") or "").strip()
                            if not zone_id:
                                continue
                            try:
                                listing = eo_api.list_acceleration_domains(zone_id)
                            except Exception:
                                continue
                            for entry in (listing.get("items") or []):
                                domain_name = str(entry.get("domainName") or "").strip().strip(".").lower()
                                cert_id = str(entry.get("certificateId") or "").strip()
                                if not domain_name or not cert_id:
                                    continue
                                live_eo = {
                                    "bound": True,
                                    "certificateId": cert_id,
                                    "https": str(entry.get("certificateMode") or "") == "sslcert",
                                    "notAfter": str(entry.get("certificateExpireTime") or ""),
                                    "domainStatus": str(entry.get("domainStatus") or ""),
                                    "cnameStatus": str(entry.get("cnameStatus") or ""),
                                }
                                item_eo: Dict[str, Any] = {
                                    "deploymentId": -len(eo_checks) - 1,
                                    "provider": "edgeone",
                                    "providerLabel": "腾讯云 EdgeOne",
                                    "domain": domain_name,
                                    "credentialName": str(eo_cred["name"] or "EdgeOne"),
                                    "platformCertId": cert_id,
                                    "recordedNotAfter": live_eo["notAfter"],
                                    "recordedStatus": "synced" if str(entry.get("certificateStatus") or "") == "deployed" else str(entry.get("certificateStatus") or "unknown"),
                                    "checked": True,
                                    "live": live_eo,
                                    "drift": False,
                                    "isEdgeOne": True,
                                }
                                if live_eo["notAfter"]:
                                    item_eo["liveNotAfter"] = live_eo["notAfter"]
                                    item_eo["liveDaysRemaining"] = certificate_days_remaining(live_eo["notAfter"])
                                eo_checks.append(item_eo)
                    except Exception:
                        continue
            except Exception:
                eo_checks = []
            for item_eo in eo_checks:
                checks.append(item_eo)
            try:
                with conn() as c:
                    eo_rows = c.execute(
                        "SELECT * FROM acceleration_cert_bindings WHERE userId = ? ORDER BY updatedAt DESC LIMIT 500",
                        (uid,),
                    ).fetchall()
            except Exception:
                eo_rows = []
            for row in eo_rows:
                provider = str(row["provider"] or "edgeone").strip().lower()
                if provider != "edgeone":
                    continue
                domain = str(row["domainName"] or "").strip().strip(".")
                edge_cert_id = str(row["edgeCertId"] or "").strip()
                # 实时扫描已覆盖的域名跳过。
                if any(c3.get("domain") == domain.lower() and c3.get("provider") == "edgeone" for c3 in checks):
                    continue
                item: Dict[str, Any] = {
                    "deploymentId": -int(row["id"] or 0),  # 负数 id 区分 EdgeOne 绑定
                    "provider": "edgeone",
                    "providerLabel": "腾讯云 EdgeOne",
                    "domain": domain,
                    "credentialName": "EdgeOne 加速",
                    "platformCertId": edge_cert_id,
                    "recordedNotAfter": row["notAfter"],
                    "recordedStatus": row["status"],
                    "checked": False,
                    "isEdgeOne": True,
                }
                try:
                    accel_cred_id = int(row["accelerationCredentialId"] or 0)
                    accel_ctx = self._acceleration_auth(uid, accel_cred_id)
                    accel_api = accel_ctx.get("api")
                    site_id = str(row["siteId"] or "").strip()
                    live: Dict[str, Any] = {}
                    if accel_api is not None and hasattr(accel_api, "list_acceleration_domains"):
                        try:
                            listing = accel_api.list_acceleration_domains(site_id)
                            for entry in (listing.get("items") or []):
                                if str(entry.get("domainName") or "").strip().strip(".").lower() == domain.lower():
                                    live = {
                                        "bound": bool(entry.get("certificateId")),
                                        "certificateId": str(entry.get("certificateId") or ""),
                                        "https": str(entry.get("certificateMode") or "") == "sslcert",
                                        "notAfter": str(entry.get("certificateExpireTime") or ""),
                                        "domainStatus": str(entry.get("domainStatus") or ""),
                                        "cnameStatus": str(entry.get("cnameStatus") or ""),
                                    }
                                    break
                        except Exception as exc:
                            live = {"error": str(exc)[:200]}
                    item["checked"] = True
                    item["live"] = live
                    live_cert_id = str(live.get("certificateId") or "").strip()
                    item["drift"] = bool(live_cert_id and edge_cert_id and live_cert_id != edge_cert_id)
                    if live.get("notAfter"):
                        item["liveNotAfter"] = live["notAfter"]
                        item["liveDaysRemaining"] = certificate_days_remaining(live["notAfter"])
                except Exception as exc:
                    item["checked"] = False
                    item["error"] = str(exc)[:300]
                checks.append(item)
            with conn() as c:
                rows = c.execute(
                    """SELECT d.*, cr.name AS credentialName, cr.provider AS credProvider
                         FROM ssl_platform_deployments d
                         LEFT JOIN dns_credentials cr ON cr.id = d.credentialId
                        WHERE d.userId = ?
                        ORDER BY d.provider ASC, d.domain ASC""",
                    (uid,),
                ).fetchall()
            grouped: Dict[tuple, list] = {}
            for row in rows:
                grouped.setdefault(
                    (str(row["provider"] or "").lower(), int(row["credentialId"] or 0)), []
                ).append(row)
            for (provider, cred_id), group in grouped.items():
                try:
                    cred_row = self._get_credential_row(uid, cred_id)
                    if cred_row is None:
                        raise ValueError("平台凭证已删除")
                    secrets = self._credential_secrets(cred_row)
                    api = _build_platform_api(provider, secrets)
                except Exception as exc:
                    for row in group:
                        checks.append({
                            "deploymentId": row["id"], "provider": provider,
                            "domain": row["domain"], "checked": False,
                            "error": str(exc)[:200],
                        })
                    continue
                for row in group:
                    domain = str(row["domain"] or "").strip().strip(".")
                    item: Dict[str, Any] = {
                        "deploymentId": row["id"],
                        "provider": provider,
                        "providerLabel": PLATFORM_PROVIDER_LABELS.get(provider, provider),
                        "domain": domain,
                        "credentialName": row["credentialName"],
                        "platformCertId": row["platformCertId"],
                        "platformCertName": row["platformCertName"],
                        "recordedNotAfter": row["notAfter"],
                        "recordedStatus": row["status"],
                        "checked": False,
                    }
                    try:
                        if provider == "upyun":
                            status = api.get_binding_status(domain)
                        elif provider == "qiniu":
                            status = api.get_binding_status(domain)
                        elif provider == "tencent":
                            status = api.get_binding_status(domain)
                        else:
                            status = {"bound": None, "error": "不支持的平台"}
                        item["checked"] = True
                        item["live"] = status
                        # 与面板记录比对：平台当前绑定的证书 ID 与记录不一致 → 漂移。
                        live_cert_id = str((status or {}).get("certificateId") or "").strip()
                        recorded_cert_id = str(row["platformCertId"] or "").strip()
                        if live_cert_id and recorded_cert_id and live_cert_id != recorded_cert_id:
                            item["drift"] = True
                        else:
                            item["drift"] = False
                        # 平台返回的实际到期时间。
                        live_not_after = str((status or {}).get("notAfter") or "")
                        if live_not_after:
                            item["liveNotAfter"] = live_not_after
                            item["liveDaysRemaining"] = certificate_days_remaining(live_not_after)
                    except Exception as exc:
                        item["checked"] = False
                        item["error"] = str(exc)[:300]
                    checks.append(item)
            ok_count = len([c2 for c2 in checks if c2.get("checked")])
            drift_count = len([c2 for c2 in checks if c2.get("drift")])
            message = f"检查完成：{ok_count}/{len(checks)} 个域名状态已核实"
            if drift_count:
                message += f"，发现 {drift_count} 个漂移（平台绑定的证书与面板记录不一致）"
            self._ok({"checks": checks, "checked": ok_count, "total": len(checks), "drift": drift_count}, message)
            return

        # DELETE /api/ssl/platform-deployments/<id> — remove record (best-effort unbind for upyun)
        m_pd = re.fullmatch(r"/platform-deployments/(\d+)", sub)
        if self.command == "DELETE" and m_pd:
            dep_id = int(m_pd.group(1))
            with conn() as c:
                row = c.execute("SELECT * FROM ssl_platform_deployments WHERE id = ? AND userId = ? LIMIT 1", (dep_id, uid)).fetchone()
            if row is None:
                self._err("部署记录不存在", 404)
                return
            unbind_note = ""
            if str(row["provider"] or "").lower() == "upyun":
                try:
                    cred_row, _, secrets = _platform_credential_row(self, uid, row["credentialId"])
                    UpyunConsoleApi(secrets.get("username") or "", secrets.get("password") or "").unbind_domain(str(row["domain"] or ""))
                    unbind_note = "（已关闭该域名 HTTPS）"
                except Exception as exc:
                    unbind_note = f"（解除绑定失败：{str(exc)[:120]}，仅删除了记录）"
            with conn() as c:
                c.execute("DELETE FROM ssl_platform_deployments WHERE id = ? AND userId = ?", (dep_id, uid))
                c.commit()
            self._ok(None, "部署记录已删除" + unbind_note)
            return

        self._err("接口不存在", 404)
    except TencentSslApiError as e:
        self._err(str(e), int(e.status or 400))
    except ValueError as e:
        self._err(str(e), 400)
    except Exception as e:
        self._err(str(e), 500)



def _api_tokens_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    u = self._auth()
    if not u:
        return
    uid = int(u.get("id") or 0)
    if uid <= 0:
        self._err("无效用户", 401)
        return

    sub = path[len("/api/api-tokens"):].strip()
    body = self._json_body(b)
    allowed_scopes = {"ssl:read", "ssl:pem", "ssl:issue", "ssl:renew", "ssl:deploy", "ssl:*", "dns:read", "dns:write", "dashboard:read", "logs:read", "accel:read", "accel:write", "*"}

    try:
        # GET /api/api-tokens — list tokens (never expose the hash)
        if self.command == "GET" and sub in ("", "/"):
            with conn() as c:
                rows = c.execute(
                    "SELECT id, name, prefix, scopes, lastUsedAt, createdAt FROM api_tokens WHERE userId = ? ORDER BY id DESC",
                    (uid,),
                ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                try:
                    item["scopes"] = json.loads(item.get("scopes") or '["*"]')
                except Exception:
                    item["scopes"] = ["*"]
                result.append(item)
            self._ok(result, "获取 API Token 列表成功")
            return

        # POST /api/api-tokens — create a new long-lived token
        if self.command == "POST" and sub in ("", "/"):
            name = str(body.get("name") or "").strip()
            if not name:
                self._err("请填写 Token 名称", 400)
                return
            scopes_raw = body.get("scopes")
            scopes = [str(s).strip() for s in scopes_raw] if isinstance(scopes_raw, list) else ["ssl:read", "ssl:pem", "ssl:issue", "ssl:renew", "ssl:deploy"]
            scopes = list(dict.fromkeys(s for s in scopes if s in allowed_scopes))
            if not scopes or ("*" in scopes and len(scopes) > 1):
                self._err("无效的 Token 权限范围", 400)
                return
            raw, token_hash = generate_api_token()
            prefix = raw[:12]
            with conn() as c:
                c.execute(
                    "INSERT INTO api_tokens (userId, name, tokenHash, prefix, scopes) VALUES (?, ?, ?, ?, ?)",
                    (uid, name, token_hash, prefix, json.dumps(scopes, ensure_ascii=False)),
                )
                c.commit()
                tid = c.execute(
                    "SELECT id FROM api_tokens WHERE userId = ? AND tokenHash = ?",
                    (uid, token_hash),
                ).fetchone()
            self._ok(
                {"id": tid["id"] if tid else None, "name": name, "token": raw, "prefix": prefix, "scopes": scopes},
                "Token 已创建，请妥善保存（仅显示一次）",
                201,
            )
            return

        # DELETE /api/api-tokens/{id}
        if self.command == "DELETE" and sub.startswith("/"):
            try:
                tid = int(sub.strip("/"))
            except (ValueError, TypeError):
                self._err("无效的 Token ID", 400)
                return
            with conn() as c:
                row = c.execute(
                    "SELECT id FROM api_tokens WHERE id = ? AND userId = ?",
                    (tid, uid),
                ).fetchone()
                if not row:
                    self._err("Token 不存在", 404)
                    return
                c.execute("DELETE FROM api_tokens WHERE id = ? AND userId = ?", (tid, uid))
                c.commit()
            self._ok(None, "Token 已删除")
            return

        self._err("接口不存在", 404)
    except Exception as e:
        self._err(str(e), 500)


def _notifications_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/notifications") :] or "/"
    body = self._json_body(b)
    auth_user = self._auth()
    if not auth_user:
        return
    uid = int(auth_user.get("id") or 0)
    if uid <= 0:
        self._err("认证失败", 401)
        return

    def _load_settings():
        with conn() as c:
            try:
                row = c.execute(
                    "SELECT enabled, channels, updatedAt FROM notification_settings WHERE userId = ? LIMIT 1",
                    (uid,),
                ).fetchone()
            except Exception:
                row = None
        if not row:
            return {"enabled": True, "channels": []}
        channels = []
        raw = row["channels"] or "[]"
        try:
            # Prefer encrypted blob (iv:hex...); fall back to plaintext JSON for legacy rows.
            if isinstance(raw, str) and ":" in raw and not raw.lstrip().startswith(("[", "{")):
                try:
                    raw = decrypt_text(raw) or "[]"
                except Exception:
                    pass
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(parsed, list):
                channels = parsed
        except Exception:
            channels = []
        return {
            "enabled": bool(row["enabled"]),
            "channels": channels,
            "updatedAt": row["updatedAt"] if "updatedAt" in row.keys() else None,
        }

    if self.command == "GET" and sub == "/settings":
        self._ok(_load_settings(), "获取通知设置成功")
        return

    if self.command == "PUT" and sub == "/settings":
        enabled = body.get("enabled")
        try:
            channels = sanitize_notification_channels(body.get("channels") if isinstance(body.get("channels"), list) else [])
        except ValueError as exc:
            self._err(str(exc), 400)
            return
        enabled_flag = 1 if (enabled is None or bool(enabled)) else 0
        channels_json = json.dumps(channels, ensure_ascii=False)
        try:
            channels_store = encrypt_text(channels_json)
        except Exception:
            channels_store = channels_json
        with conn() as c:
            c.execute(
                """
                INSERT INTO notification_settings (userId, channels, enabled, updatedAt)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(userId) DO UPDATE SET
                  channels = excluded.channels,
                  enabled = excluded.enabled,
                  updatedAt = CURRENT_TIMESTAMP
                """,
                (uid, channels_store, enabled_flag),
            )
            c.commit()
        self._ok(_load_settings(), "通知设置已保存")
        return

    if self.command == "POST" and sub == "/test":
        channel = body.get("channel") if isinstance(body.get("channel"), dict) else None
        if not channel:
            self._err("缺少 channel 配置", 400)
            return
        try:
            sanitized = sanitize_notification_channels([channel])
        except ValueError as exc:
            self._err(str(exc), 400)
            return
        if not sanitized:
            self._err("渠道配置无效", 400)
            return
        title = str(body.get("title") or "DNS Panel 测试通知")
        content = str(body.get("content") or "这是一条测试消息")
        # enrich email channel with user SMTP if missing
        with conn() as c:
            user = c.execute(
                "SELECT smtpHost, smtpPort, smtpSecure, smtpUser, smtpPass, smtpFrom, domainExpiryNotifyEmailTo, email FROM users WHERE id = ? LIMIT 1",
                (uid,),
            ).fetchone()
        ch = dict(sanitized[0])
        cfg = dict(ch.get("config") or {})
        if str(ch.get("type") or "") == "email" and user:
            cfg.setdefault("smtpHost", user["smtpHost"])
            cfg.setdefault("smtpPort", user["smtpPort"])
            cfg.setdefault("smtpSecure", user["smtpSecure"])
            cfg.setdefault("smtpUser", user["smtpUser"])
            if not cfg.get("smtpPass") and user["smtpPass"]:
                try:
                    cfg["smtpPass"] = decrypt_text(user["smtpPass"])
                except Exception:
                    cfg["smtpPass"] = ""
            elif cfg.get("smtpPass"):
                # If caller supplied the stored ciphertext by mistake, decrypt when possible.
                raw_pass = str(cfg.get("smtpPass") or "")
                if ":" in raw_pass and all(c in "0123456789abcdefABCDEF:" for c in raw_pass):
                    try:
                        decrypted = decrypt_text(raw_pass)
                        if decrypted:
                            cfg["smtpPass"] = decrypted
                    except Exception:
                        pass
            cfg.setdefault("smtpFrom", user["smtpFrom"])
            cfg.setdefault("to", user["domainExpiryNotifyEmailTo"] or user["email"] or cfg.get("to"))
        if str(ch.get("type") or "") == "inapp":
            cfg["userId"] = uid
        ch["config"] = cfg
        results = send_notification([ch], title, content, level="info", meta={"event": "test"})
        self._ok({"results": results}, "测试发送完成")
        return

    if self.command == "GET" and sub == "/inbox":
        status = str((q.get("status") or ["all"])[0] or "all").strip()
        limit = p_int((q.get("limit") or ["50"])[0], 50, 200)
        with conn() as c:
            try:
                if status in ("unread", "read"):
                    rows = c.execute(
                        "SELECT id, level, title, message, status, meta, createdAt FROM inapp_notifications WHERE userId = ? AND status = ? ORDER BY id DESC LIMIT ?",
                        (uid, status, limit),
                    ).fetchall()
                else:
                    rows = c.execute(
                        "SELECT id, level, title, message, status, meta, createdAt FROM inapp_notifications WHERE userId = ? ORDER BY id DESC LIMIT ?",
                        (uid, limit),
                    ).fetchall()
                unread = c.execute(
                    "SELECT COUNT(*) AS c FROM inapp_notifications WHERE userId = ? AND status = 'unread'",
                    (uid,),
                ).fetchone()["c"]
            except Exception:
                rows, unread = [], 0
        items = []
        for r in rows:
            try:
                meta = json.loads(r["meta"] or "{}")
            except Exception:
                meta = {}
            items.append(
                {
                    "id": r["id"],
                    "level": r["level"],
                    "title": r["title"],
                    "message": r["message"],
                    "status": r["status"],
                    "meta": meta,
                    "createdAt": r["createdAt"],
                }
            )
        self._ok({"items": items, "unread": int(unread or 0)}, "获取站内通知成功")
        return

    if self.command == "POST" and sub == "/inbox/read":
        nid = body.get("id")
        mark_all = bool(body.get("all"))
        with conn() as c:
            try:
                if mark_all:
                    c.execute("UPDATE inapp_notifications SET status = 'read' WHERE userId = ? AND status = 'unread'", (uid,))
                elif nid is not None:
                    c.execute(
                        "UPDATE inapp_notifications SET status = 'read' WHERE userId = ? AND id = ?",
                        (uid, int(nid)),
                    )
                c.commit()
            except Exception as exc:
                self._err(f"标记已读失败: {exc}", 500)
                return
        self._ok({"ok": True}, "已标记已读")
        return

    self._err("接口不存在", 404)
