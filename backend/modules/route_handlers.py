#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List

from modules.cache import (
    cache_get, cache_set, cache_delete_pattern,
    zones_key, records_key, lines_key, providers_key,
    esa_sites_key, esa_records_key,
    ssl_certs_key, ssl_cert_detail_key,
)

def attach_route_methods(handler_cls: type, env: Dict[str, Any]) -> None:
    method_names = [
        '_auth_routes',
        '_logs_routes',
        '_domain_expiry_routes',
        '_dns_credentials_routes',
        '_dns_records_routes',
        '_hostnames_routes',
        '_tunnels_routes',
        '_aliyun_esa_routes',
        '_dashboard',
        '_ssl_routes',
    ]
    for name in method_names:
        fn = globals().get(name)
        if callable(fn):
            fn.__globals__.update(env)
            setattr(handler_cls, name, fn)

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
        self._err("公开注册已关闭", 403)
        return

    if self.command == "GET" and sub == "/registration-status":
        self._json(200, {"registrationOpen": False, "setupComplete": setup_complete})
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
        set_system_setting("registration_open", "0")
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


def _domain_expiry_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    sub = path[len("/api/domain-expiry") :] or "/"
    auth_user = self._auth()
    if not auth_user:
        return

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
        results = [self._lookup_domain_expiry_single(d) for d in unique]
        self._ok({"results": results}, "获取域名到期信息成功")
        return

    self._err("接口不存在", 404)


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

    if self.command == "GET" and sub == "/providers":
        ck = providers_key()
        cached = cache_get(ck)
        if cached is not None:
            self._ok(cached, "获取提供商列表成功")
            return
        data = {"providers": get_all_provider_capabilities()}
        cache_set(ck, data, 86400)
        self._ok(data, "获取提供商列表成功")
        return

    if self.command == "GET" and sub == "/":
        with conn() as c:
            rows = c.execute(
                """
                SELECT id, name, provider, accountId, isDefault, createdAt, updatedAt
                FROM dns_credentials
                WHERE userId = ?
                ORDER BY isDefault DESC, createdAt ASC
                """,
                (uid,),
            ).fetchall()
        credentials = []
        for r in rows:
            provider = str(r["provider"] or "")
            created_at = r["createdAt"]
            updated_at = r["updatedAt"]
            if created_at and not isinstance(created_at, str):
                created_at = created_at.isoformat().replace("+00:00", "Z") if hasattr(created_at, 'isoformat') else str(created_at)
            if updated_at and not isinstance(updated_at, str):
                updated_at = updated_at.isoformat().replace("+00:00", "Z") if hasattr(updated_at, 'isoformat') else str(updated_at)
            credentials.append(
                {
                    "id": r["id"],
                    "name": r["name"],
                    "provider": provider,
                    "providerName": PROVIDER_NAMES.get(provider, provider),
                    "accountId": r["accountId"],
                    "isDefault": bool(r["isDefault"]),
                    "createdAt": created_at,
                    "updatedAt": updated_at,
                }
            )
        self._ok({"credentials": credentials}, "获取凭证列表成功")
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
        if not self._provider_supported(provider):
            self._err(f"不支持的提供商: {provider}", 400)
            return

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
            cnt = c.execute("SELECT COUNT(*) c FROM dns_credentials WHERE userId = ?", (uid,)).fetchone()["c"]
            is_default = 1 if int(cnt) == 0 else 0
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

        created_at = row["createdAt"]
        updated_at = row["updatedAt"]
        if created_at and not isinstance(created_at, str):
            created_at = created_at.isoformat().replace("+00:00", "Z") if hasattr(created_at, 'isoformat') else str(created_at)
        if updated_at and not isinstance(updated_at, str):
            updated_at = updated_at.isoformat().replace("+00:00", "Z") if hasattr(updated_at, 'isoformat') else str(updated_at)
        self._ok(
            {
                "credential": {
                    "id": row["id"],
                    "name": row["name"],
                    "provider": row["provider"],
                    "providerName": PROVIDER_NAMES.get(str(row["provider"] or ""), str(row["provider"] or "")),
                    "accountId": row["accountId"],
                    "isDefault": bool(row["isDefault"]),
                    "createdAt": created_at,
                    "updatedAt": updated_at,
                }
            },
            "凭证创建成功",
            201,
        )
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

            updates: Dict[str, Any] = {}
            if "name" in body and body.get("name") is not None:
                nv = str(body.get("name") or "").strip()
                if nv:
                    updates["name"] = nv
            if "accountId" in body:
                av = body.get("accountId")
                updates["accountId"] = str(av).strip() if av is not None and str(av).strip() else None
            if "secrets" in body and isinstance(body.get("secrets"), dict):
                updates["secrets"] = encrypt_text(json.dumps(body.get("secrets"), ensure_ascii=False))
            set_default = body.get("isDefault") is True
            if set_default:
                c.execute("UPDATE dns_credentials SET isDefault = 0, updatedAt = CURRENT_TIMESTAMP WHERE userId = ?", (uid,))
                updates["isDefault"] = 1

            if updates:
                sets = ", ".join([f"{k} = ?" for k in updates.keys()] + ["updatedAt = CURRENT_TIMESTAMP"])
                vals = list(updates.values()) + [cid]
                c.execute(f"UPDATE dns_credentials SET {sets} WHERE id = ?", vals)

            row = c.execute(
                """
                SELECT id, name, provider, accountId, isDefault, createdAt, updatedAt
                FROM dns_credentials WHERE id = ? LIMIT 1
                """,
                (cid,),
            ).fetchone()
            c.commit()

        created_at = row["createdAt"]
        updated_at = row["updatedAt"]
        if created_at and not isinstance(created_at, str):
            created_at = created_at.isoformat().replace("+00:00", "Z") if hasattr(created_at, 'isoformat') else str(created_at)
        if updated_at and not isinstance(updated_at, str):
            updated_at = updated_at.isoformat().replace("+00:00", "Z") if hasattr(updated_at, 'isoformat') else str(updated_at)
        cache_delete_pattern(f"dns:*:cred:{cid}:*")
        cache_delete_pattern(f"esa:*:cred:{cid}:*")
        self._ok(
            {
                "credential": {
                    "id": row["id"],
                    "name": row["name"],
                    "provider": row["provider"],
                    "providerName": PROVIDER_NAMES.get(str(row["provider"] or ""), str(row["provider"] or "")),
                    "accountId": row["accountId"],
                    "isDefault": bool(row["isDefault"]),
                    "createdAt": created_at,
                    "updatedAt": updated_at,
                }
            },
            "凭证更新成功",
        )
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
            c.execute("DELETE FROM dns_credentials WHERE id = ?", (cid,))
            if bool(existing["isDefault"]):
                first = c.execute(
                    "SELECT id FROM dns_credentials WHERE userId = ? ORDER BY createdAt ASC LIMIT 1",
                    (uid,),
                ).fetchone()
                if first:
                    c.execute("UPDATE dns_credentials SET isDefault = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ?", (first["id"],))
            c.commit()

        cache_delete_pattern(f"dns:*:cred:{cid}:*")
        cache_delete_pattern(f"esa:*:cred:{cid}:*")
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

        provider = str(row["provider"] or "")
        valid = False
        err_msg = None
        try:
            secrets = self._json_loads_safe(decrypt_text(row["secrets"]))
            if provider == "cloudflare":
                token = str(secrets.get("apiToken") or "").strip()
                if not token:
                    raise ValueError("缺少 Cloudflare API Token")
                valid = CloudflareApi(token).verify_token()
            else:
                caps = get_provider_capabilities(provider)
                if caps is None:
                    raise ValueError(f"不支持的提供商: {provider}")
                fields = caps.get("authFields") if isinstance(caps.get("authFields"), list) else []
                required_fields = [str(f.get("name") or "").strip() for f in fields if isinstance(f, dict) and bool(f.get("required"))]
                missing = [k for k in required_fields if not str(secrets.get(k) or "").strip()]
                # DNSPod 主凭证存在双模式，允许 secretId/secretKey 或 tokenId/token
                if provider == "dnspod":
                    has_tc3 = str(secrets.get("secretId") or "").strip() and str(secrets.get("secretKey") or "").strip()
                    has_token = str(secrets.get("tokenId") or "").strip() and str(secrets.get("token") or "").strip()
                    valid = bool(has_tc3 or has_token)
                else:
                    valid = len(missing) == 0
                if not valid and missing:
                    err_msg = f"缺少字段: {', '.join(missing)}"
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
                new_value=json.dumps({"id": cid, "provider": provider, "valid": valid}, ensure_ascii=False),
                error_message=None if valid else (err_msg or "凭证无效"),
            )
        except Exception:
            pass
        if valid:
            self._ok({"valid": True}, "凭证验证成功")
        else:
            self._ok({"valid": False, "error": err_msg} if err_msg else {"valid": False}, "凭证验证失败")
        return

    self._err("接口不存在", 404)


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

    try:
        ctx = self._dns_context(uid, q)
    except Exception as e:
        self._err(str(e), 400)
        return
    provider = ctx["provider"]
    is_cf = provider == "cloudflare"
    cf = ctx.get("cf")
    dnspod = ctx.get("dnspod")

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
            if is_cf:
                result = cf.list_zones(page, page_size, keyword)
                zones_raw = result.get("zones") if isinstance(result, dict) else []
                zones = [self._map_cf_zone(z) for z in zones_raw if isinstance(z, dict)]
            else:
                result = dnspod.list_zones(page, page_size, keyword)
                zones_raw = result.get("zones") if isinstance(result, dict) else []
                zones = [self._map_dnspod_zone(z) for z in zones_raw if isinstance(z, dict)]
            total = int(result.get("total")) if isinstance(result, dict) and result.get("total") is not None else len(zones)
            data = {"zones": zones, "total": total, "page": page, "pageSize": page_size}
            cache_set(ck, data, (get_provider_capabilities(provider) or {}).get("domainCacheTtl", 300))
            self._ok(data, "获取域名列表成功")
        except (CloudflareApiError, DnspodApiError) as e:
            self._err(str(e), e.status)
        return

    if self.command == "POST" and sub == "/zones":
        domains = self._parse_domains(body.get("domains") if "domains" in body else body.get("domain") if "domain" in body else body.get("text"))
        if not domains:
            self._err("缺少必需参数: domains", 400)
            return

        if is_cf:
            account_id = str(ctx["credential"]["accountId"] or "").strip()
            if not account_id:
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
                if is_cf:
                    existed_zone = cf.get_zone_by_name(domain, account_id)
                    if existed_zone:
                        zone = existed_zone
                        existed = True
                    else:
                        zone = cf.create_zone(domain, account_id)
                        existed = False
                    name_servers = [str(x) for x in zone.get("name_servers")] if isinstance(zone.get("name_servers"), list) else None
                else:
                    zone = dnspod.create_zone(domain)
                    existed = False
                    name_servers = None
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
            if is_cf:
                zone = cf.get_zone(zone_id)
                self._ok({"zone": self._map_cf_zone(zone)}, "获取域名详情成功")
            else:
                zone = dnspod.get_zone(zone_id)
                self._ok({"zone": self._map_dnspod_zone(zone)}, "获取域名详情成功")
        except (CloudflareApiError, DnspodApiError) as e:
            self._err(str(e), e.status)
        return

    m = re.fullmatch(r"/zones/([^/]+)", sub)
    if self.command == "DELETE" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        zone_name = zone_id
        try:
            if is_cf:
                zone = cf.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
            else:
                zone = dnspod.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
        except Exception:
            pass
        try:
            if is_cf:
                ok = cf.delete_zone(zone_id)
            else:
                ok = dnspod.delete_zone(zone_id)
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
            code = e.status if isinstance(e, (CloudflareApiError, DnspodApiError)) else 400
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
            if is_cf:
                zone = cf.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                filters: Dict[str, Any] = {}
                if sub_domain:
                    filters["name"] = sub_domain
                if rtype:
                    filters["type"] = rtype
                if value:
                    filters["content"] = value
                res = cf.list_records(zone_id, page, page_size, filters)
                records_raw = res.get("records") if isinstance(res, dict) else []
                records = [self._map_cf_record(zone_id, zone_name, r) for r in records_raw if isinstance(r, dict)]
                if keyword:
                    kw = keyword.lower()
                    records = [r for r in records if kw in str(r.get("name") or "").lower() or kw in str(r.get("value") or "").lower()]
            else:
                zone = dnspod.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                filters = {}
                if sub_domain:
                    filters["subDomain"] = sub_domain
                if rtype:
                    filters["type"] = rtype
                if value:
                    filters["value"] = value
                if keyword:
                    filters["keyword"] = keyword
                res = dnspod.list_records(zone_id, page, page_size, filters)
                records_raw = res.get("records") if isinstance(res, dict) else []
                records = [self._map_dnspod_record(zone_id, zone_name, r) for r in records_raw if isinstance(r, dict)]
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
            code = e.status if isinstance(e, (CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/batch-status", sub)
    if self.command == "PUT" and m:
        if is_cf:
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
                dnspod.set_record_status(zone_id, rid, bool(enabled))
                results.append({"recordId": rid, "success": True})
            except Exception as e:
                results.append({"recordId": rid, "success": False, "error": str(e)})
        success_count = len([x for x in results if x.get("success")])
        failed_count = len(results) - success_count
        cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
        self._ok({"successCount": success_count, "failedCount": failed_count, "results": results}, "批量状态更新完成（部分失败）" if failed_count else "批量状态更新成功")
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/([^/]+)", sub)
    if self.command == "GET" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        try:
            if is_cf:
                zone = cf.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                record = cf.get_record(zone_id, record_id)
                self._ok({"record": self._map_cf_record(zone_id, zone_name, record)}, "获取记录详情成功")
            else:
                zone = dnspod.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                record = dnspod.get_record(zone_id, record_id)
                self._ok({"record": self._map_dnspod_record(zone_id, zone_name, record)}, "获取记录详情成功")
        except Exception as e:
            code = e.status if isinstance(e, (CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
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
            if is_cf:
                zone = cf.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                payload = {
                    "type": rtype,
                    "name": name,
                    "content": self._normalize_txt_for_cf(rtype, value),
                    "ttl": int(body.get("ttl")) if isinstance(body.get("ttl"), (int, float)) else 1,
                    "priority": int(body.get("priority")) if isinstance(body.get("priority"), (int, float)) else None,
                    "comment": body.get("remark"),
                }
                if rtype in {"A", "AAAA", "CNAME"} and isinstance(body.get("proxied"), bool):
                    payload["proxied"] = bool(body.get("proxied"))
                record = cf.create_record(zone_id, payload)
                mapped = self._map_cf_record(zone_id, zone_name, record)
            else:
                zone = dnspod.get_zone(zone_id)
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
                }
                record = dnspod.create_record(zone_id, params)
                mapped = self._map_dnspod_record(zone_id, zone_name, record)
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
            code = e.status if isinstance(e, (CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/([^/]+)", sub)
    if self.command == "PUT" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        try:
            if is_cf:
                zone = cf.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                old = None
                try:
                    old = cf.get_record(zone_id, record_id)
                except Exception:
                    old = None
                base = old if isinstance(old, dict) else {}
                rtype = str(body.get("type") or base.get("type") or "").strip().upper()
                name = str(body.get("name") or base.get("name") or "").strip()
                value = body.get("value", base.get("content"))
                if not name or not rtype or value is None:
                    self._err("缺少必需参数: name, type, value", 400)
                    return
                payload = {
                    "type": rtype,
                    "name": name,
                    "content": self._normalize_txt_for_cf(rtype, value),
                    "ttl": int(body.get("ttl")) if isinstance(body.get("ttl"), (int, float)) else int(base.get("ttl") or 1),
                    "priority": int(body.get("priority")) if isinstance(body.get("priority"), (int, float)) else base.get("priority"),
                    "comment": body.get("remark") if "remark" in body else base.get("comment"),
                }
                if rtype in {"A", "AAAA", "CNAME"}:
                    if isinstance(body.get("proxied"), bool):
                        payload["proxied"] = bool(body.get("proxied"))
                    elif isinstance(base.get("proxied"), bool):
                        payload["proxied"] = bool(base.get("proxied"))
                record = cf.update_record(zone_id, record_id, payload)
                mapped = self._map_cf_record(zone_id, zone_name, record)
            else:
                zone = dnspod.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                old = None
                try:
                    old_rec = dnspod.get_record(zone_id, record_id)
                    old = old_rec
                except Exception:
                    old = None
                params = {
                    "name": body.get("name"),
                    "type": body.get("type"),
                    "value": str(body["value"]) if "value" in body else None,
                    "ttl": int(body.get("ttl")) if isinstance(body.get("ttl"), (int, float)) else None,
                    "priority": int(body.get("priority")) if isinstance(body.get("priority"), (int, float)) else None,
                    "weight": int(body.get("weight")) if isinstance(body.get("weight"), (int, float)) else None,
                    "line": body.get("line"),
                    "remark": body.get("remark") if "remark" in body else None,
                }
                record = dnspod.update_record(zone_id, record_id, params)
                mapped = self._map_dnspod_record(zone_id, zone_name, record)
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
            self._ok({"record": mapped}, "DNS 记录更新成功")
        except Exception as e:
            try:
                create_log(user_id=uid, action="UPDATE", resource_type="DNS", status="FAILED", error_message=str(e), ip_address=ip)
            except Exception:
                pass
            code = e.status if isinstance(e, (CloudflareApiError, DnspodApiError)) else 400
            self._err(str(e), code)
        return

    m = re.fullmatch(r"/zones/([^/]+)/records/([^/]+)", sub)
    if self.command == "DELETE" and m:
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        try:
            if is_cf:
                zone = cf.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                old = None
                try:
                    old = cf.get_record(zone_id, record_id)
                except Exception:
                    old = None
                cf.delete_record(zone_id, record_id)
            else:
                zone = dnspod.get_zone(zone_id)
                zone_name = str(zone.get("name") or zone_id)
                old = None
                try:
                    old = dnspod.get_record(zone_id, record_id)
                except Exception:
                    old = None
                dnspod.delete_record(zone_id, record_id)
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
            cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
            self._ok(None, "DNS 记录删除成功")
        except Exception as e:
            try:
                create_log(user_id=uid, action="DELETE", resource_type="DNS", status="FAILED", error_message=str(e), ip_address=ip)
            except Exception:
                pass
            code = e.status if isinstance(e, (CloudflareApiError, DnspodApiError)) else 400
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
                    if is_cf:
                        old = cf.get_record(zone_id, rid)
                    else:
                        old = dnspod.get_record(zone_id, rid)
                except Exception:
                    old = None
                if is_cf:
                    cf.delete_record(zone_id, rid)
                else:
                    dnspod.delete_record(zone_id, rid)
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
        if is_cf:
            self._err("当前提供商不支持启用/禁用记录", 400)
            return
        zone_id = urllib.parse.unquote(m.group(1))
        record_id = urllib.parse.unquote(m.group(2))
        enabled = body.get("enabled")
        if enabled is None:
            self._err("缺少参数: enabled (boolean)", 400)
            return
        try:
            dnspod.set_record_status(zone_id, record_id, bool(enabled))
            cache_delete_pattern(f"dns:records:cred:{ctx['credential']['id']}:z:{zone_id}:*")
            self._ok(None, "记录状态更新成功")
        except (DnspodApiError,) as e:
            self._err(str(e), e.status)
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
        if is_cf:
            data = {"lines": [{"code": "default", "name": "默认"}]}
            cache_set(ck, data, 3600)
            self._ok(data, "获取线路列表成功")
        else:
            try:
                lines = dnspod.get_lines(zone_id)
                data = {"lines": lines}
                cache_set(ck, data, 3600)
                self._ok(data, "获取线路列表成功")
            except (DnspodApiError,) as e:
                self._err(str(e), e.status)
        return

    m = re.fullmatch(r"/zones/([^/]+)/min-ttl", sub)
    if self.command == "GET" and m:
        if is_cf:
            self._ok({"minTTL": 1}, "获取最低TTL成功")
        else:
            zone_id = urllib.parse.unquote(m.group(1))
            try:
                min_ttl = dnspod.get_min_ttl(zone_id)
                self._ok({"minTTL": min_ttl}, "获取最低TTL成功")
            except (DnspodApiError,) as e:
                self._err(str(e), e.status)
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


def _ssl_routes(self, path: str, q: Dict[str, List[str]], b: bytes) -> None:
    u = self._auth()
    if not u:
        return
    uid = int(u.get("id") or 0)
    if uid <= 0:
        self._err("无效用户", 401)
        return

    sub = path[len("/api/ssl"):]
    body = self._json_body(b)

    def _get_cred_id(source: Any = None) -> str | None:
        v = source if source is not None else (body.get("credentialId") or first_or_none(q, "credentialId"))
        return str(v).strip() if v else None

    def _ssl_api(cred_id_raw: str | None):
        ctx = self._ssl_context(uid, cred_id_raw)
        return ctx["credential"], ctx["api"]

    def _invalidate(cred_id: int) -> None:
        cache_delete_pattern(f"ssl:*:cred:{cred_id}:*")
        cache_delete_pattern(f"ssl:*:{cred_id}:*")

    def _sync_to_db(cred_id: int, provider: str, certs: list) -> None:
        """Upsert remote certificates into local ssl_certificates table."""
        ts = now_iso()
        with conn() as c:
            for cert in certs:
                remote_id = cert.get("remoteCertId", "")
                if not remote_id:
                    continue
                existing = c.execute(
                    "SELECT id FROM ssl_certificates WHERE userId = ? AND provider = ? AND remoteCertId = ?",
                    (uid, provider, remote_id),
                ).fetchone()
                if existing:
                    c.execute(
                        """UPDATE ssl_certificates SET
                            domain = ?, san = ?, certType = ?, productName = ?,
                            status = ?, statusMsg = ?, issuer = ?,
                            notBefore = ?, notAfter = ?, isUploaded = ?,
                            remoteCreatedAt = ?, syncedAt = ?, updatedAt = ?
                        WHERE id = ?""",
                        (
                            cert.get("domain", ""),
                            json.dumps(cert.get("san") or [], ensure_ascii=False) if isinstance(cert.get("san"), list) else str(cert.get("san") or ""),
                            cert.get("certType", ""),
                            cert.get("productName", ""),
                            cert.get("status", "applying"),
                            cert.get("statusMsg", ""),
                            cert.get("issuer", ""),
                            cert.get("notBefore", ""),
                            cert.get("notAfter", ""),
                            1 if cert.get("isUploaded") else 0,
                            cert.get("remoteCreatedAt", ""),
                            ts,
                            ts,
                            existing["id"],
                        ),
                    )
                else:
                    c.execute(
                        """INSERT INTO ssl_certificates
                            (userId, credentialId, provider, remoteCertId, domain, san,
                             certType, productName, status, statusMsg, issuer,
                             notBefore, notAfter, isUploaded, remoteCreatedAt, syncedAt, createdAt, updatedAt)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            uid, cred_id, provider, remote_id,
                            cert.get("domain", ""),
                            json.dumps(cert.get("san") or [], ensure_ascii=False) if isinstance(cert.get("san"), list) else str(cert.get("san") or ""),
                            cert.get("certType", ""),
                            cert.get("productName", ""),
                            cert.get("status", "applying"),
                            cert.get("statusMsg", ""),
                            cert.get("issuer", ""),
                            cert.get("notBefore", ""),
                            cert.get("notAfter", ""),
                            1 if cert.get("isUploaded") else 0,
                            cert.get("remoteCreatedAt", ""),
                            ts, ts, ts,
                        ),
                    )
            c.commit()

    try:
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

            # ── Aggregated multi-credential view ──
            if cred_id_raw == "all":
                with conn() as c:
                    cred_rows = c.execute(
                        "SELECT id, name, provider, secrets FROM dns_credentials WHERE userId = ? AND provider IN ('dnspod', 'tencent_ssl')",
                        (uid,),
                    ).fetchall()
                all_certs: list = []
                errors: list = []
                for cr in cred_rows:
                    cr_secrets = self._credential_secrets(cr)
                    sid = str(cr_secrets.get("secretId") or "").strip()
                    skey = str(cr_secrets.get("secretKey") or "").strip()
                    if not sid or not skey:
                        continue
                    if filter_cred and str(cr["id"]) != filter_cred:
                        continue
                    try:
                        cr_api = TencentSslApi(sid, skey)
                        r = cr_api.list_certificates(offset=0, limit=100, search_key=search or None)
                        for cert in r.get("certificates", []):
                            cert["credentialId"] = cr["id"]
                            cert["credentialName"] = cr["name"]
                        all_certs.extend(r.get("certificates", []))
                    except Exception as ex:
                        errors.append({"credentialId": cr["id"], "name": cr["name"], "error": str(ex)})
                all_certs.sort(key=lambda x: x.get("remoteCreatedAt", ""), reverse=True)
                total = len(all_certs)
                offset = (page_num - 1) * limit
                paged = all_certs[offset:offset + limit]
                resp_body: Dict[str, Any] = {
                    "success": True,
                    "message": "获取证书列表成功（聚合）",
                    "data": paged,
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
                certs_out.append(c2)
            cache_set(cache_k, result, 120)
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

        # POST /api/ssl/certificates/upload — upload third-party cert
        if self.command == "POST" and sub == "/certificates/upload":
            cred_id_raw = _get_cred_id()
            pub_key = str(body.get("publicKey") or "").strip()
            priv_key = str(body.get("privateKey") or "").strip()
            alias = str(body.get("alias") or "").strip() or None
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            if not pub_key or not priv_key:
                self._err("缺少证书公钥或私钥", 400)
                return
            cred_row, api = _ssl_api(cred_id_raw)
            result = api.upload_certificate(pub_key, priv_key, alias)
            _invalidate(int(cred_row["id"]))
            self._ok(result, "证书上传成功", 201)
            return

        # DELETE /api/ssl/certificates/<id> — delete
        m = re.fullmatch(r"/certificates/([^/]+)", sub)
        if self.command == "DELETE" and m:
            cert_id = urllib.parse.unquote(m.group(1))
            cred_id_raw = _get_cred_id(first_or_none(q, "credentialId"))
            if not cred_id_raw:
                self._err("缺少 credentialId 参数", 400)
                return
            cred_row, api = _ssl_api(cred_id_raw)
            api.delete_certificate(cert_id)
            cred_id = int(cred_row["id"])
            with conn() as c:
                c.execute(
                    "DELETE FROM ssl_certificates WHERE userId = ? AND credentialId = ? AND remoteCertId = ?",
                    (uid, cred_id, cert_id),
                )
                c.commit()
            _invalidate(cred_id)
            self._ok(None, "证书已删除")
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

            _sync_to_db(cred_id, "tencent_ssl", all_certs)
            _invalidate(cred_id)
            self._ok({"synced": len(all_certs)}, f"同步完成，共 {len(all_certs)} 个证书")
            return

        # POST /api/ssl/certificates/renew-expired — auto-renew expiring certs
        if self.command == "POST" and sub == "/certificates/renew-expired":
            from datetime import datetime, timedelta
            import time as _time
            renew_days = int(body.get("renewDays") or 30)
            dns_credential_id = body.get("dnsCredentialId")
            now_dt = datetime.utcnow()
            threshold_dt = now_dt.replace(tzinfo=timezone.utc) + timedelta(days=renew_days)
            threshold = threshold_dt.isoformat().replace("+00:00", "Z")

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
                        if not not_after:
                            continue
                        # Normalize notAfter for comparison (may be "2025-06-15 08:00:00" or "2025-06-15")
                        not_after_cmp = not_after if " " in not_after else not_after + " 00:00:00"
                        # Skip if not expired / not expiring within threshold
                        if not_after_cmp > threshold and status == "issued":
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
                            if old_cert_id and status == "issued" and not_after_cmp <= threshold:
                                # If already expired, OldCertificateId renewal is not supported.
                                if not_after_cmp >= now_dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"):
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

            total_renewed = len(renewed)
            msg = f"续期检查完成：{total_renewed} 个已续期"
            if failed:
                msg += f"，{len(failed)} 个失败"
            if skipped:
                msg += f"，{len(skipped)} 个跳过"
            self._ok({"renewed": renewed, "failed": failed, "skipped": skipped}, msg)
            return

        self._err("接口不存在", 404)
    except TencentSslApiError as e:
        self._err(str(e), int(e.status or 400))
    except ValueError as e:
        self._err(str(e), 400)
    except Exception as e:
        self._err(str(e), 500)

