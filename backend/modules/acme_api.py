from __future__ import annotations

"""acme.sh integration — issue / renew / read / remove Let's Encrypt certs via DNS-01.

Unlike ``tencent_ssl_api`` (which talks to a cloud HTTP API), this module shells
out to the ``acme.sh`` program. The DNS-01 challenge is handled entirely by
acme.sh's own DNS plugins; we just translate an existing panel DNS credential
(cloudflare / dnspod / aliyun ...) into the environment variables each plugin
expects.

State (account keys + issued certs) lives under ``ACME_HOME`` which points at the
mounted ``/app/db`` volume so it survives container restarts/upgrades. Cert
metadata (notBefore / notAfter / SAN) is parsed from the PEM with ``cryptography``
(already a project dependency) rather than scraped from acme.sh stdout.

acme.sh is a Unix shell program; on Windows (local dev) it is absent and every
operation raises a clear ``AcmeApiError`` so the rest of the panel keeps working.
"""

import os
import re
import shutil
import subprocess
import threading
from datetime import timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class AcmeApiError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = int(status)


# ── Configuration (overridable via env) ──────────────────────────────
# Where the acme.sh program is installed inside the backend image.
_ACME_BIN_CANDIDATES = [
    os.getenv("ACME_SH_BIN", "").strip(),
    "/opt/acme.sh/acme.sh",
    str(Path.home() / ".acme.sh" / "acme.sh"),
    "acme.sh",
]
# Persisted state dir (account keys + issued certs). Lives on the db volume.
ACME_HOME = (os.getenv("ACME_HOME", "").strip() or "/app/db/acme")
# CA: Let's Encrypt (no email/registration friction).
ACME_CA_SERVER = (os.getenv("ACME_CA_SERVER", "").strip() or "letsencrypt")

# Panel DNS providers we can map to an acme.sh DNS plugin.
ACME_SUPPORTED_DNS_PROVIDERS: Tuple[str, ...] = (
    "cloudflare",
    "dnspod",
    "dnspod_token",
    "aliyun",
)

# Serialize issue/renew: acme.sh is not safe to run concurrently against the
# same home dir, and DNS-01 propagation waits make these long anyway.
_ACME_LOCK = threading.Lock()


def _find_acme_bin() -> Optional[str]:
    for cand in _ACME_BIN_CANDIDATES:
        if not cand:
            continue
        if cand == "acme.sh":
            found = shutil.which("acme.sh")
            if found:
                return found
            continue
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def acme_available() -> bool:
    """True when acme.sh can be invoked (i.e. running in the Docker image)."""
    return _find_acme_bin() is not None


def normalize_domain(domain: str) -> str:
    d = str(domain or "").strip().lower().rstrip(".")
    d = re.sub(r"^https?://", "", d)
    d = d.split("/", 1)[0]
    d = re.sub(r":\d+$", "", d)
    return d


def validate_domain(domain: str) -> str:
    """Return a canonical DNS name and reject filesystem/argument abuse."""
    d = normalize_domain(domain)
    if not d or len(d) > 253 or any(ch in d for ch in ("/", "\\", "\x00")) or ".." in d:
        raise AcmeApiError(f"无效域名: {domain}", 400)
    wildcard = d.startswith("*.")
    host = d[2:] if wildcard else d
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except Exception:
        raise AcmeApiError(f"无效域名: {domain}", 400)
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise AcmeApiError(f"无效域名: {domain}", 400)
    return ("*." if wildcard else "") + ascii_host


def _safe_dir_name(domain: str) -> str:
    """Filesystem-safe name for our managed cert dir (wildcards contain '*')."""
    return validate_domain(domain).replace("*", "_wildcard_")


def _deployed_dir(primary: str) -> Path:
    root = (Path(ACME_HOME) / "deployed").resolve()
    target = (root / _safe_dir_name(primary)).resolve()
    if target.parent != root:
        raise AcmeApiError("证书目录越界", 400)
    return target


def _tail(text: str, lines: int = 12) -> str:
    parts = [ln for ln in (text or "").splitlines() if ln.strip()]
    return "\n".join(parts[-lines:]).strip() or "（无输出）"


# ── DNS credential → acme.sh plugin + env mapping ─────────────────────

def dns_plugin_env(
    provider: str,
    secrets: Dict[str, Any],
    account_id: str = "",
) -> Tuple[str, Dict[str, str]]:
    """Map a panel DNS credential to (acme.sh dns plugin name, env vars)."""
    p = str(provider or "").strip().lower()
    env: Dict[str, str] = {}

    if p == "cloudflare":
        token = str(secrets.get("apiToken") or "").strip()
        if not token:
            raise AcmeApiError("Cloudflare 凭证缺少 API Token", 400)
        env["CF_Token"] = token
        if account_id:
            env["CF_Account_ID"] = str(account_id).strip()
        return "dns_cf", env

    if p in ("dnspod", "dnspod_token"):
        token_id = str(secrets.get("tokenId") or "").strip()
        token = str(secrets.get("token") or "").strip()
        sid = str(secrets.get("secretId") or "").strip()
        skey = str(secrets.get("secretKey") or "").strip()
        # Prefer DNSPod token (DP_Id/DP_Key); fall back to TC3 → dns_tencent.
        if token_id and token:
            env["DP_Id"] = token_id
            env["DP_Key"] = token
            return "dns_dp", env
        if token and "," in token:
            tid, _, tk = token.partition(",")
            if tid.strip() and tk.strip():
                env["DP_Id"] = tid.strip()
                env["DP_Key"] = tk.strip()
                return "dns_dp", env
        if sid and skey:
            env["Tencent_SecretId"] = sid
            env["Tencent_SecretKey"] = skey
            return "dns_tencent", env
        raise AcmeApiError("DNSPod 凭证缺少 TokenId/Token 或 SecretId/SecretKey", 400)

    if p == "aliyun":
        ak = str(secrets.get("accessKeyId") or "").strip()
        sk = str(secrets.get("accessKeySecret") or "").strip()
        if not ak or not sk:
            raise AcmeApiError("阿里云凭证缺少 AccessKeyId / AccessKeySecret", 400)
        env["Ali_Key"] = ak
        env["Ali_Secret"] = sk
        return "dns_ali", env

    raise AcmeApiError(f"acme.sh 暂不支持使用 {provider} 凭证进行 DNS 验证", 400)


# ── Certificate PEM parsing (via cryptography) ────────────────────────

def parse_cert_pem(pem_text: str) -> Dict[str, Any]:
    """Extract notBefore / notAfter / SAN from a PEM cert (leaf = first block)."""
    try:
        from cryptography import x509
    except Exception as e:  # pragma: no cover - dependency always present
        raise AcmeApiError(f"无法解析证书（缺少 cryptography）: {e}", 500)

    text = pem_text or ""
    # fullchain.pem contains multiple certs; the leaf is the first block.
    first = text
    marker = "-----END CERTIFICATE-----"
    idx = text.find(marker)
    if idx != -1:
        first = text[: idx + len(marker)]
    try:
        cert = x509.load_pem_x509_certificate(first.encode("utf-8"))
    except Exception as e:
        raise AcmeApiError(f"证书解析失败: {e}", 502)

    def _fmt(dt) -> str:
        if dt is None:
            return ""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

    san: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = list(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        san = []

    issuer = ""
    try:
        from cryptography.x509.oid import NameOID
        attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if attrs:
            issuer = str(attrs[0].value)
        if not issuer:
            cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer = str(cn[0].value) if cn else ""
    except Exception:
        issuer = ""

    return {
        "notBefore": _fmt(not_before),
        "notAfter": _fmt(not_after),
        "san": san,
        "issuer": issuer or "Let's Encrypt",
    }


# ── acme.sh invocation ────────────────────────────────────────────────

def _run(args: List[str], env_extra: Dict[str, str], timeout: int = 600) -> subprocess.CompletedProcess:
    bin_path = _find_acme_bin()
    if not bin_path:
        raise AcmeApiError("acme.sh 未安装，签发功能仅在 Docker 部署环境可用", 503)
    Path(ACME_HOME).mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(env_extra or {})
    env["LE_WORKING_DIR"] = ACME_HOME
    cmd = [bin_path, "--home", ACME_HOME] + list(args)
    try:
        return subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise AcmeApiError("acme.sh 执行超时（DNS 传播过慢或网络异常）", 504)
    except Exception as e:
        raise AcmeApiError(f"acme.sh 执行失败: {e}", 500)


class AcmeService:
    """Stateless helper around acme.sh for one panel user/credential."""

    def __init__(self, key_length: str = "2048") -> None:
        kl = str(key_length or "2048").strip() or "2048"
        self.key_length = kl
        self.is_ecc = kl.lower().startswith("ec")

    def _ecc_args(self) -> List[str]:
        return ["--ecc"] if self.is_ecc else []

    def issue(
        self,
        domains: List[str],
        provider: str,
        secrets: Dict[str, Any],
        account_id: str = "",
    ) -> Dict[str, Any]:
        """Issue (or re-issue) a cert for ``domains`` (domains[0] = primary)."""
        if len(domains or []) > 100:
            raise AcmeApiError("单张证书最多支持 100 个域名", 400)
        norm = [validate_domain(d) for d in domains]
        if not norm:
            raise AcmeApiError("缺少有效域名", 400)
        primary = norm[0]
        plugin, env = dns_plugin_env(provider, secrets, account_id)

        args = ["--issue", "--dns", plugin, "--server", ACME_CA_SERVER, "--keylength", self.key_length]
        for d in norm:
            args += ["-d", d]
        with _ACME_LOCK:
            proc = _run(args, env, timeout=600)
            # acme.sh exits 0 on success; 2 means "skipped, not yet time to renew"
            # for an existing valid cert — treat that as success and just read it.
            if proc.returncode not in (0, 2):
                raise AcmeApiError(f"签发失败：{_tail(proc.stdout + chr(10) + proc.stderr)}", 502)
            return self._install_and_read(primary, env)

    def renew(
        self,
        primary: str,
        provider: str = "",
        secrets: Optional[Dict[str, Any]] = None,
        account_id: str = "",
        domains: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Force-renew an existing cert and re-read the refreshed PEM.

        Falls back to a fresh ``--issue`` when acme.sh has no renewal config
        for the domain (state wiped / cert only exists as files), so renewals
        never get stuck on a missing conf.
        """
        p = validate_domain(primary)
        if not p:
            raise AcmeApiError("缺少域名", 400)
        env: Dict[str, str] = {}
        plugin = ""
        if provider and secrets is not None:
            # Re-supply creds in case acme.sh's saved conf is stale.
            try:
                plugin, env = dns_plugin_env(provider, secrets, account_id)
            except AcmeApiError:
                env = {}
        args = ["--renew", "-d", p, "--force"] + self._ecc_args()
        with _ACME_LOCK:
            proc = _run(args, env, timeout=600)
            if proc.returncode not in (0, 2):
                # No renewal conf (or corrupt) → issue anew with the same names
                # and credentials instead of failing the renewal outright.
                if plugin:
                    names = [validate_domain(d) for d in (domains or [p])] or [p]
                    if p not in names:
                        names.insert(0, p)
                    issue_args = ["--issue", "--dns", plugin, "--server", ACME_CA_SERVER, "--keylength", self.key_length]
                    for d in names:
                        issue_args += ["-d", d]
                    retry = _run(issue_args, env, timeout=600)
                    if retry.returncode in (0, 2):
                        return self._install_and_read(p, env)
                    raise AcmeApiError(f"续期失败（且无法重新签发）：{_tail(retry.stdout + chr(10) + retry.stderr)}", 502)
                raise AcmeApiError(f"续期失败：{_tail(proc.stdout + chr(10) + proc.stderr)}", 502)
            return self._install_and_read(p, env)

    def _install_files(self, primary: str, env: Dict[str, str]) -> Tuple[Path, Path]:
        """Materialize acme.sh's current certificate into the panel-owned path.

        acme.sh keeps the source certificate under ``ACME_HOME`` while the panel
        serves a stable copy under ``deployed``.  Re-running ``--install-cert``
        is intentionally idempotent and repairs the common case where the
        deployed copy was removed during a container upgrade.  When
        ``--install-cert`` itself fails (saved conf lost its hooks), the files
        are copied straight from acme.sh's cert store instead.
        """
        out_dir = _deployed_dir(primary)
        out_dir.mkdir(parents=True, exist_ok=True)
        fullchain = out_dir / "fullchain.pem"
        privkey = out_dir / "privkey.pem"
        args = [
            "--install-cert", "-d", primary,
            "--key-file", str(privkey),
            "--fullchain-file", str(fullchain),
        ] + self._ecc_args()
        proc: Optional[subprocess.CompletedProcess] = None
        try:
            proc = _run(args, env, timeout=120)
        except AcmeApiError:
            proc = None
        done = (
            proc is not None
            and proc.returncode == 0
            and fullchain.is_file() and privkey.is_file()
            and fullchain.stat().st_size > 0 and privkey.stat().st_size > 0
        )
        if not done:
            store = self._store_files(primary)
            if store is not None:
                src_full, src_key = store
                try:
                    fullchain.write_text(src_full.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
                    privkey.write_text(src_key.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
                    done = True
                except Exception:
                    done = False
        if not done:
            tail = _tail((proc.stdout + chr(10) + proc.stderr) if proc is not None else "acme.sh 执行失败")
            raise AcmeApiError(f"证书安装失败：{tail}", 502)
        return fullchain, privkey

    def _install_and_read(self, primary: str, env: Dict[str, str]) -> Dict[str, Any]:
        """Copy issued cert to a deterministic dir we control, then parse it."""
        fullchain, _ = self._install_files(primary, env)
        pub = fullchain.read_text(encoding="utf-8", errors="replace")
        meta = parse_cert_pem(pub)
        meta["primary"] = primary
        return meta

    def files_exist(self, primary: str) -> bool:
        """Whether the panel-managed PEM pair is present and non-empty."""
        p = validate_domain(primary)
        out_dir = _deployed_dir(p)
        fullchain = out_dir / "fullchain.pem"
        privkey = out_dir / "privkey.pem"
        return bool(fullchain.is_file() and privkey.is_file() and fullchain.stat().st_size and privkey.stat().st_size)

    def _store_files(self, primary: str) -> Optional[Tuple[Path, Path]]:
        """Locate the certificate straight inside acme.sh's own state dir.

        acme.sh keeps the issued files at ``ACME_HOME/<domain>[_ecc]/`` —
        ``fullchain.cer`` plus ``<domain>.key``. Reading them directly makes
        downloads work even when ``--install-cert`` cannot run (e.g. the saved
        conf lost its install hooks or the deployed copy was pruned), which is
        what previously produced a misleading "证书不存在" on valid certs.
        """
        p = validate_domain(primary)
        base = Path(ACME_HOME)
        # Search the directory matching this service's key type first; a stale
        # directory from the other key type could otherwise shadow it.
        dirs = [base / f"{p}_ecc", base / p] if self.is_ecc else [base / p, base / f"{p}_ecc"]
        for d in dirs:
            if not d.is_dir():
                continue
            full = next((f for f in (d / "fullchain.cer", d / f"{p}.cer", d / "fullchain.pem")
                         if f.is_file() and f.stat().st_size), None)
            key = next((f for f in (d / f"{p}.key", d / "privkey.pem")
                        if f.is_file() and f.stat().st_size), None)
            if full is not None and key is not None:
                return full, key
        return None

    def read_pem(self, primary: str) -> Dict[str, str]:
        """Return {publicKey, privateKey} for a previously issued cert.

        Recovery order: the panel-owned deployed copy → ``--install-cert``
        re-materialization (which itself falls back to acme.sh's own cert
        store). Works after container upgrades without re-issuing.
        """
        p = validate_domain(primary)
        out_dir = _deployed_dir(p)
        fullchain = out_dir / "fullchain.pem"
        privkey = out_dir / "privkey.pem"
        if not fullchain.is_file() or not privkey.is_file() or fullchain.stat().st_size == 0 or privkey.stat().st_size == 0:
            # Recover the stable copy from acme.sh's persistent account/state.
            try:
                fullchain, privkey = self._install_files(p, {})
            except AcmeApiError as exc:
                raise AcmeApiError("证书文件不存在，且无法从 acme.sh 状态恢复（可能尚未签发成功）", 404) from exc
        return {
            "publicKey": fullchain.read_text(encoding="utf-8", errors="replace"),
            "privateKey": privkey.read_text(encoding="utf-8", errors="replace"),
        }

    def remove(self, primary: str) -> None:
        """Unregister from acme.sh auto-renew and delete local cert files."""
        p = validate_domain(primary)
        # Best effort — never block deletion of the DB row on acme.sh errors.
        if acme_available():
            try:
                _run(["--remove", "-d", p] + self._ecc_args(), {}, timeout=60)
            except AcmeApiError:
                pass
        for d in (_deployed_dir(p), Path(ACME_HOME) / p, Path(ACME_HOME) / f"{p}_ecc"):
            try:
                if d.exists():
                    shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass
