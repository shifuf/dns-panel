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


def _safe_dir_name(domain: str) -> str:
    """Filesystem-safe name for our managed cert dir (wildcards contain '*')."""
    return normalize_domain(domain).replace("*", "_wildcard_")


def _deployed_dir(primary: str) -> Path:
    return Path(ACME_HOME) / "deployed" / _safe_dir_name(primary)


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
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

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
        norm = [normalize_domain(d) for d in domains if normalize_domain(d)]
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
    ) -> Dict[str, Any]:
        """Force-renew an existing cert and re-read the refreshed PEM."""
        p = normalize_domain(primary)
        if not p:
            raise AcmeApiError("缺少域名", 400)
        env: Dict[str, str] = {}
        if provider and secrets is not None:
            # Re-supply creds in case acme.sh's saved conf is stale.
            try:
                _, env = dns_plugin_env(provider, secrets, account_id)
            except AcmeApiError:
                env = {}
        args = ["--renew", "-d", p, "--force"] + self._ecc_args()
        with _ACME_LOCK:
            proc = _run(args, env, timeout=600)
            if proc.returncode not in (0, 2):
                raise AcmeApiError(f"续期失败：{_tail(proc.stdout + chr(10) + proc.stderr)}", 502)
            return self._install_and_read(p, env)

    def _install_and_read(self, primary: str, env: Dict[str, str]) -> Dict[str, Any]:
        """Copy issued cert to a deterministic dir we control, then parse it."""
        out_dir = _deployed_dir(primary)
        out_dir.mkdir(parents=True, exist_ok=True)
        fullchain = out_dir / "fullchain.pem"
        privkey = out_dir / "privkey.pem"
        args = [
            "--install-cert", "-d", primary,
            "--key-file", str(privkey),
            "--fullchain-file", str(fullchain),
        ] + self._ecc_args()
        proc = _run(args, env, timeout=120)
        if proc.returncode != 0 or not fullchain.exists() or not privkey.exists():
            raise AcmeApiError(f"证书安装失败：{_tail(proc.stdout + chr(10) + proc.stderr)}", 502)
        pub = fullchain.read_text(encoding="utf-8", errors="replace")
        meta = parse_cert_pem(pub)
        meta["primary"] = primary
        return meta

    def read_pem(self, primary: str) -> Dict[str, str]:
        """Return {publicKey, privateKey} for a previously issued cert."""
        p = normalize_domain(primary)
        out_dir = _deployed_dir(p)
        fullchain = out_dir / "fullchain.pem"
        privkey = out_dir / "privkey.pem"
        if not fullchain.exists() or not privkey.exists():
            raise AcmeApiError("证书文件不存在（可能尚未签发成功）", 404)
        return {
            "publicKey": fullchain.read_text(encoding="utf-8", errors="replace"),
            "privateKey": privkey.read_text(encoding="utf-8", errors="replace"),
        }

    def remove(self, primary: str) -> None:
        """Unregister from acme.sh auto-renew and delete local cert files."""
        p = normalize_domain(primary)
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
