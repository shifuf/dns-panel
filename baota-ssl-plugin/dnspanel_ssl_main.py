#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------+
# | BaoTa Linux panel - DNS panel SSL certificate sync plugin         |
# | Pulls issued SSL certificates from the DNS panel and deploys them |
# | to the sites managed by this BaoTa instance.                      |
# +-------------------------------------------------------------------+
from __future__ import print_function

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import time

try:
    from urllib.parse import quote as urllib_quote
    from urllib.parse import urlsplit
except ImportError:
    from urlparse import urlsplit
    from urllib import quote as urllib_quote

try:
    from datetime import datetime, timezone
except ImportError:
    from datetime import datetime

    class _UTC(object):
        @staticmethod
        def utcnow():
            return datetime.utcnow()

    timezone = _UTC()

os.chdir("/www/server/panel")
sys.path.append("class/")
import public

__plugin_path = "/www/server/panel/plugin/dnspanel_ssl/"
__config = None
PLUGIN_VERSION = "1.8.0"
PLUGIN_LOG_TAG = "DNS panel SSL sync"

# ---------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------


def _get_config(key=None, force=False):
    """Read the plugin config.json (cached until force=True)."""
    global __config
    if not __config or force:
        config_file = __plugin_path + "config.json"
        if not os.path.exists(config_file):
            return None
        body = public.ReadFile(config_file)
        if not body:
            return None
        try:
            __config = json.loads(_as_text(body))
        except Exception:
            __config = {}
    if not isinstance(__config, dict):
        __config = {}
    if key:
        return __config.get(key)
    return __config


def _set_config(key=None, value=None):
    """Persist one config key (or the whole config when key is None)."""
    global __config
    if not isinstance(__config, dict):
        __config = {}
    if key:
        __config[key] = _json_safe(value)
    config_file = __plugin_path + "config.json"
    _atomic_write(config_file, json.dumps(__config, ensure_ascii=False))
    try:
        os.chmod(config_file, 0o600)
    except Exception:
        pass
    return True


def _as_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    return str(value)


def _write_log(message):
    """Best-effort BaoTa log write that can never break a plugin call."""
    try:
        public.WriteLog(PLUGIN_LOG_TAG, _as_text(message))
    except Exception:
        pass


def _json_safe(value, _depth=0):
    """Coerce a value into something json.dumps can always serialise."""
    if _depth > 12:
        return _as_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            out[_as_text(key)] = _json_safe(item, _depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item, _depth + 1) for item in value]
    try:
        json.dumps(value)
        return value
    except Exception:
        return _as_text(value)


def _to_int(value, default=None):
    """Best-effort int coercion for values coming from HTML form arguments."""
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _normalize_bool(value, default=False):
    """Coerce HTML form values (true / on / 1 / false) into a bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = _as_text(value).strip().lower()
    if text in ("", "undefined", "null", "none"):
        return default
    return text not in ("0", "false", "off", "no")


def _normalize_string_list(value):
    if isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        text = _as_text(value).strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            raw = parsed if isinstance(parsed, list) else text.split(",")
        except Exception:
            raw = text.split(",")
    result = []
    for item in raw:
        clean = _as_text(item).strip()
        if clean and clean not in result:
            result.append(clean)
    return result


def _atomic_write(path, content, mode=0o600):
    """Write through a temp file + rename so readers never see a partial file."""
    tmp = path + ".dnspanel.tmp"
    raw = content if isinstance(content, bytes) else _as_text(content).encode("utf-8")
    with open(tmp, "wb") as fh:
        fh.write(raw)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    try:
        os.replace(tmp, path)
    except AttributeError:
        os.rename(tmp, path)


def _safe_site_name(site_name):
    """Validate a BaoTa site name and prove it stays inside the cert root."""
    name = _as_text(site_name).strip()
    if not name or len(name) > 253 or not re.match(r"^[A-Za-z0-9._-]+$", name) or ".." in name:
        return None
    cert_root = os.path.realpath("/www/server/panel/vhost/cert")
    cert_dir = os.path.realpath(os.path.join(cert_root, name))
    if not cert_dir.startswith(cert_root + os.sep):
        return None
    return name


def _host_in_list(host_value, candidates):
    """True when a hostname (or wildcard) belongs to a candidate host list.

    Panel certificates cover names like *.example.com while an accelerated
    domain is the concrete host a.b.example.com, and the reverse happens too
    (certificate for example.com, accelerated host www.example.com), so both
    directions are checked. A wildcard only ever matches one extra label, which
    is the same rule the certificate coverage check uses.
    """
    host = _as_text(host_value).strip().lower().rstrip(".")
    if not host:
        return False
    for candidate in candidates or []:
        other = _as_text(candidate).strip().lower().rstrip(".")
        if not other:
            continue
        if host == other:
            return True
        bare = host[2:] if host.startswith("*.") else host
        base = other[2:] if other.startswith("*.") else other
        if bare == base:
            return True
        if bare.endswith("." + base) or base.endswith("." + bare):
            return True
    return False


def _names_cover_hosts(cert_names, hosts):
    """True when every host is covered by at least one name in cert_names."""
    if not hosts:
        return False
    for host in hosts:
        if not any(_name_covers(_as_text(name), _as_text(host)) for name in (cert_names or [])):
            return False
    return True


def _safe_cert_name(site_name):
    """A certificate file name built from a site name, proven to stay in cert root."""
    name = _as_text(site_name).strip().lstrip("*.").lower()
    if not name or len(name) > 253 or not re.match(r"^[a-z0-9._-]+$", name) or ".." in name:
        return None
    cert_root = os.path.realpath("/www/server/panel/vhost/cert")
    cert_dir = os.path.realpath(os.path.join(cert_root, name))
    if not cert_dir.startswith(cert_root + os.sep):
        return None
    return name


def _panel_host_of(url):
    """Hostname out of a panel server URL ('' when it cannot be parsed)."""
    text = _as_text(url).strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except Exception:
        return ""
    return _as_text(parsed.hostname).strip().lower().rstrip(".")


def _find_executable(candidates):
    for candidate in candidates:
        if not candidate:
            continue
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            path = os.path.join(directory, candidate)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
    return None


def _run_checked(command):
    """Run a command, returning (ok, combined_output_text)."""
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        return True, _as_text(output)
    except subprocess.CalledProcessError as exc:
        return False, _as_text(exc.output or b"")
    except Exception as exc:
        return False, str(exc)


def _plugin_tmp_path(prefix):
    """Temp file path for openssl scratch work (platform temp dir)."""
    import tempfile
    return os.path.join(tempfile.gettempdir(), prefix + "-" + str(os.getpid()) + ".pem")


def _parse_expiry(value):
    """Parse an ISO-8601 / panel timestamp into an aware UTC datetime."""
    if value is None:
        return None
    raw = _as_text(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except Exception:
        try:
            parsed = datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            try:
                parsed = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
            except Exception:
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _days_until(expiry):
    """Whole days until `expiry` (negative when already expired, None when unknown)."""
    if expiry is None:
        return None
    try:
        delta = (expiry - datetime.now(timezone.utc)).total_seconds()
    except Exception:
        return None
    return int(delta // 86400)


def _certificate_health(cert, renew_days=30):
    """Classify one certificate row as valid / expiring / expired / unknown."""
    days = _days_until(_parse_expiry((cert or {}).get("notAfter")))
    status = _as_text((cert or {}).get("status")).lower()
    if days is None:
        return {"state": "unknown", "daysRemaining": None, "needsRenewal": True, "reason": "无法解析证书到期时间"}
    if days < 0 or status == "expired":
        return {"state": "expired", "daysRemaining": days, "needsRenewal": True, "reason": "证书已过期"}
    if days <= int(renew_days or 30):
        return {"state": "expiring", "daysRemaining": days, "needsRenewal": True, "reason": "证书即将到期"}
    return {"state": "valid", "daysRemaining": days, "needsRenewal": False, "reason": "证书有效"}


def _days_remaining(cert):
    return _days_until(_parse_expiry((cert or {}).get("notAfter")))


def _cert_names_from_pem(pem_text):
    """Extract the SAN DNS names (fallback: CN) of a certificate PEM."""
    # Pure-Python first, so this works on a panel host with no openssl binary.
    parsed = _x509_summary(_as_text(pem_text))
    if parsed and parsed.get("names"):
        return list(parsed["names"])
    return _cert_names_from_openssl(pem_text)


def _cert_names_from_openssl(pem_text):
    """openssl fallback for SAN names when DER parsing is unavailable."""
    text = _as_text(pem_text)
    if "-----BEGIN CERTIFICATE-----" not in text:
        return []
    cert_tmp = _plugin_tmp_path("dnspanel-names")
    try:
        _atomic_write(cert_tmp, text)
        names = []
        ok, output = _run_checked([
            "openssl", "x509", "-in", cert_tmp, "-noout",
            "-ext", "subjectAltName",
        ])
        if ok:
            for token in re.split(r"[,\s]+", output):
                token = token.strip().lower().rstrip(".")
                if token.startswith("dns:"):
                    token = token[4:]
                if not token or "=" in token or "altname" in token:
                    continue
                if "." in token and token not in names:
                    names.append(token)
        if names:
            return names
        ok, output = _run_checked([
            "openssl", "x509", "-in", cert_tmp, "-noout", "-subject",
        ])
        if ok:
            match = re.search(r"CN\s*=\s*([^\n,/]+)", output)
            if match:
                return [match.group(1).strip().lower()]
        return []
    except Exception:
        return []
    finally:
        try:
            os.remove(cert_tmp)
        except Exception:
            pass




def _asn1_read(data, index):
    "Read one DER TLV. Returns (tag, value_start, value_end, next_index)."
    if index + 2 > len(data):
        return None
    tag = data[index]
    first = data[index + 1]
    if first < 0x80:
        length = first
        cursor = index + 2
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or index + 2 + count > len(data):
            return None
        length = int.from_bytes(data[index + 2:index + 2 + count], "big")
        cursor = index + 2 + count
    if cursor + length > len(data):
        return None
    return tag, cursor, cursor + length, cursor + length


def _asn1_list(data, start, end):
    "Every TLV inside [start, end), using each element's next index."
    items = []
    index = start
    while index < end:
        item = _asn1_read(data, index)
        if not item:
            break
        if item[3] <= index:
            break
        items.append(item)
        index = item[3]
    return items


def _asn1_oid_value(data, start, end):
    "Dotted-decimal text for a DER OBJECT IDENTIFIER value."
    if start >= end:
        return ""
    first = data[start]
    values = [first // 40, first % 40]
    current = 0
    started = False
    for byte in data[start + 1:end]:
        current = (current << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            values.append(current)
            current = 0
            started = False
    return ".".join(str(item) for item in values)



def _asn1_string(data, start, end):
    "Decode a DER string value (UTF-8 preferred, latin-1 fallback)."
    raw = bytes(data[start:end])
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding).strip()
        except Exception:
            continue
    return ""


def _asn1_date(data, tag, start, end):
    "UTCTime (tag 23) or GeneralizedTime (tag 24) to an aware UTC datetime."
    if tag not in (23, 24):
        return None
    text = "".join(char for char in bytes(data[start:end]).decode("ascii", "ignore") if char.isdigit())
    try:
        if tag == 23:
            if len(text) < 12:
                return None
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            month, day = int(text[2:4]), int(text[4:6])
            hour, minute, second = int(text[6:8]), int(text[8:10]), int(text[10:12])
        else:
            if len(text) < 14:
                return None
            year, month, day = int(text[0:4]), int(text[4:6]), int(text[6:8])
            hour, minute, second = int(text[8:10]), int(text[10:12]), int(text[12:14])
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except Exception:
        return None


def _asn1_attributes(data, start, end):
    "(OID, text) pairs for an X.501 Name (RDNSequence)."
    found = []
    for tag, rdns, rdne, _ in _asn1_list(data, start, end):
        if tag not in (0x30, 0x31):
            continue
        for attr_tag, as_, ae, _ in _asn1_list(data, rdns, rdne):
            if attr_tag != 0x30:
                continue
            pair = _asn1_list(data, as_, ae)
            if len(pair) < 2:
                continue
            oid_item, value_item = pair[0], pair[1]
            if oid_item[0] != 0x06:
                continue
            oid = _asn1_oid_value(data, oid_item[1], oid_item[2])
            text = _asn1_string(data, value_item[1], value_item[2])
            found.append((oid, text))
    return found



def _asn1_san(data, ext_start, ext_end):
    "DNS names (context tag 2) inside a subjectAltName extension value."
    names = []
    for item_tag, item_start, item_end, _ in _asn1_list(data, ext_start, ext_end):
        if item_tag != 0x30:
            continue
        for entry_tag, entry_start, entry_end, _ in _asn1_list(data, item_start, item_end):
            if entry_tag != 0x82:
                continue
            name = _asn1_string(data, entry_start, entry_end).lower().rstrip(".")
            if name and name not in names:
                names.append(name)
    return names


def _pem_first_der(pem_text):
    "DER bytes of the first CERTIFICATE block in a PEM text."
    text = _as_text(pem_text)
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    if begin not in text or end not in text:
        return None
    body = text.split(begin, 1)[1].split(end, 1)[0]
    body = "".join(body.split())
    if not body:
        return None
    try:
        return base64.b64decode(body)
    except Exception:
        return None



def _x509_summary(pem_text):
    "Parse a certificate PEM in pure Python: names, expiry and issuer."
    ""
    "BaoTa's panel Python runs with a minimal PATH and the host frequently has"
    "no openssl binary, so shelling out made every certificate unreadable and"
    "every site looked undeployed. This reads the DER directly instead, and"
    "openssl is only a last-resort fallback."
    ""
    "Returns {names, expiry, subject_cn, subject_org, issuer_cn, issuer_org}"
    "or None when the bytes are not a parseable certificate."
    ""
    der = _pem_first_der(pem_text)
    if not der:
        return None
    try:
        top = _asn1_read(der, 0)
        if not top or top[0] != 0x30:
            return None
        certificate = _asn1_list(der, top[1], top[2])
        if len(certificate) < 3 or certificate[0][0] != 0x30:
            return None
        tbs_tag, tbs_start, tbs_end, _ = certificate[0]
        tbs = _asn1_list(der, tbs_start, tbs_end)
        offset = 1 if tbs and tbs[0][0] == 0xA0 else 0
        if len(tbs) < offset + 5:
            return None
        issuer_start, issuer_end = tbs[offset + 2][1], tbs[offset + 2][2]
        validity_start, validity_end = tbs[offset + 3][1], tbs[offset + 3][2]
        subject_start, subject_end = tbs[offset + 4][1], tbs[offset + 4][2]
        expiry = None
        validity = _asn1_list(der, validity_start, validity_end)
        if len(validity) >= 2:
            expiry = _asn1_date(der, validity[1][0], validity[1][1], validity[1][2])
        names = []
        for tag, ext_start, ext_end, _ in _asn1_list(der, tbs_start, tbs_end):
            if tag != 0xA3:
                continue
            entries = _asn1_list(der, ext_start, ext_end)
            if entries and entries[0][0] == 0x30 and len(entries) == 1:
                probe = _asn1_list(der, entries[0][1], entries[0][2])
                if probe and probe[0][0] == 0x30:
                    entries = probe
            for entry_tag, entry_start, entry_end, _ in entries:
                if entry_tag != 0x30:
                    continue
                entry = _asn1_list(der, entry_start, entry_end)
                if len(entry) < 2 or entry[0][0] != 0x06:
                    continue
                if _asn1_oid_value(der, entry[0][1], entry[0][2]) != "2.5.29.17":
                    continue
                value_tag, value_start, value_end, _ = entry[-1]
                if value_tag == 0x04:
                    names = _asn1_san(der, value_start, value_end)
                elif value_tag == 0x30:
                    names = _asn1_san(der, value_start, value_end)
        issuer_cn, issuer_org = "", ""
        for oid, value in _asn1_attributes(der, issuer_start, issuer_end):
            if oid == "2.5.4.3" and not issuer_cn:
                issuer_cn = value
            elif oid == "2.5.4.10" and not issuer_org:
                issuer_org = value
        subject_cn, subject_org = "", ""
        for oid, value in _asn1_attributes(der, subject_start, subject_end):
            if oid == "2.5.4.3" and not subject_cn:
                subject_cn = value
            elif oid == "2.5.4.10" and not subject_org:
                subject_org = value
        if not names and subject_cn:
            names = [subject_cn.lower()]
        return {
            "names": names,
            "expiry": expiry,
            "subject_cn": subject_cn,
            "subject_org": subject_org,
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
        }
    except Exception:
        return None


def _cert_summary_from_pem(pem_text):
    """Summarise one certificate PEM: names, expiry and fingerprint."""
    text = _as_text(pem_text)
    if "-----BEGIN CERTIFICATE-----" not in text:
        return None
    # Pure-Python first: BaoTa's panel Python has a minimal PATH and the host
    # often has no openssl binary, which used to make every certificate
    # unreadable and therefore every site look undeployed.
    parsed = _x509_summary(text)
    if parsed and parsed.get("expiry") is not None:
        return {
            "names": parsed.get("names") or [],
            "expiry": parsed.get("expiry"),
            "fingerprint": _cert_fingerprint(text),
            "issuerCn": parsed.get("issuer_cn") or "",
            "issuerOrg": parsed.get("issuer_org") or "",
            "subjectCn": parsed.get("subject_cn") or "",
        }
    return _cert_summary_from_openssl(text)


def _cert_summary_from_openssl(pem_text):
    """openssl fallback for certificates the pure-Python parser cannot read."""
    text = _as_text(pem_text)
    cert_tmp = _plugin_tmp_path("dnspanel-summary")
    try:
        _atomic_write(cert_tmp, text)
        ok, output = _run_checked([
            "openssl", "x509", "-in", cert_tmp, "-noout",
            "-enddate", "-fingerprint", "-sha256",
        ])
        if not ok:
            return None
        expiry = None
        fingerprint = ""
        for line in output.splitlines():
            line = line.strip()
            if line.lower().startswith("notafter="):
                expiry = _parse_expiry(line.split("=", 1)[-1].strip())
            elif "Fingerprint=" in line:
                fingerprint = line.split("=", 1)[-1].strip().replace(":", "").lower()
        if expiry is None:
            return None
        return {
            "names": _cert_names_from_pem(text),
            "expiry": expiry,
            "fingerprint": fingerprint,
        }
    except Exception:
        return None
    finally:
        try:
            os.remove(cert_tmp)
        except Exception:
            pass


def _cert_fingerprint(pem_text):
    """SHA-256 of the certificate DER, lowercase hex (empty when unreadable)."""
    der = _pem_first_der(pem_text)
    if not der:
        return ""
    try:
        return hashlib.sha256(der).hexdigest()
    except Exception:
        return ""


def _read_file_raw(path):
    """Plain file read fallback for when the BaoTa public helper fails."""
    with open(path, "rb") as fh:
        return fh.read()




def _issuer_source_label(pem_text):
    """
    Which authority issued a certificate PEM, read from its own issuer field.

    The issuer is authoritative and works for certificates the panel never
    issued (one deployed by hand or by another tool), which is the case that
    matters when reporting what a site currently serves. Parsing is pure
    Python so it still works on a panel host with no openssl binary.
    """
    parsed = _x509_summary(_as_text(pem_text))
    if parsed:
        haystack = (str(parsed.get("issuer_cn") or "") + " " + str(parsed.get("issuer_org") or "")).lower()
        return _issuer_label_from_text(haystack)
    return _issuer_source_label_openssl(pem_text)


# Intermediates and roots that carry no organisation of their own. A certificate
# whose issuer is R10/E1/YR2 is still a Let\u2019s Encrypt certificate, and
# reporting it as unknown hid the source in the UI.
_LETS_ENCRYPT_NAMES = (
    "let" + chr(39) + "s encrypt",
    "letsencrypt",
    "isrg",
    "yr2",
    "yr1",
    "r3",
    "r4",
    "r10",
    "r11",
    "e1",
    "e5",
    "e6",
)


# Other authorities, mapped to the label the UI shows for their certificates.
_SOURCE_ISSUER_HINTS = (
    ("tencent", "tencent"),
    ("trustasia", "tencent"),
    ("digicert", "uploaded"),
    ("sectigo", "uploaded"),
    ("comodo", "uploaded"),
    ("globalsign", "uploaded"),
    ("godaddy", "uploaded"),
    ("geotrust", "uploaded"),
)


def _issuer_label_from_text(haystack):
    """Map an issuer name string to a known source key (empty when unknown)."""
    text = _as_text(haystack).lower().strip()
    if not text:
        return ""
    for name in _LETS_ENCRYPT_NAMES:
        if name in text:
            return "letsencrypt"
    for needle, key in _SOURCE_ISSUER_HINTS:
        if needle in text:
            return key
    return ""


def _issuer_source_label_openssl(pem_text):
    """openssl fallback for issuer detection when DER parsing is unavailable."""
    text = _as_text(pem_text)
    if "-----BEGIN CERTIFICATE-----" not in text:
        return ""
    cert_tmp = _plugin_tmp_path("dnspanel-issuer")
    try:
        _atomic_write(cert_tmp, text)
        ok, output = _run_checked([
            "openssl", "x509", "-in", cert_tmp, "-noout", "-issuer",
        ])
        if not ok:
            return ""
        return _issuer_label_from_text(output)
    except Exception:
        return ""
    finally:
        try:
            os.remove(cert_tmp)
        except Exception:
            pass

def _cert_summary_from_file(path):
    """Read one certificate file and summarise it (None when unreadable)."""
    try:
        if not os.path.exists(path) or os.path.getsize(path) <= 0:
            return None
    except Exception:
        return None
    body = ""
    for reader in (public.ReadFile, _read_file_raw):
        try:
            body = _as_text(reader(path))
        except Exception:
            body = ""
        if body:
            break
    if not body:
        return None
    summary = _cert_summary_from_pem(body)
    if not summary:
        return None
    summary["path"] = path
    issuer_source = _issuer_source_label(body)
    summary["sources"] = [issuer_source] if issuer_source else []
    return summary


def _cert_not_after_from_pem(pem_text):
    """Return the certificate notAfter as an aware UTC datetime, or None."""
    summary = _cert_summary_from_pem(pem_text)
    return summary.get("expiry") if summary else None


def _name_covers(cert_name, host):
    """True when certificate name `cert_name` serves `host` (TLS wildcard rules)."""
    cn = _as_text(cert_name).strip().lower().rstrip(".")
    h = _as_text(host).strip().lower().rstrip(".")
    if not cn or not h:
        return False
    if h.startswith("*."):
        return cn == h
    if cn.startswith("*."):
        base = cn[2:]
        return h.endswith("." + base) and h.count(".") == base.count(".") + 1
    return h == cn


def _names_coverage_score(cert_names, hosts):
    """How many of `hosts` are covered by the certificate names."""
    return sum(1 for host in (hosts or []) if any(_name_covers(name, host) for name in (cert_names or [])))


def _covered_hosts(cert_names, hosts):
    """Subset of `hosts` covered by the certificate names, original order kept."""
    return [host for host in (hosts or []) if any(_name_covers(name, host) for name in (cert_names or []))]


def _dedup_latest_by_domain(certs):
    """Keep one certificate per domain: the one with the most remaining validity."""
    best = {}
    epoch = _parse_expiry("1970-01-01T00:00:00Z")
    for cert in certs or []:
        domain = _as_text((cert or {}).get("domain")).strip().lower()
        if not domain:
            continue
        current = best.get(domain)
        if not current:
            best[domain] = cert
            continue
        if (_parse_expiry(cert.get("notAfter")) or epoch) > (_parse_expiry(current.get("notAfter")) or epoch):
            best[domain] = cert
    return list(best.values())


def _source_of(cert):
    """Map a panel certificate row to its deploy source key."""
    row = cert or {}
    provider = _as_text(row.get("provider")).strip().lower()
    source = _as_text(row.get("source")).strip().lower()
    if provider == "acme" or source == "letsencrypt":
        return "letsencrypt"
    return "tencent"


def _source_label(cert):
    row = cert or {}
    if _source_of(row) == "letsencrypt":
        return "Let's Encrypt"
    if row.get("isUploaded"):
        return "上传证书"
    return "腾讯云"


def _auto_renew_label(cert):
    row = cert or {}
    provider = _as_text(row.get("provider")).strip().lower()
    if provider == "acme":
        if row.get("autoRenew"):
            last = _as_text(row.get("lastRenewedAt")).strip()[:10]
            return ("自动续期 - 上次 " + last) if last else "自动续期"
        return "已关闭"
    if row.get("autoRenew"):
        return "腾讯云自动续费"
    return "面板托管"


def _edgeone_binding_status(cert, bindings):
    """Match a panel certificate to EdgeOne acceleration bindings.

    `bindings` maps edge-domain -> binding row (from /ssl/edgeone-bindings).
    Returns one of:
      {"state": "none"}                      未启用加速
      {"state": "synced", "domains": [...]}  加速边缘已绑定本证书
      {"state": "stale", "domains": [...]}   加速边缘绑定的是旧证书（需同步）
      {"state": "failed", "domains": [...]}  上次同步失败
    """
    row = cert or {}
    names = _cert_names_from_panel_cert(row)
    if not bindings or not names:
        return {"state": "none"}
    cert_id = _as_text(row.get("remoteCertId")).strip()
    matched_synced = []
    matched_stale = []
    matched_failed = []
    for edge_domain, binding in bindings.items():
        # Does this edge binding belong to any of the cert's names?
        if not any(_name_covers(name, edge_domain) for name in names):
            continue
        status = _as_text(binding.get("status")).strip().lower()
        same_cert = _as_text(binding.get("certRemoteId")).strip() == cert_id
        up_to_date = binding.get("upToDate")
        if status == "failed":
            matched_failed.append(edge_domain)
        elif same_cert and up_to_date is not False:
            matched_synced.append(edge_domain)
        else:
            matched_stale.append(edge_domain)
    if matched_failed:
        return {"state": "failed", "domains": matched_failed}
    if matched_stale:
        return {"state": "stale", "domains": matched_stale}
    if matched_synced:
        return {"state": "synced", "domains": matched_synced}
    return {"state": "none"}



def _cert_names_from_panel_cert(cert):
    """Merge a panel certificate row's primary domain and SAN list."""
    row = cert or {}
    names = []
    primary = _as_text(row.get("domain")).strip().lower().rstrip(".")
    if primary and primary not in names:
        names.append(primary)
    san = row.get("san")
    if isinstance(san, str):
        try:
            san = json.loads(san)
        except Exception:
            san = None
    if isinstance(san, (list, tuple)):
        for item in san:
            name = _as_text(item).strip().lower().rstrip(".")
            if name and name not in names:
                names.append(name)
    return names


def _certificate_identity(cert_names):
    """
    Stable identity of a hostname set, ignoring wildcard spelling.

    The order-insensitive name set is what decides whether two certificates
    serve the same namespace, so SUPERSEDE decisions never depend on the
    remaining validity of an independently managed certificate.
    """
    names = set()
    for name in cert_names or []:
        clean = _as_text(name).strip().lower().rstrip(".")
        if clean.startswith("*."):
            clean = clean[2:]
        if clean:
            names.add(clean)
    return tuple(sorted(names))


def _is_supersede(cert_names, installed_names):
    """
    True when `cert_names` and `installed_names` cover the same namespace.

    A renewal keeps its CN/SAN set, so the (wildcard-stripped) name sets of a
    renewed certificate and the certificate it replaces are identical. A
    separate certificate that merely happens to cover one of the site hosts
    almost never has the very same set, so the site is left alone.
    """
    new_identity = _certificate_identity(cert_names)
    old_identity = _certificate_identity(installed_names)
    return bool(new_identity) and new_identity == old_identity


def _panel_api(path):
    """Build the full URL of a DNS panel API path."""
    base = _as_text(_get_config("serverUrl")).strip().rstrip("/")
    return base + "/api" + path


def _panel_headers():
    """Authorization headers carrying the configured API token."""
    token = _as_text(_get_config("apiToken")).strip()
    return {"Authorization": "Bearer " + token, "Content-Type": "application/json"}


def _validate_server_url(value):
    """Accept http:// only for loopback / RFC1918 addresses; https elsewhere."""
    try:
        parsed = urlsplit(_as_text(value).strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        if parsed.username or parsed.password:
            return None
        host = parsed.hostname.lower()
        is_private_172 = False
        if host.startswith("172."):
            try:
                is_private_172 = 16 <= int(host.split(".")[1]) <= 31
            except Exception:
                is_private_172 = False
        local = (
            host in ("127.0.0.1", "localhost", "::1")
            or host.startswith("10.")
            or host.startswith("192.168.")
            or is_private_172
        )
        if parsed.scheme != "https" and not local:
            return None
        return _as_text(value).strip().rstrip("/")
    except Exception:
        return None


def _http_request(url, method="GET", headers=None, data=None, timeout=30):
    """HTTP request helper compatible with both panel Python runtimes."""
    try:
        import urllib.request as url_module
    except ImportError:
        import urllib2 as url_module
    request_headers = headers or {}
    body = None
    if data is not None:
        body = json.dumps(_json_safe(data)).encode("utf-8")
    try:
        try:
            request = url_module.Request(url, data=body, headers=request_headers, method=method)
        except TypeError:
            request = url_module.Request(url, data=body, headers=request_headers)
            request.get_method = lambda: method

        class _NoRedirect(url_module.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, response_headers, newurl):
                return None

        opener = url_module.build_opener(_NoRedirect())
        response = opener.open(request, timeout=timeout)
        return _as_text(response.read())
    except Exception as exc:
        return json.dumps({"success": False, "message": str(exc)}, ensure_ascii=False)


def _panel_get(path, timeout=30):
    """GET a panel API path and return the parsed JSON object."""
    raw = _http_request(_panel_api(path), headers=_panel_headers(), timeout=timeout)
    try:
        parsed = json.loads(raw)
    except Exception:
        return {"success": False, "message": "解析响应失败"}
    return parsed if isinstance(parsed, dict) else {"success": False, "message": "响应格式异常"}


def _panel_post(path, payload=None, timeout=60):
    """POST JSON to a panel API path and return the parsed JSON object."""
    raw = _http_request(
        _panel_api(path), method="POST", headers=_panel_headers(),
        data=(payload if payload is not None else {}), timeout=timeout,
    )
    try:
        parsed = json.loads(raw)
    except Exception:
        return {"success": False, "message": "解析响应失败"}
    return parsed if isinstance(parsed, dict) else {"success": False, "message": "响应格式异常"}




def _is_real_site_name(name):
    """
    True only for names that can be a BaoTa site bound to a real domain.

    BaoTa's vhost directory also holds internal worker configs, whose file
    names (0.fastcgi_cache, 0.site_total_log_format, 0.websocket,
    waf2monitor_data) are not domains. They have no certificate of their own
    and must not be reported as sites needing attention.
    """
    value = _as_text(name).strip()
    if not value or value in _SKIP_SITE_NAMES:
        return False
    if value.startswith("ssl.") or value.startswith("0."):
        return False
    lowered = value.lower()
    if lowered.startswith("_") or lowered.startswith("waf"):
        return False
    labels = lowered.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False
    for label in labels:
        if not label:
            return False
        for char in label:
            if not (char.isalnum() or char == "-" or char == "_"):
                return False
    return True

def _list_bt_sites():
    """
    Every BaoTa site with its bound domains: [{id, name, domains: [...]}].

    Two independent sources are merged so the list survives panel version
    differences: the sites database table (plus the domain table) and the
    vhost config filenames on disk, whose stem is exactly the site name
    BaoTa uses for the site certificate directory.
    """
    import glob
    sites = {}
    try:
        rows = public.M("sites").field("id,name").select()
    except Exception:
        try:
            rows = public.M("sites").select()
        except Exception:
            rows = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict) or not row.get("name"):
                continue
            name = _as_text(row.get("name")).strip()
            if not _is_real_site_name(name):
                continue
            entry = sites.setdefault(name, {"id": row.get("id"), "name": name, "domains": set()})
            try:
                domains = public.M("domain").where("pid=?", (row.get("id"),)).field("name").select()
                if isinstance(domains, list):
                    for domain in domains:
                        if isinstance(domain, dict) and domain.get("name"):
                            entry["domains"].add(_as_text(domain.get("name")).strip())
            except Exception:
                pass
    for base in _VHOST_CONF_DIRS:
        try:
            for path in glob.glob(base + "/*.conf"):
                name = os.path.basename(path)
                if name.endswith(".conf"):
                    name = name[:-5]
                name = name.strip()
                if _is_real_site_name(name):
                    sites.setdefault(name, {"id": None, "name": name, "domains": set()})
        except Exception:
            pass
    output = []
    for name, entry in sites.items():
        output.append({"id": entry["id"], "name": name, "domains": sorted(entry["domains"])})
    output.sort(key=lambda item: item["name"])
    return output


def _match_sites_for_domain(domain, sites):
    """Every BaoTa site that can serve `domain` (site name or bound domain)."""
    target = _as_text(domain).strip().lower().lstrip("*.")
    if not target:
        return []
    matched = []
    seen = set()
    for site in sites or []:
        site_name = _as_text(site.get("name")).strip()
        if not site_name or site_name in seen:
            continue
        candidates = [site_name.lower()]
        candidates += [_as_text(item).strip().lower().lstrip("*.") for item in (site.get("domains") or [])]
        if any(c and (target == c or target.endswith("." + c) or c.endswith("." + target)) for c in candidates):
            seen.add(site_name)
            matched.append(site)
    return matched


def _site_vhost_conf_paths(site_name):
    """
    Candidate vhost config paths for a BaoTa site, nginx/OpenResty first.

    BaoTa writes per-site nginx HTTPS settings either inline in <site>.conf,
    through a shared nginx.conf, or through its SSL include directory, so all
    of those layouts are probed before giving up.
    """
    name = _as_text(site_name).strip()
    if not name:
        return []
    paths = [
        "/www/server/panel/vhost/nginx/" + name + ".conf",
        "/www/server/panel/vhost/openresty/" + name + ".conf",
        "/www/server/panel/vhost/nginx/ssl/" + name + ".conf",
        "/www/server/panel/vhost/nginx/" + name + "/nginx.conf",
        "/www/server/panel/vhost/openresty/" + name + "/nginx.conf",
        "/www/server/panel/vhost/apache/" + name + ".conf",
    ]
    ordered = []
    for path in paths:
        if path not in ordered:
            ordered.append(path)
    return ordered


def _config_text(conf_path, site_name):
    """
    Read a vhost config, expanding the BaoTa path variables it may contain.

    BaoTa's SSL include files use $VHOST_PATH, and the nginx.conf / openresty
    layouts use $SERVER_NAME. Both are expanded to this site's real values so
    the `ssl_certificate` path in the file can actually be opened.
    """
    try:
        if not os.path.exists(conf_path) or os.path.getsize(conf_path) <= 0:
            return None
    except Exception:
        return None
    text = ""
    for reader in (public.ReadFile, _read_file_raw):
        try:
            text = _as_text(reader(conf_path))
        except Exception:
            text = ""
        if text:
            break
    if not text:
        return None
    text = text.replace("$VHOST_PATH", "/www/server/panel/vhost")
    text = text.replace("$SERVER_NAME", _as_text(site_name).strip())
    return text


def _configured_site_cert_paths(site_name):
    """
    Certificate files the site's own vhost config points at, in file order.

    This is the source of truth for what the site really serves: a certificate
    the user deployed outside this plugin (BaoTa SSL tab, certificate folder,
    another tool) lives wherever the config points, which is often not the
    plugin's own default directory.
    """
    found = []
    pattern = re.compile(r"(?m)^[ \t]*ssl_certificate[ \t]+([^;\r\n]+);")
    for conf_path in _site_vhost_conf_paths(site_name):
        text = _config_text(conf_path, site_name)
        if not text:
            continue
        for match in pattern.finditer(text):
            path = _as_text(match.group(1)).strip(_QUOTES)
            if path and path not in found:
                found.append(path)
    return found


def _site_cert_dir(site_name):
    """Standard per-site certificate directory used by BaoTa and this plugin."""
    return "/www/server/panel/vhost/cert/" + _as_text(site_name).strip()


def _default_site_cert_candidates(site_name):
    """Fallback search list inside the standard BaoTa certificate directory."""
    cert_dir = _site_cert_dir(site_name)
    candidates = [cert_dir + "/fullchain.pem", cert_dir + "/cert.pem", cert_dir + "/certificate.pem"]
    try:
        for entry in sorted(os.listdir(cert_dir)):
            lowered = entry.lower()
            if "key" in lowered:
                continue
            if lowered.endswith((".pem", ".crt", ".cer")):
                candidates.append(cert_dir + "/" + entry)
    except Exception:
        pass
    return candidates




def _deployed_source_label(installed):
    """
    Which certificate authority issued the certificate a site serves now.

    The deployed file is compared against the certificate families the panel
    knows about, so the UI can say 腾讯云 or Let's Encrypt instead of showing a
    bare fingerprint. An unknown origin is reported as 手工部署 rather than
    guessed, and a certificate whose origin cannot be established is still
    reported as deployed.
    """
    row = installed or {}
    sources = row.get("sources") or []
    labels = []
    for source in sources:
        label = _SOURCE_LABELS.get(_as_text(source).strip().lower())
        if label and label not in labels:
            labels.append(label)
    if not labels:
        return "手工部署"
    return " / ".join(labels)


_SOURCE_LABELS = {
    "tencent": "腾讯云",
    "letsencrypt": "Let's Encrypt",
    "acme": "Let's Encrypt",
    "uploaded": "上传证书",
}

def _summarize_cert_paths(paths):
    """Summaries for every readable certificate in `paths`, deduplicated."""
    summaries = []
    seen = set()
    for path in paths or []:
        try:
            real = os.path.realpath(path)
        except Exception:
            continue
        if real in seen:
            continue
        seen.add(real)
        summary = _cert_summary_from_file(real)
        if summary:
            summaries.append(summary)
    return summaries


def _live_installed_cert_summaries(site_name):
    """Certificates the site really serves via its vhost config, freshest first."""
    summaries = _summarize_cert_paths(_configured_site_cert_paths(site_name))
    return _sort_by_expiry(summaries)


def _installed_cert_summaries(site_name):
    """
    Certificates the site serves, falling back to the site certificate folder.

    The vhost config is the source of truth. The standard certificate folder
    is scanned only when the config exposes no readable certificate: that
    folder can hold leftovers this plugin itself wrote (for example a
    certificate for a site whose config was later switched to one the user
    manages themselves), and a leftover must never be reported as the
    certificate the site is serving.
    """
    name = _as_text(site_name).strip()
    if not name:
        return []
    summaries = _live_installed_cert_summaries(name)
    for _cert_entry in summaries:
        _cert_entry["chainComplete"] = _certificate_chain_state(_cert_entry.get("path"))
    if not summaries:
        summaries = _sort_by_expiry(_summarize_cert_paths(_default_site_cert_candidates(name)))
    return summaries


def _sort_by_expiry(summaries):
    """Sort certificate summaries by notAfter, freshest first."""
    def _key(summary):
        expiry = (summary or {}).get("expiry")
        try:
            return expiry.timestamp() if expiry else 0.0
        except Exception:
            return 0.0
    return sorted(summaries or [], key=_key, reverse=True)


def _installed_cert_summary(site_name):
    """The best certificate currently deployed on a site, or None."""
    summaries = _installed_cert_summaries(site_name)
    return summaries[0] if summaries else None




_CERT_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----",
    re.DOTALL,
)


def _split_pem_certificates(pem_text):
    "Every certificate block in a PEM, in file order."
    text = _as_text(pem_text)
    return [match.group(0).strip() for match in _CERT_BLOCK_RE.finditer(text)]


def _pem_certificate_count(pem_text):
    "How many certificates a PEM file contains."
    return len(_split_pem_certificates(pem_text))


def _chain_positions(pem_text):
    "(subject, issuer) for every certificate block, in file order."
    """
    Each side falls back to the organization when the CN is missing, because
    root and intermediate certificates routinely carry only an O. Comparing CN
    alone would report a complete chain as broken.
    """
    positions = []
    for block in _split_pem_certificates(pem_text):
        parsed = _x509_summary(block)
        if not parsed:
            positions.append(("", ""))
            continue
        subject = _as_text(parsed.get("subject_cn") or "").lower()
        if not subject:
            subject = _as_text(parsed.get("subject_org") or "").lower()
        issuer = _as_text(parsed.get("issuer_cn") or "").lower()
        if not issuer:
            issuer = _as_text(parsed.get("issuer_org") or "").lower()
        positions.append((subject, issuer))
    return positions


def _pem_chain_complete(pem_text):
    "True when every certificate in a PEM links to the next one."
    ""
    "A file holding several blocks is only a valid chain when each block's"
    "issuer is the next block's subject: a leaf followed by an unrelated"
    "certificate still leaves the browser unable to build a path, which is"
    "what makes https show 不安全."
    ""
    positions = _chain_positions(pem_text)
    if len(positions) < 2:
        return False
    for index in range(len(positions) - 1):
        issuer = positions[index][1]
        subject = positions[index + 1][0]
        if issuer and subject and issuer == subject:
            continue
        # A root that is its own issuer ends the chain legitimately.
        if positions[index][0] and positions[index][0] == issuer:
            continue
        return False
    return True



def _chain_source_paths(site_name, cert_dir):
    "Candidate files that may hold the intermediate certificate."
    name = _as_text(site_name).strip()
    paths = [
        cert_dir + "/fullchain.pem",
        cert_dir + "/chain.pem",
        cert_dir + "/ca.pem",
        cert_dir + "/chain.crt",
        cert_dir + "/ca_bundle.pem",
        cert_dir + "/intermediate.pem",
    ]
    if name:
        paths.extend([
            "/www/server/panel/vhost/ssl/" + name + "/chain.pem",
            "/www/server/panel/vhost/ssl/" + name + "/fullchain.pem",
            "/root/.acme.sh/" + name + "/ca.cer",
            "/root/.acme.sh/" + name + "/fullchain.cer",
            "/www/server/panel/vhost/letsencrypt/" + name + "/chain.pem",
            "/etc/letsencrypt/live/" + name + "/chain.pem",
            "/etc/ssl/certs/" + name + ".chain.pem",
        ])
    for directory in (cert_dir, os.path.join(cert_dir, "..")):
        try:
            if not directory or not os.path.isdir(directory):
                continue
            for entry in sorted(os.listdir(directory)):
                lower = _as_text(entry).lower()
                if not lower.endswith((".pem", ".crt", ".cer")):
                    continue
                if "privkey" in lower or lower.endswith(".key"):
                    continue
                candidate = os.path.join(directory, entry)
                if candidate not in paths:
                    paths.append(candidate)
        except Exception:
            continue
    ordered = []
    for path in paths:
        if path and path not in ordered:
            ordered.append(path)
    return ordered



def _complete_certificate_chain(pem_text, site_name="", cert_dir=""):
    "Return a PEM whose chain is complete, adding any missing intermediate."
    ""
    "BaoTa and the certificate sources it reads from sometimes hand over a"
    "leaf certificate on its own. nginx then serves a chain the browser"
    "cannot build, and https reports 不安全 even though the certificate"
    "itself is valid. Missing intermediates are looked up locally, so this"
    "needs no network access and no openssl binary."
    ""
    "Returns (pem_text, added_count, note)."
    ""
    text = _as_text(pem_text)
    blocks = _split_pem_certificates(text)
    if not blocks:
        return text, 0, "证书内容为空"
    if _pem_chain_complete(text):
        return text, 0, "证书链完整"
    known_subjects = set()
    for block in blocks:
        parsed = _x509_summary(block)
        if parsed and parsed.get("subject_cn"):
            known_subjects.add(_as_text(parsed["subject_cn"]).lower())
    needed = None
    if blocks:
        leaf = _x509_summary(blocks[-1])
        if leaf and leaf.get("issuer_cn"):
            needed = _as_text(leaf["issuer_cn"]).lower()
    if not needed:
        return text, 0, "无法确定所需中间证书"
    additions = []
    for path in _chain_source_paths(site_name, cert_dir):
        if _as_text(path).split("/")[-1] == "fullchain.pem":
            continue
        for block in _read_certificate_blocks(path):
            parsed = _x509_summary(block)
            if not parsed:
                continue
            subject = _as_text(parsed.get("subject_cn") or "").lower()
            if not subject or subject in known_subjects:
                continue
            if subject == needed or needed in subject or subject in needed:
                additions.append(block)
                known_subjects.add(subject)
        if additions:
            break
    if not additions:
        return text, 0, "未找到中间证书，请检查证书来源是否包含完整链"
    combined = text.rstrip() + chr(10) + chr(10).join(additions) + chr(10)
    return combined, len(additions), "已自动补全证书链"





def _certificate_chain_state(path):
    "True when the certificate file at `path` serves a complete chain."
    ""
    "A file holding only the leaf certificate leaves the browser unable to"
    "build a path to a trusted root, so https reports 不安全 even though the"
    "certificate is valid. Unknown is reported as True so an unreadable file"
    "is never accused of a fault it may not have."
    ""
    if not path:
        return True
    blocks = _read_certificate_blocks(path)
    if not blocks:
        return True
    return _pem_chain_complete(chr(10).join(blocks))


def _read_certificate_blocks(path):
    "Certificate blocks inside a local PEM file ([] when unreadable)."
    try:
        if not os.path.exists(path) or os.path.getsize(path) <= 0:
            return []
    except Exception:
        return []
    body = ""
    for reader in (public.ReadFile, _read_file_raw):
        try:
            body = _as_text(reader(path))
        except Exception:
            body = ""
        if body:
            break
    return _split_pem_certificates(body)


def _cert_deployed(site_name):
    """True when the site already has a readable certificate deployed."""
    if not site_name:
        return False
    return bool(_installed_cert_summaries(site_name))


def _site_cert_paths_in_configs(site_name):
    """
    Map every config file of a site to the certificate it references.

    Used before a deployment so every layout the site uses (inline vhost,
    BaoTa SSL include file, openresty layout) can be repointed together and
    nginx never keeps serving a stale certificate from a file it still
    includes.
    """
    mapping = []
    for conf_path in _site_vhost_conf_paths(site_name):
        text = _config_text(conf_path, site_name)
        if not text:
            continue
        certs = []
        for match in re.finditer(_CERT_DIRECTIVE_RE, text):
            path = _as_text(match.group(1)).strip(_QUOTES)
            if path and path not in certs:
                certs.append(path)
        if certs:
            mapping.append({"path": conf_path, "certs": certs})
    return mapping


def _shared_site_cert_dir(site_name):
    """
    Directory of the certificate file the site currently serves, if any.

    A certificate deployed by hand lives in its owner's directory; writing a
    refreshed certificate back to that same directory keeps every config that
    points at it (present and future) working, instead of silently forking a
    second copy in the plugin's default folder.
    """
    for conf_path in _site_vhost_conf_paths(site_name):
        text = _config_text(conf_path, site_name)
        if not text:
            continue
        match = _CERT_DIRECTIVE_RE.search(text)
        if not match:
            continue
        path = _as_text(match.group(1)).strip(_QUOTES)
        if not path or not os.path.isabs(path):
            continue
        directory = os.path.dirname(path)
        if not directory or not os.path.isdir(directory):
            continue
        if not os.access(directory, os.W_OK):
            continue
        return directory
    return None


def _deploy_cert_paths(site_name):
    """
    Where a deployment writes its certificate and private key.

    Preference order: the directory of the certificate the site serves today,
    then the standard BaoTa per-site certificate directory. Both are created
    on demand.
    """
    directory = _shared_site_cert_dir(site_name) or _site_cert_dir(site_name)
    if not os.path.isdir(directory):
        os.makedirs(directory)
    return directory + "/fullchain.pem", directory + "/privkey.pem"


def _ssl_data_dir():
    """Directory holding generated SSL snippets and deploy records."""
    return "/www/server/panel/vhost/cert/dnspanel_ssl"


def _resource_key(cert_id, credential_id, site_name):
    """Stable deploy fingerprint key for one certificate and site pair."""
    value = (
        _as_text(credential_id).strip() + "|" + _as_text(cert_id).strip() + "|"
        + _as_text(site_name).strip().lower()
    )
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def _dedupe_ssl_directives(text):
    """
    Drop duplicate `ssl_certificate` directives inside one server block.

    Appending a directive to a block that already declares it makes nginx
    refuse to start ("duplicate ssl_certificate"), so a rewrite must never
    add a second copy. The first occurrence is kept, later ones are removed
    together with their line when the line holds nothing else.
    """
    lines = _as_text(text).split(NL)
    output = []
    inside_server = False
    depth = 0
    seen_certificate = False
    pattern = re.compile(r"^[ 	]*ssl_certificate[ 	]+[^;" + NL + CR + "]+;[ 	]*")
    for line in lines:
        stripped = line.strip()
        if re.match(r"^server[ 	]*{", stripped) or stripped == "server":
            inside_server = True
            depth = 0
            seen_certificate = False
        if inside_server:
            depth += line.count("{") - line.count("}")
            if pattern.match(line):
                if seen_certificate:
                    if depth <= 0:
                        inside_server = False
                    continue
                seen_certificate = True
            if depth <= 0 and stripped != "":
                inside_server = False
                seen_certificate = False
        output.append(line)
    return NL.join(output)


def _insert_directive_into_server(text, directive, value):
    """
    Ensure `directive value;` exists inside the first server block that lacks it.

    The directive is written immediately after `ssl_certificate_key`, after
    `ssl_certificate`, otherwise right after the block's opening brace. Returns
    the original text when no suitable block exists.
    """
    lines = _as_text(text).split(NL)
    output = []
    total = len(lines)
    index = 0
    while index < total:
        line = lines[index]
        output.append(line)
        if not re.match(r"^[ 	]*server[ 	]*{", line.strip()) and line.strip() != "server {":
            index += 1
            continue
        block = []
        depth = line.count("{") - line.count("}")
        cursor = index + 1
        while cursor < total and depth > 0:
            current = lines[cursor]
            depth += current.count("{") - current.count("}")
            block.append(current)
            cursor += 1
        block_text = NL.join(block)
        if re.search(r"^[ 	]*" + re.escape(directive) + r"[ 	]+", block_text, re.M):
            output.extend(block)
            index = cursor
            continue
        indent = "    "
        anchor = None
        for position, item in enumerate(block):
            if re.match(r"^[ 	]*ssl_certificate_key[ 	]+", item):
                anchor = position
            elif anchor is None and re.match(r"^[ 	]*ssl_certificate[ 	]+", item):
                anchor = position
        new_line = indent + directive + "    " + value + ";"
        if anchor is None:
            block.insert(0, new_line)
        else:
            block.insert(anchor + 1, new_line)
        output.extend(block)
        return NL.join(output)
    return _as_text(text)


def _replace_ssl_certificate_directives(text, cert_path, key_path):
    """
    Repoint every certificate directive of a vhost at the given files.

    `ssl_certificate` always points at the certificate and
    `ssl_certificate_key` at the key, while `ssl_certificate_rsa` (its key
    sits in `ssl_certificate_key_rsa`) gets the same certificate so a site
    with an RSA twin directive does not keep serving the old certificate for
    RSA handshakes.
    """
    updated = _as_text(text)
    updated, _ = re.subn(
        r"(?m)^([ 	]*ssl_certificate_key[ 	]+)[^;\r\n]+;",
        lambda match: match.group(1) + key_path + ";",
        updated,
    )
    updated, _ = re.subn(
        r"(?m)^([ 	]*ssl_certificate(?![_a-zA-Z0-9])[ 	]+)[^;\r\n]+;",
        lambda match: match.group(1) + cert_path + ";",
        updated,
    )
    return updated


def _https_server_block(site_name, cert_path, key_path, server_name_value, cert_names):
    """
    Build the HTTPS server block used when a site never had SSL configured.

    Every site domain is listed in server_name so a multi-domain site is not
    reduced to the single `server_name` line of its HTTP block.
    """
    names = [item for item in (cert_names or []) if item]
    if names:
        server_name_line = " ".join(names)
    else:
        server_name_line = _as_text(server_name_value).strip() or "~^"
    return (
        NL
        + "# HTTPS server block (auto-generated by the DNS panel SSL plugin)" + NL
        + "server {" + NL
        + "    listen 443 ssl http2;" + NL
        + "    listen [::]:443 ssl http2;" + NL
        + "    server_name " + server_name_line + ";" + NL
        + NL
        + "    ssl_certificate    " + cert_path + ";" + NL
        + "    ssl_certificate_key    " + key_path + ";" + NL
        + "    ssl_protocols TLSv1.2 TLSv1.3;" + NL
        + "    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;" + NL
        + "    ssl_prefer_server_ciphers on;" + NL
        + "    ssl_session_cache shared:SSL:10m;" + NL
        + "    ssl_session_timeout 10m;" + NL
    )


def _portable_conf_copy(conf_path, conf_content, site_name):
    """
    Counterpart of a BaoTa SSL include file without the variable placeholders.

    BaoTa's SSL include files carry $VHOST_PATH, which nginx resolves against
    the include directory. When such a config is rewritten those placeholders
    are expanded, so the written file keeps real paths instead of a variable
    nginx cannot resolve in that context.
    """
    current = _as_text(conf_content)
    if "$VHOST_PATH" not in current and "$SERVER_NAME" not in current:
        return current
    return _config_text(conf_path, site_name)


# BaoTa keeps vhost configs in these directories; the `ssl_certificate`
# directive inside them is the certificate a site actually serves.
_QUOTES = "" + ''
_VHOST_CONF_DIRS = (
    "/www/server/panel/vhost/nginx",
    "/www/server/panel/vhost/openresty",
    "/www/server/panel/vhost/apache",
)



NL = chr(10)
CR = chr(13)
TAB = chr(9)

_SKIP_SITE_NAMES = ("0.default", "default", "phpfpm_status")

# A wildcard ssl_certificate name is not a file and a path may carry nginx
# variables, so only values that look like real certificate files are used.
# Accelerated hosts keep their own certificate copy, keyed by the host itself
# (www.example.com). The first label is dropped so a wildcard panel certificate
# named *.example.com and the accelerated host resolve to the same directory —
# without that, config.json fills up with one directory per sub-domain.
_ACCEL_CERT_SHARED_PREFIXES = ("www", "cdn", "static", "assets", "img", "api", "m")

# ── CDN / EdgeOne acceleration certificate sync ─────────────────────
# A domain that is accelerated on a CDN serves the certificate the CDN holds,
# NOT the one nginx was given. Deploying only to BaoTa therefore left the site
# showing an expired certificate in the browser while the local file was fresh.
# When the panel exposes acceleration state for the domain, the deployed
# certificate is also pushed to the accelerated copy (bypassing the CDN origin
# pull, so no cache purge is needed) and the page reports both copies.

ACCEL_PANEL_PATH = "/acceleration/certificates"
ACCEL_PAGES = 20
ACCEL_PAGE_LIMIT = 200
ACCEL_ID_LIMIT = 400
ACCEL_HOST_LIMIT = 50
ACCEL_CANDIDATE_LIMIT = 20

# CDN certificates usually run for a year, so re-binding is driven by "the copy
# on the CDN is gone" or "the panel has a strictly newer certificate", not by
# expiry. REBIND_DAYS still catches a CDN copy that is genuinely close to dying.
ACCEL_REBIND_DAYS = 30
ACCEL_EXPIRING_DAYS = 15
ACCEL_FAILURE_COOLDOWN_SECONDS = 1800
ACCEL_MAX_FAILURES = 3


def _accel_local_cert_paths(host):
    """Local certificate files a plugin deploy writes for an accelerated host."""
    name = _safe_cert_name(host)
    if not name:
        return []
    cert_dir = os.path.realpath(os.path.join("/www/server/panel/vhost/cert", name))
    return [cert_dir + "/fullchain.pem", cert_dir + "/privkey.pem"]


def _accel_shared_cert_hosts(host):
    """Same-host spellings that legitimately share one local certificate copy."""
    name = _as_text(host).strip().lower().rstrip(".")
    if not name:
        return []
    hosts = [name]
    prefix, _, tail = name.partition(".")
    if tail and prefix in _ACCEL_CERT_SHARED_PREFIXES and tail not in hosts:
        hosts.append(tail)
    return hosts


_CERT_DIRECTIVE_RE = re.compile(
    r"(?m)^[ 	]*ssl_certificate[ 	]+([^;\r\n]+);"
)


def _is_certificate_path(path):
    """True when a directive value looks like a certificate file path."""
    value = _as_text(path).strip()
    if not value or value.startswith("$"):
        return False
    if not value.startswith("/"):
        return False
    lowered = value.lower()
    if lowered.endswith((".key", ".csr", ".ocsp")):
        return False
    return True


def _certificate_directive_paths(text):
    """Certificate file paths named by every ssl_certificate directive."""
    paths = []
    for match in _CERT_DIRECTIVE_RE.finditer(_as_text(text)):
        tokens = _as_text(match.group(1)).split()
        if not tokens:
            continue
        value = tokens[-1].strip(_QUOTES)
        value = value.replace("$VHOST_PATH", "/www/server/panel/vhost")
        if _is_certificate_path(value) and value not in paths:
            paths.append(value)
    return paths


def _validate_pem_pair(public_key, private_key, hostnames=None):
    if "-----BEGIN CERTIFICATE-----" not in public_key or "PRIVATE KEY-----" not in private_key:
        return False, "证书或私钥 PEM 格式无效"
    cert_tmp = _plugin_tmp_path("dnspanel-cert")
    key_tmp = _plugin_tmp_path("dnspanel-key")
    try:
        _atomic_write(cert_tmp, public_key)
        _atomic_write(key_tmp, private_key)
        cert_pub = subprocess.check_output(["openssl", "x509", "-in", cert_tmp, "-pubkey", "-noout"], stderr=subprocess.STDOUT)
        key_pub = subprocess.check_output(["openssl", "pkey", "-in", key_tmp, "-pubout"], stderr=subprocess.STDOUT)
        if hashlib.sha256(cert_pub).digest() != hashlib.sha256(key_pub).digest():
            return False, "证书与私钥不匹配"
        subprocess.check_output(["openssl", "x509", "-in", cert_tmp, "-checkend", "0", "-noout"], stderr=subprocess.STDOUT)
        candidates = []
        for h in (hostnames or []):
            raw = str(h).strip().lower().rstrip(".")
            if not raw:
                continue
            if raw.startswith("*."):
                # openssl -checkhost rejects literal wildcard bindings; match
                # those against the certificate's own SAN list instead.
                candidates.append(("wildcard", raw))
            else:
                candidates.append(("host", raw.lstrip("*.")))
        if candidates:
            cert_names = _cert_names_from_pem(public_key)
            covered = False
            for kind, hostname in candidates:
                if kind == "wildcard":
                    if hostname in cert_names:
                        covered = True
                        break
                    continue
                try:
                    subprocess.check_output(["openssl", "x509", "-in", cert_tmp, "-checkhost", hostname, "-noout"], stderr=subprocess.STDOUT)
                    covered = True
                    break
                except Exception:
                    pass
            if not covered:
                return False, "证书域名与目标站点不匹配"
        return True, ""
    except Exception as e:
        return False, "证书校验失败: " + str(e)
    finally:
        for path in (cert_tmp, key_tmp):
            try:
                os.remove(path)
            except Exception:
                pass



# ── Panel-side acceleration certificate lookup (CDN copy tracking) ───

def _accel_panel_items():
    """Every acceleration certificate row the panel exposes for these domains.

    Paged so a large account is covered completely; an older panel without the
    endpoint simply returns nothing and every accelerated host is then reported
    as 面板不支持/未纳入 instead of silently looking fine.
    """
    items = []
    page = 1
    while page <= ACCEL_PAGES:
        try:
            data = _panel_get(
                ACCEL_PANEL_PATH + "?page=" + str(page) + "&limit=" + str(ACCEL_PAGE_LIMIT) + "&status=all",
                timeout=30,
            )
        except Exception:
            return items
        if not isinstance(data, dict) or not data.get("success"):
            return items
        batch = data.get("items")
        if batch is None:
            batch = (data.get("data") or {}).get("items") if isinstance(data.get("data"), dict) else data.get("data")
        if not isinstance(batch, list):
            return items
        items.extend([item for item in batch if isinstance(item, dict)])
        try:
            total = int((data.get("pagination") or {}).get("total") or data.get("total") or 0)
        except Exception:
            total = 0
        if len(batch) < ACCEL_PAGE_LIMIT or (total and len(items) >= total):
            break
        page += 1
    return items


def _panel_expiry(cert):
    """Best-effort panel expiry (ISO string) for any panel certificate row."""
    if not isinstance(cert, dict):
        return ""
    for key in ("notAfter", "expiresAt", "expiry", "not_after", "endTime"):
        value = _as_text(cert.get(key)).strip()
        if value:
            return value
    return ""


def _panel_id(cert):
    return _as_text((cert or {}).get("remoteCertId") or (cert or {}).get("id")).strip()


def _find_panel_cert(panel_certs, cert_id):
    wanted = _as_text(cert_id).strip()
    if not wanted:
        return None
    for cert in panel_certs or []:
        if _panel_id(cert) == wanted:
            return cert
    return None


def _find_local_cert(host, local_certs, cname=""):
    """Local certificate copy used for an accelerated host, newest usable first."""
    wanted = [name for name in [cname, host] if name]
    names = set()
    for entry in local_certs or []:
        names.update([_as_text(item).strip().lower().rstrip(".") for item in (entry.get("names") or [])])
    best = None
    for entry in local_certs or []:
        entry_names = [_as_text(item).strip().lower().rstrip(".") for item in (entry.get("names") or [])]
        matched = _host_in_list(host, entry_names) or _host_in_list(cname, entry_names)
        if not matched and wanted:
            matched = any(item in names for item in wanted)
        if not matched:
            continue
        if best is None or (entry.get("expiry") is not None and (best.get("expiry") is None or entry["expiry"] > best["expiry"])):
            best = entry
    return best


def _choose_accel_certificate(candidates, cert_names):
    """Best panel certificate to bind to a CDN host: same certificate family
    first (so a renewal replaces the previous cert rather than a wildcard
    taking over), never a shorter-lived one."""
    wanted = [name for name in (cert_names or []) if name]
    pool = [item for item in (candidates or []) if item.get("names") and _names_cover_hosts(item.get("names"), wanted)]
    if not pool:
        return None
    def _score(item):
        days = item.get("daysRemaining")
        return (
            0 if _host_in_list(_as_text(item.get("domain")).lower(), wanted) else 1,
            -(days if isinstance(days, int) else 99999),
        )
    pool.sort(key=_score)
    return pool[0]


def _accel_result_days(result):
    days = (result or {}).get("accelDaysRemaining")
    return days if isinstance(days, int) else None


def _redact_secret_url(text):
    """Strip query strings from URLs before logging (signed URLs carry secrets)."""
    return re.sub(r"(https?://[^\s?]+)\?[^\s]*", r"\1?***", _as_text(text))


def _accel_state_signature(row, entry):
    """Identity of an accelerated host's certificate state (for unchanged-skip)."""
    return "|".join([
        _as_text((row or {}).get("panelFingerprint")),
        _as_text((row or {}).get("localFingerprint")),
        _as_text((entry or {}).get("certificateId")),
        _as_text((entry or {}).get("accelExpireTime")),
        _as_text((entry or {}).get("accelFingerprint")),
    ])


def _accel_days_left(expiry_text):
    parsed = _parse_expiry(expiry_text)
    return _days_until(parsed) if parsed is not None else None


def _accel_next_expiry(cert_id, details):
    """Expiry EdgeOne reports for the panel certificate bound to a host."""
    for item in (details or {}).get("items") or []:
        if cert_id and _as_text(item.get("certificateId")) == _as_text(cert_id):
            return item.get("expireTime") or ""
    return ""


def _diagnose_sites():
    """Diagnostics shown when no sites are found, to pinpoint the cause."""
    import glob
    info = {}
    try:
        rows = public.M("sites").select()
        info["db_sites_count"] = len(rows) if isinstance(rows, list) else "非列表: " + str(type(rows))
    except Exception as e:
        info["db_sites_error"] = str(e)
    for base, key in (("/www/server/panel/vhost/nginx", "nginx_confs"),
                      ("/www/server/panel/vhost/apache", "apache_confs")):
        try:
            info[key] = [os.path.basename(x) for x in glob.glob(base + "/*.conf")]
        except Exception as e:
            info[key] = "err: " + str(e)
    return info



def _match_site_for_domain(domain, sites):
    """Find the BaoTa site serving `domain`, matching site name OR bound domains."""
    d = (domain or "").strip().lower().lstrip("*.")
    if not d:
        return None
    for s in sites:
        candidates = [str(s.get("name") or "").strip().lower()]
        candidates += [str(x).strip().lower().lstrip("*.") for x in (s.get("domains") or [])]
        for c in candidates:
            if not c:
                continue
            if d == c or d.endswith("." + c) or c.endswith("." + d):
                return s
    return None



def _replace_nginx_directive(text, directive, value):
    """Point an nginx directive at `value`, preserving indentation.

    Matches the whole directive line (`ssl_certificate /old/path;`) and falls
    back to the inline form for unusual layouts. Returns `text` unchanged when
    the directive is absent. A lambda replacement is used so certificate paths
    are inserted literally (no backreference escaping needed).
    """
    pattern = r'(?m)^([ \t]*' + re.escape(directive) + r'[ \t]+)[^;\r\n]+;'
    updated, count = re.subn(pattern, lambda m: m.group(1) + value + ';', text)
    if count:
        return updated
    loose = r'(?<![\w.])' + re.escape(directive) + r'[ \t]+[^;]+;'
    updated, count = re.subn(loose, lambda m: directive + '    ' + value + ';', text)
    return updated if count else text

class dnspanel_ssl_main:

    def __init__(self):
        pass

    # ── Panel-side acceleration (CDN / EdgeOne) certificate lookup ──

    def _accel_panel_lookup(self, hosts):
        """Panel acceleration certificate rows for the given hosts ([] when unknown).

        Returns a list of dicts: {host, panelDomain, cname, panelFingerprint,
        panelExpireTime, panelIssuer, certId, siteId, provider, credentialId,
        panelSupported}. An older panel without the endpoint yields an empty list
        and callers report the host as 未纳入 (rather than pretending it is fine).
        """
        wanted = []
        for host in hosts or []:
            name = _as_text(host).strip().lower().rstrip(".")
            if name and name not in wanted:
                wanted.append(name)
        if not wanted:
            return []

        def fetch(ids):
            query = "?status=all&limit=" + str(ACCEL_PAGE_LIMIT)
            if ids:
                query += "&domains=" + ",".join(ids)
            else:
                query += "&domains=" + ",".join(wanted)
            try:
                data = _panel_get(ACCEL_PANEL_PATH + query, timeout=30)
            except Exception:
                return []
            if not isinstance(data, dict) or not data.get("success"):
                return []
            payload = data.get("data")
            rows = payload.get("items") if isinstance(payload, dict) else payload
            if rows is None:
                rows = data.get("items")
            return [row for row in (rows or []) if isinstance(row, dict)]

        rows = fetch(wanted)
        if rows:
            return rows
        if len(wanted) > ACCEL_ID_LIMIT:
            return []
        # The panel may only match IDs (no hostnames), so search by certificate
        # ID as well before giving up on a domain.
        ids = []
        try:
            cert_data = _panel_get("/ssl/certificates?credentialId=all&page=1&limit=500", timeout=30)
            for cert in (cert_data.get("data") or []) if isinstance(cert_data, dict) else []:
                if _host_in_list(cert.get("domain"), wanted):
                    cert_id = _panel_id(cert)
                    if cert_id and cert_id not in ids:
                        ids.append(cert_id)
        except Exception:
            ids = []
        if ids:
            rows = fetch(ids[:ACCEL_ID_LIMIT])
        return rows

    def _accel_host_index(self, hosts):
        """Index panel acceleration rows by the accelerated hostname."""
        index = {}
        for row in self._accel_panel_lookup(hosts) or []:
            names = []
            for key in ("host", "domainName", "accelDomain"):
                value = _as_text(row.get(key)).strip().lower().rstrip(".")
                if value and value not in names:
                    names.append(value)
            for name in (row.get("names") or []):
                value = _as_text(name).strip().lower().rstrip(".")
                if value and value not in names:
                    names.append(value)
            entry = {
                "provider": _as_text(row.get("provider")).strip().lower() or "edgeone",
                "credentialId": row.get("credentialId"),
                "siteId": _as_text(row.get("siteId")).strip(),
                "host": names[0] if names else "",
                "cname": _as_text(row.get("cname")).strip().lower().rstrip("."),
                "panelDomain": _as_text(row.get("panelDomain")).strip().lower().rstrip("."),
                "panelFingerprint": _as_text(row.get("panelFingerprint")).strip().lower(),
                "panelExpireTime": _as_text(row.get("panelExpireTime")).strip(),
                "panelIssuer": _as_text(row.get("panelIssuer")).strip(),
                "certId": _as_text(row.get("certId")).strip(),
                "accelCertType": _as_text(row.get("accelCertType")).strip(),
                "accelCertificateId": _as_text(row.get("accelCertificateId") or row.get("accelCertId")).strip(),
                "accelStatus": _as_text(row.get("accelStatus")).strip(),
                "accelIssuer": _as_text(row.get("accelIssuer")).strip(),
                "accelEffectiveTime": _as_text(row.get("accelEffectiveTime")).strip(),
                "accelExpireTime": _as_text(row.get("accelExpireTime")).strip(),
                "accelFingerprint": _as_text(row.get("accelFingerprint")).strip().lower(),
                "accelDaysRemaining": row.get("accelDaysRemaining") if isinstance(row.get("accelDaysRemaining"), int) else None,
                "bindable": bool(row.get("bindable")),
                "supported": bool(row.get("supported", True)),
                "message": _as_text(row.get("message")).strip(),
            }
            for name in names:
                if name not in index:
                    index[name] = entry
            # A wildcard accelerated host (*.example.com) stands for every host
            # beneath it, so record it as a fallback lookup for concrete hosts.
            for name in names:
                if name.startswith("*."):
                    index.setdefault("__wildcard__" + name[2:], entry)
        return index

    def _accel_entry_for(self, index, host, cname=""):
        candidates = []
        for value in (host, cname):
            name = _as_text(value).strip().lower().rstrip(".")
            if name:
                candidates.append(name)
        for name in candidates:
            if name in index:
                return index[name]
        for name in candidates:
            if name.startswith("*."):
                continue
            base = name[2:] if name.startswith("*.") else name
            keys = [base]
            parts = base.split(".")
            if len(parts) > 2:
                keys.append(".".join(parts[1:]))
            for key in keys:
                hit = index.get("__wildcard__" + key)
                if hit:
                    return hit
        return None

    @staticmethod
    def _accel_cooldown(state, host):
        """True when a host is inside its post-failure cooldown window.

        A CDN API that keeps rejecting a bind must not be retried on every sync
        run: the failure is remembered in config.json and retried only after
        ACCEL_FAILURE_COOLDOWN_SECONDS.
        """
        record = (state or {}).get(host) or {}
        try:
            failures = int(record.get("failures") or 0)
        except Exception:
            failures = 0
        if failures < ACCEL_MAX_FAILURES:
            return False
        try:
            last = float(record.get("lastAttempt") or 0)
        except Exception:
            last = 0.0
        return (time.time() - last) < ACCEL_FAILURE_COOLDOWN_SECONDS

    @staticmethod
    def _accel_state_update(state, host, ok, note="", extras=None):
        """Remember the outcome of one accelerated-host sync in config.json."""
        record = dict((state or {}).get(host) or {})
        record["lastAttempt"] = time.time()
        record["lastResult"] = _as_text(note)[:300]
        if ok:
            record["failures"] = 0
            record["okAt"] = time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            try:
                record["failures"] = int(record.get("failures") or 0) + 1
            except Exception:
                record["failures"] = 1
            record["failedAt"] = time.strftime("%Y-%m-%d %H:%M:%S")
        for key, value in (extras or {}).items():
            record[key] = value
        state[host] = record
        return state

    @staticmethod
    def _accel_bind(entry, hostnames, cert_id):
        """Bind one panel certificate to the accelerated hosts via the panel API."""
        payload = {
            "domains": hostnames,
            "certId": _as_text(cert_id),
            "mode": "panel",
        }
        credential_id = (entry or {}).get("credentialId")
        if credential_id not in (None, ""):
            try:
                payload["credentialId"] = int(credential_id)
            except Exception:
                pass
        if (entry or {}).get("provider"):
            payload["provider"] = entry.get("provider")
        response = _panel_post(ACCEL_PANEL_PATH + "/bind", payload, timeout=120)
        if not isinstance(response, dict) or not response.get("success"):
            message = _as_text((response or {}).get("message")) or "面板加速证书绑定失败"
            return False, message, {}
        return True, _as_text(response.get("message")) or "加速证书已同步", (response.get("data") or {})

    def _accel_sync_one(self, site_name, hosts, local_cert, panel_certs, local_certs, state, dry_run=False):
        """Sync the CDN certificate of one accelerated host with the deployed one.

        status is one of:
          not_accelerated · panel_unsupported · panel_missing · unchanged
          · updated · sync_failed · bind_pending
        """
        host = _as_text(hosts[0]).strip().lower().rstrip(".") if hosts else ""
        row = {
            "host": host,
            "site": site_name,
            "status": "not_accelerated",
            "changed": False,
            "certId": "",
            "action": "未检测到加速",
            "accelDaysRemaining": None,
            "accelExpireTime": "",
            "accelIssuer": "",
            "panelNames": [],
            "localDaysRemaining": _days_until((local_cert or {}).get("expiry")) if local_cert else None,
        }
        if not host:
            return row
        index = (self._accel_host_index([host]) or {})
        entry = self._accel_entry_for(index, host)
        if not entry:
            return row
        row["provider"] = entry.get("provider") or "edgeone"
        row["siteId"] = entry.get("siteId") or ""
        row["accelCertificateId"] = entry.get("accelCertificateId") or ""
        row["accelStatus"] = entry.get("accelStatus") or ""
        row["accelExpireTime"] = entry.get("accelExpireTime") or ""
        row["accelIssuer"] = entry.get("accelIssuer") or ""
        row["accelDaysRemaining"] = entry.get("accelDaysRemaining")
        row["bindable"] = bool(entry.get("bindable"))

        if not entry.get("supported", True):
            row["status"] = "panel_unsupported"
            row["action"] = entry.get("message") or "面板暂不支持该加速插件"
            return row

        cname = entry.get("cname") or ""
        if not local_cert:
            local_cert = _find_local_cert(host, local_certs, cname)
        cert_id = entry.get("certId") or ""
        cert_names = list((local_cert or {}).get("names") or [])
        panel_cert = _find_panel_cert(panel_certs, cert_id)
        if panel_cert is not None:
            panel_names = _cert_names_from_panel_cert(panel_cert)
            if panel_names:
                cert_names = panel_names
        row["certId"] = cert_id
        row["panelNames"] = cert_names
        row["localDaysRemaining"] = _days_until((local_cert or {}).get("expiry")) if local_cert else None

        if cert_names and panel_certs and not _panel_has_usable_cert(panel_certs, cert_id):
            row["status"] = "panel_missing"
            row["action"] = "面板证书已不可用（可能已过期或被清理），请重新签发后再同步"
            return row

        accel_days = entry.get("accelDaysRemaining")
        accel_cert_id = entry.get("accelCertificateId") or ""
        needs_bind = False
        reason = ""
        if not accel_cert_id:
            needs_bind = True
            reason = "加速域名尚未绑定证书"
        elif accel_cert_id != cert_id:
            needs_bind = True
            reason = "加速证书与站点部署的证书不一致"
        elif not isinstance(accel_days, int):
            needs_bind = True
            reason = "无法读取加速证书有效期"
        elif accel_days < 0:
            needs_bind = True
            reason = "加速证书已过期"
        elif accel_days <= ACCEL_EXPIRING_DAYS:
            needs_bind = True
            reason = "加速证书即将到期"
        else:
            panel_expiry = _parse_expiry(_panel_expiry(panel_cert)) if panel_cert is not None else None
            accel_expiry = _parse_expiry(entry.get("accelExpireTime"))
            if panel_expiry is not None and accel_expiry is not None and panel_expiry > accel_expiry:
                needs_bind = True
                reason = "面板已换发新证书"

        if not needs_bind:
            row["status"] = "unchanged"
            row["action"] = "加速证书已与站点一致"
            return row

        if self._accel_cooldown(state, host):
            row["status"] = "sync_failed"
            row["action"] = "上次同步失败，冷却中：" + _as_text((state.get(host) or {}).get("lastResult"))
            return row

        if not cert_id:
            row["status"] = "bind_pending"
            if entry.get("bindable"):
                row["action"] = "面板尚未记录对应证书，请稍后再同步（面板会自动绑定）"
            else:
                row["action"] = "当前加速插件不支持自动绑定证书"
            return row

        if dry_run:
            row["status"] = "updated"
            row["action"] = reason + "（预演，未执行）"
            return row

        ok, message, _data = self._accel_bind(entry, hosts, cert_id)
        if ok:
            row["status"] = "updated"
            row["changed"] = True
            row["action"] = reason + "，已同步到加速域名"
            self._accel_state_update(state, host, True, row["action"], {"certId": cert_id})
            _write_log("已同步加速证书：" + host + " <- certId=" + cert_id + "（" + reason + "）")
        else:
            row["status"] = "sync_failed"
            row["action"] = "加速证书同步失败：" + _redact_secret_url(message)[:200]
            self._accel_state_update(state, host, False, row["action"], {"certId": cert_id})
            _write_log("加速证书同步失败：" + host + " " + _redact_secret_url(message)[:200])
        return row

    def _accel_local_source(self, hosts, cname=""):
        """Local (BaoTa) certificate copy used for an accelerated host."""
        candidates = []
        for value in (cname, hosts[0] if hosts else ""):
            name = _as_text(value).strip().lower().rstrip(".")
            if not name:
                continue
            for candidate in _accel_local_cert_paths(name):
                if candidate not in candidates:
                    candidates.append(candidate)
        site_names = []
        for value in (cname, hosts[0] if hosts else ""):
            candidate = _safe_site_name(value)
            if candidate and candidate not in site_names:
                site_names.append(candidate)
        for value in hosts[1:]:
            candidate = _safe_site_name(value)
            if candidate and candidate not in site_names:
                site_names.append(candidate)
        for name in site_names:
            for candidate in _configured_site_cert_paths(name):
                if candidate not in candidates:
                    candidates.append(candidate)
            cert_dir = os.path.realpath(os.path.join("/www/server/panel/vhost/cert", name))
            for candidate in (cert_dir + "/fullchain.pem", cert_dir + "/cert.pem"):
                if candidate not in candidates:
                    candidates.append(candidate)
        for candidate in candidates:
            summary = _cert_summary_from_file(candidate)
            if summary and summary.get("names"):
                return summary
        return None

    def index(self, args):
        return self.get_overview(args)

    # ── Overview page data ───────────────────────────────────────
    def get_overview(self, args):
        cfg = _get_config() or {}
        server_url = (cfg.get("serverUrl") or "").strip()
        has_token = bool((cfg.get("apiToken") or "").strip())
        auto_sync = cfg.get("autoSync", False)
        last_sync = cfg.get("lastSyncAt", "")

        # Fetch certificate count from the panel
        cert_count = 0
        expiring_count = 0
        expired_count = 0
        missing_count = 0
        connection_ok = False
        error_msg = ""
        # The panel's OWN auto-renew scheduler state (the source of truth). We
        # surface it so the plugin never claims "自动续期已开启" while the panel
        # side is actually off (or vice-versa) — this is the "真同步" the user
        # wants: one status, read live from the panel each time.
        panel_renew = None
        plugin_update = None
        if server_url and has_token:
            try:
                data = _panel_get("/ssl/certificates?credentialId=all&page=1&limit=200")
                if data.get("success"):
                    connection_ok = True
                    cert_count = (data.get("pagination") or {}).get("total", 0)
                    for cert in data.get("data") or []:
                        health = _certificate_health(cert, int(cfg.get("renewDays") or 30))
                        if health["state"] == "expired":
                            expired_count += 1
                        elif health["state"] == "expiring":
                            expiring_count += 1
                        if health["state"] == "unknown":
                            missing_count += 1
                else:
                    error_msg = data.get("message", "连接失败")
            except Exception as e:
                error_msg = str(e)
            # Read the panel-side auto-renew toggle (best-effort).
            try:
                ar = _panel_get("/ssl/auto-renew")
                if ar.get("success"):
                    d = ar.get("data") or {}
                    panel_renew = {
                        "enabled": bool(d.get("enabled")),
                        "days": int(d.get("days") or 7),
                        "lastRunAt": d.get("lastRunAt") or "",
                        "lastResult": d.get("lastResult") or "",
                    }
            except Exception:
                panel_renew = None
            # Check whether a newer plugin release is expected by the panel.
            try:
                pv = _panel_get("/ssl/plugin-version")
                if pv.get("success"):
                    expected = str((pv.get("data") or {}).get("expectedVersion") or "").strip()
                    if expected and expected != PLUGIN_VERSION:
                        def _vtuple(text):
                            return tuple(int(x) for x in re.findall(r"\d+", text)[:4]) or (0,)
                        if _vtuple(expected) > _vtuple(PLUGIN_VERSION):
                            plugin_update = {
                                "expectedVersion": expected,
                                "currentVersion": PLUGIN_VERSION,
                                "releaseNotes": str((pv.get("data") or {}).get("releaseNotes") or ""),
                            }
            except Exception:
                pass

        # Effective auto-renew = panel scheduler OR the local BaoTa cron. When we
        # can read the panel state, it is authoritative; fall back to the local
        # flag only when the panel is unreachable.
        effective_auto = (panel_renew["enabled"] if panel_renew else bool(auto_sync))

        return {
            "configured": bool(server_url and has_token),
            "serverUrl": server_url,
            "autoSync": bool(auto_sync),
            "autoRenew": effective_auto,
            "panelRenew": panel_renew,
            "lastSyncAt": last_sync,
            "connectionOk": connection_ok,
            "certCount": cert_count,
            "expiringCount": expiring_count,
            "expiredCount": expired_count,
            "unknownExpiryCount": missing_count,
            "lastCheckAt": cfg.get("lastCertificateCheckAt", ""),
            "lastCheckResult": cfg.get("lastCertificateCheckResult", ""),
            "lastSiteCheckAt": cfg.get("lastSiteCheckAt", ""),
            "lastSiteCheckResult": cfg.get("lastSiteCheckResult", ""),
            "pluginVersion": PLUGIN_VERSION,
            "pluginUpdate": plugin_update,
            "error": error_msg,
            "allowedSites": cfg.get("allowedSites") or [],
            "allowedSources": cfg.get("allowedSources") or ["tencent", "letsencrypt"],
            "availableSites": [site.get("name") for site in _list_bt_sites() if site.get("name")],
        }


    # ── Save connection settings ─────────────────────────────────
    def save_config(self, args):
        server_url = _validate_server_url(getattr(args, "serverUrl", ""))
        api_token = str(getattr(args, "apiToken", "") or "").strip()
        auto_sync = getattr(args, "autoSync", False)
        auto_sync = bool(auto_sync) and str(auto_sync) != "false"
        # Optional renew-window (days before expiry). Kept in sync with the panel.
        renew_days_raw = getattr(args, "renewDays", None)
        current_cfg = _get_config() or {}
        allowed_sites_raw = _normalize_string_list(getattr(args, "allowedSites", current_cfg.get("allowedSites") or []))
        allowed_sources_raw = _normalize_string_list(getattr(args, "allowedSources", current_cfg.get("allowedSources") or ["tencent", "letsencrypt"]))
        if not server_url:
            return public.ReturnMsg(False, "服务器地址无效；公网地址必须使用 HTTPS")

        # A blank token means "keep the existing one" (so editing other fields
        # doesn't force re-entering the secret). Require a token on first setup.
        existing_token = (_get_config("apiToken") or "").strip()
        if not api_token and not existing_token:
            return public.ReturnMsg(False, "请填写 API Token")

        known_sites = set(site.get("name") for site in _list_bt_sites() if site.get("name"))
        unsafe_sites = [name for name in allowed_sites_raw if not _safe_site_name(name) or name not in known_sites]
        if unsafe_sites:
            return public.ReturnMsg(False, "部署站点白名单包含不存在或不安全的站点: " + "、".join(unsafe_sites))
        allowed_sources = [source.lower() for source in allowed_sources_raw if source.lower() in ("tencent", "letsencrypt")]
        if not allowed_sources:
            return public.ReturnMsg(False, "至少选择一个允许部署的证书来源")
        _set_config("serverUrl", server_url)
        if api_token:
            _set_config("apiToken", api_token)
        _set_config("autoSync", auto_sync)
        _set_config("allowedSites", allowed_sites_raw)
        _set_config("allowedSources", allowed_sources)

        # 真同步：push the toggle to the panel's OWN auto-renew scheduler so the
        # plugin switch and the panel switch never diverge. When the plugin turns
        # auto-renew ON/OFF, the panel-side scheduler follows; the local BaoTa
        # cron (installed by install.sh) then acts as a redundant trigger.
        panel_synced = None
        try:
            renew_days = None
            if renew_days_raw is not None and str(renew_days_raw).strip() != "":
                try:
                    renew_days = max(1, min(60, int(renew_days_raw)))
                except Exception:
                    renew_days = None
                if renew_days is not None:
                    _set_config("renewDays", renew_days)
            payload = {"enabled": auto_sync}
            if renew_days is not None:
                payload["days"] = renew_days
            ar = _panel_post("/ssl/auto-renew", payload)
            panel_synced = bool(ar.get("success"))
        except Exception:
            panel_synced = None

        public.WriteLog("DNS面板SSL同步", "更新连接配置（自动续期=" + ("开" if auto_sync else "关") + "，面板同步=" + str(panel_synced) + "）")
        msg = "配置已保存"
        if panel_synced is True:
            msg += "，已同步面板自动续期开关"
        elif panel_synced is False:
            msg += "（面板自动续期同步失败，请检查 Token 权限）"
        return public.ReturnMsg(True, msg)

    # ── Toggle auto-renew (真同步: panel scheduler + local cron) ──
    def set_auto_renew(self, args):
        """Flip auto-renew from the overview switch.

        Writes the local flag AND pushes to the panel's own auto-renew
        scheduler so the two switches always agree. Reuses the existing
        renewDays if the caller doesn't supply one."""
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")

        enabled_raw = getattr(args, "enabled", False)
        enabled = bool(enabled_raw) and str(enabled_raw) != "false"
        _set_config("autoSync", enabled)

        renew_days = None
        rd_raw = getattr(args, "renewDays", None)
        if rd_raw is not None and str(rd_raw).strip() != "":
            try:
                renew_days = max(1, min(60, int(rd_raw)))
                _set_config("renewDays", renew_days)
            except Exception:
                renew_days = None
        if renew_days is None:
            try:
                renew_days = int(cfg.get("renewDays") or 0) or None
            except Exception:
                renew_days = None

        payload = {"enabled": enabled}
        if renew_days is not None:
            payload["days"] = renew_days
        panel_synced = None
        try:
            ar = _panel_post("/ssl/auto-renew", payload)
            panel_synced = bool(ar.get("success"))
        except Exception:
            panel_synced = None

        public.WriteLog("DNS面板SSL同步", "切换自动续期=" + ("开" if enabled else "关") + "，面板同步=" + str(panel_synced))
        if panel_synced is False:
            return public.ReturnMsg(True, ("已" + ("开启" if enabled else "关闭") + "本机自动续期，但面板同步失败（请检查 Token 权限）"))
        return public.ReturnMsg(True, "自动续期已" + ("开启" if enabled else "关闭") + "（面板 + 本机已同步）")

    # ── Certificate health/reconciliation ───────────────────────
    def check_certificates(self, args):
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")
        renew_days = int(getattr(args, "renewDays", None) or cfg.get("renewDays") or 30)
        result = _panel_post("/ssl/certificates/reconcile", {"credentialId": "all"}, timeout=120)
        cert_result = _panel_get("/ssl/certificates?credentialId=all&page=1&limit=500")
        if not cert_result.get("success"):
            return public.ReturnMsg(False, cert_result.get("message", "证书检查失败"))
        certs = cert_result.get("data") or []
        health = []
        for cert in certs:
            item = dict(cert)
            item["health"] = _certificate_health(item, renew_days)
            health.append(item)
        due = [x for x in health if x["health"].get("needsRenewal")]
        now_text = time.strftime("%Y-%m-%d %H:%M:%S")
        summary = {"checked": len(health), "needsRenewal": len(due), "expired": sum(1 for x in due if x["health"]["state"] == "expired"), "reconcile": result.get("data") or {}}
        _set_config("lastCertificateCheckAt", now_text)
        _set_config("lastCertificateCheckResult", json.dumps(summary, ensure_ascii=False))
        public.WriteLog("DNS面板SSL同步", "证书健康检查：检查 " + str(len(health)) + "，待续期 " + str(len(due)))
        return {"success": True, "message": "证书检查完成", "data": summary, "certificates": health}

    # ── Per-site certificate update detection ───────────────────
    # ── Per-site certificate update detection ───────────────────
    def check_site_certificates(self, args):
        """Compare every BaoTa site's live certificate with the panel's best
        available certificate and report what needs updating.

          ok        站点当前证书有效，且面板没有更合适的证书
          update    面板存在适合该站点的证书（覆盖缺口或同一证书的换发）
          expiring  站点证书临近到期，面板暂无更新版本
          expired   站点证书已过期，面板暂无可用替换
          missing   站点尚无证书，面板已有可用证书
          none      站点无证书，面板也无可用证书
          error     无法读取站点证书
        """
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")
        renew_days = _to_int(cfg.get("renewDays"), 30) or 30

        cert_result = _panel_get("/ssl/certificates?credentialId=all&page=1&limit=500")
        if not cert_result.get("success"):
            return public.ReturnMsg(False, cert_result.get("message", "获取面板证书失败"))
        deployable = [
            cert for cert in (cert_result.get("data") or [])
            if (cert.get("status") == "issued" or cert.get("isUploaded"))
            and _certificate_health(cert, renew_days)["state"] != "expired"
        ]
        deployable = _dedup_latest_by_domain(deployable)

        allowed_sites = set(_as_text(item) for item in (cfg.get("allowedSites") or []) if _as_text(item))
        allowed_sources = set(_as_text(item).lower() for item in (cfg.get("allowedSources") or ["tencent", "letsencrypt"]))
        sites = _list_bt_sites()

        items = []
        updates = 0
        for site in sites:
            name = _as_text(site.get("name")).strip()
            if not name:
                continue
            if allowed_sites and name not in allowed_sites:
                continue
            try:
                item = self._site_certificate_report(site, deployable, allowed_sources, renew_days)
            except Exception as exc:
                item = {
                    "site": name,
                    "hosts": [name],
                    "deployed": False,
                    "installedCerts": [],
                    "panelCerts": [],
                    "state": "error",
                    "action": "检测失败：" + str(exc)[:120],
                }
            if item.get("state") in ("update", "missing", "error"):
                updates += 1
            items.append(item)

        summary = {
            "sites": len(items),
            "needUpdate": updates,
            "expired": sum(1 for entry in items if entry.get("state") == "expired"),
            "expiring": sum(1 for entry in items if entry.get("state") == "expiring"),
            "ok": sum(1 for entry in items if entry.get("state") == "ok"),
        }
        _set_config("lastSiteCheckAt", time.strftime("%Y-%m-%d %H:%M:%S"))
        _set_config("lastSiteCheckResult", json.dumps(summary, ensure_ascii=False))
        _write_log("站点证书检测：共 " + str(len(items)) + " 个站点，待更新 " + str(updates))
        return {"success": True, "message": "站点证书检测完成", "data": {"summary": summary, "items": items}}

    def _site_certificate_report(self, site, deployable, allowed_sources, renew_days):
        """Per-site report row; a single bad site never breaks the whole check."""
        name = _as_text(site.get("name")).strip()
        hosts = [name] + [_as_text(item).strip() for item in (site.get("domains") or []) if _as_text(item).strip()]
        hosts = [host for host in hosts if host]

        installed_certs = []
        read_error = ""
        try:
            installed_certs = _installed_cert_summaries(name)
        except Exception as exc:
            read_error = str(exc)
        for entry in installed_certs:
            entry["daysRemaining"] = _days_until(entry.get("expiry"))
        best_installed = installed_certs[0] if installed_certs else None

        candidates = []
        for cert in deployable:
            source = _source_of(cert)
            if source not in allowed_sources:
                continue
            names = _cert_names_from_panel_cert(cert)
            if not names:
                continue
            coverage = _names_coverage_score(names, hosts)
            if coverage <= 0:
                continue
            candidates.append({
                "id": cert.get("remoteCertId") or "",
                "credentialId": cert.get("credentialId") or "",
                "domain": cert.get("domain") or "",
                "names": names,
                "coverage": coverage,
                "daysRemaining": _days_remaining(cert),
                "source": source,
                "sourceLabel": _source_label(cert),
                "supersede": bool(best_installed) and _is_supersede(names, best_installed.get("names") or []),
                "coversAll": coverage >= len(hosts),
            })
        candidates.sort(key=lambda entry: (
            0 if entry["supersede"] else 1,
            0 if entry["coversAll"] else 1,
            -entry["coverage"],
            -(entry["daysRemaining"] if entry["daysRemaining"] is not None else 99999),
        ))
        best_cert = candidates[0] if candidates else None

        item = {
            "site": name,
            "hosts": hosts,
            "deployed": bool(installed_certs),
            "staleSites": [],
            "staleCertDomain": "",
            "installedCerts": [
                {
                    "names": entry.get("names") or [],
                    "daysRemaining": entry.get("daysRemaining"),
                    "path": entry.get("path") or "",
                    "sources": [_SOURCE_LABELS.get(_as_text(src).strip().lower(), src) for src in (entry.get("sources") or [])] or ["手工部署"],
                    "chainComplete": entry.get("chainComplete", True),
                }
                for entry in installed_certs
            ],
            "installedNames": (best_installed or {}).get("names") or [],
            "installedDaysRemaining": (best_installed or {}).get("daysRemaining"),
            "panelCerts": candidates,
            "bestCertDomain": (best_cert or {}).get("domain") or "",
            "bestCertId": (best_cert or {}).get("id") or "",
            "bestCertCredentialId": (best_cert or {}).get("credentialId") or "",
            "bestCertDaysRemaining": (best_cert or {}).get("daysRemaining"),
            "source": (best_cert or {}).get("source") or "",
        }

        if read_error and not installed_certs:
            item["state"] = "error"
            item["action"] = "无法读取站点证书：" + read_error[:120]
            return item

        installed_days = (best_installed or {}).get("daysRemaining")
        if not installed_certs:
            if best_cert:
                item["state"] = "missing"
                item["action"] = "站点尚未部署证书，可部署面板证书"
            else:
                item["state"] = "none"
                item["action"] = "无需处理（面板暂无可用证书）"
            return item

        if installed_days is None:
            item["state"] = "error"
            item["action"] = "无法解析站点证书有效期，建议重新部署"
            return item

        if installed_days < 0:
            if best_cert:
                item["state"] = "update"
                item["action"] = "站点证书已过期，立即部署面板证书"
            else:
                item["state"] = "expired"
                item["action"] = "站点证书已过期，面板暂无可用替换，请先申请证书"
            return item

        installed_names = best_installed.get("names") or []
        missing_hosts = [host for host in hosts if not any(_name_covers(cn, host) for cn in installed_names)]
        covering_missing = bool(best_cert) and all(
            any(_name_covers(cn, host) for cn in best_cert["names"]) for host in missing_hosts
        )
        if missing_hosts and covering_missing:
            item["state"] = "update"
            item["action"] = "现有证书未覆盖：" + "、".join(missing_hosts[:3]) + "，可部署面板候选证书"
            return item
        if missing_hosts:
            item["state"] = "error"
            item["action"] = "现有证书未覆盖：" + "、".join(missing_hosts[:3]) + "，请检查证书配置"
            return item

        if best_cert and best_cert.get("supersede"):
            candidate_days = best_cert.get("daysRemaining")
            # A site that already serves a valid certificate of this exact family
            # is left alone: the panel offering a renewed copy is not a reason to
            # overwrite a certificate the user deployed and manages themselves.
            # Only surface it once the deployed certificate is near expiry, which
            # the expiring branch below reports.
            if candidate_days is not None and candidate_days > installed_days and installed_days <= renew_days:
                item["state"] = "update"
                item["action"] = "面板已换发同一证书，剩余 " + str(installed_days) + " → " + str(candidate_days) + " 天"
                return item

        if best_cert and best_cert.get("supersede") and best_cert.get("coversAll"):
            item["staleSites"] = [name]
            item["staleCertDomain"] = best_cert.get("domain") or ""
        if installed_days <= renew_days:
            item["state"] = "expiring"
            item["action"] = "站点证书临近到期（剩余 " + str(installed_days) + " 天），面板证书未更新，可先触发续期"
            return item

        item["state"] = "ok"
        item["action"] = "站点证书有效，无需更新"
        return item
    # ── List certificates from the DNS panel ─────────────────────
    def get_certificates(self, args):
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return {"success": False, "message": "请先配置连接信息", "data": []}

        keyword = _as_text(getattr(args, "keyword", "")).strip()
        path = "/ssl/certificates?credentialId=all&page=1&limit=500"
        if keyword:
            path += "&search=" + keyword
        raw = _http_request(_panel_api(path), headers=_panel_headers())
        try:
            data = json.loads(raw)
        except Exception:
            return {"success": False, "message": "解析响应失败", "data": []}

        if not data.get("success"):
            return {"success": False, "message": data.get("message", "获取失败"), "data": []}

        certs = data.get("data") or []
        renew_days = _to_int(cfg.get("renewDays"), 30) or 30
        issued = [
            cert for cert in certs
            if (cert.get("status") == "issued" or cert.get("isUploaded"))
            and _certificate_health(cert, renew_days)["state"] != "expired"
        ]
        issued = _dedup_latest_by_domain(issued)
        issued.sort(key=lambda cert: (_as_text(cert.get("domain"))))

        sites = _list_bt_sites()
        installed_cache = {}

        def _installed_for(site_name):
            if site_name not in installed_cache:
                try:
                    installed_cache[site_name] = _installed_cert_summary(site_name)
                except Exception:
                    installed_cache[site_name] = None
            return installed_cache[site_name]

        # EdgeOne acceleration certificate bindings (domain -> binding). Lets the
        # plugin show whether the CDN edge already serves the same cert, so the
        # user can spot the "site OK but edge expired" mismatch at a glance.
        accel_bindings = {}
        try:
            eb = _panel_get("/ssl/edgeone-bindings")
            if eb.get("success"):
                for b in (eb.get("data") or []):
                    dn = _as_text(b.get("domainName")).strip().lower().rstrip(".")
                    if dn:
                        accel_bindings[dn] = b
        except Exception:
            accel_bindings = {}

        site_domains = dict((_as_text(s.get("name")).strip(), list(s.get("domains") or [])) for s in sites)
        for cert in issued:
            names = _cert_names_from_panel_cert(cert)
            cert_expiry = _parse_expiry(cert.get("notAfter"))
            matched = _match_sites_for_domain(cert.get("domain"), sites)
            matched_names = [_as_text(site.get("name")) for site in matched if site.get("name")]
            cert["matchedSite"] = matched_names[0] if matched_names else ""
            cert["matchedSites"] = matched_names

            # EdgeOne acceleration status for this certificate's domain(s).
            accel_status = _edgeone_binding_status(cert, accel_bindings)
            cert["edgeOne"] = accel_status

            deployed_sites = []
            pending_sites = []
            deployed_via = {}
            for name in matched_names:
                installed = _installed_for(name)
                if not installed or not installed.get("names"):
                    pending_sites.append(name)
                    continue
                installed_names = installed.get("names") or []
                # The question is whether the site's own certificate covers the
                # site's own hosts. Comparing against the panel certificate's
                # names instead is what made every site that serves its own
                # exact-domain certificate look undeployed as soon as the panel
                # offered a wildcard for the same parent domain.
                site_hosts = [name] + [_as_text(item).strip() for item in (site_domains.get(name) or [])]
                site_hosts = [host for host in site_hosts if host]
                if not site_hosts:
                    site_hosts = names
                covered = _names_coverage_score(installed_names, site_hosts) == len(site_hosts)
                if not covered:
                    pending_sites.append(name)
                    continue
                deployed_sites.append(name)
                deployed_via[name] = _deployed_source_label(installed)
                installed_expiry = installed.get("expiry")
                if cert_expiry is not None and installed_expiry is not None and installed_expiry < cert_expiry:
                    cert.setdefault("staleSites", []).append(name)
            cert["deployedSites"] = deployed_sites
            cert["deployedVia"] = deployed_via
            cert["pendingSites"] = pending_sites
            cert["staleSites"] = cert.get("staleSites", [])
            cert["deployed"] = bool(deployed_sites) and not pending_sites

            cert["sourceLabel"] = _source_label(cert)
            cert["daysRemaining"] = _days_remaining(cert)
            cert["autoRenewLabel"] = _auto_renew_label(cert)
        return {"success": True, "data": issued, "total": len(issued)}
    def get_sites(self, args):
        sites = _list_bt_sites()
        if sites:
            return {"success": True, "data": sites}
        return {"success": True, "data": [], "debug": _diagnose_sites()}

    # ── Deploy a certificate to a BaoTa site ─────────────────────
    def deploy(self, args):
        cert_id = str(getattr(args, "certId", "") or "").strip()
        credential_id = str(getattr(args, "credentialId", "") or "").strip()
        site_name = _safe_site_name(getattr(args, "siteName", ""))
        force = bool(getattr(args, "force", False))

        if not cert_id or not site_name:
            return public.ReturnMsg(False, "缺少证书ID或站点名")
        known_site = next((s for s in _list_bt_sites() if s.get("name") == site_name), None)
        if not known_site:
            return public.ReturnMsg(False, "站点不存在或名称不安全")

        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")
        allowed_sites = set(str(x) for x in (cfg.get("allowedSites") or []) if str(x))
        if allowed_sites and site_name not in allowed_sites:
            return public.ReturnMsg(False, "目标站点不在部署白名单")

        # Fetch PEM content
        pem_path = "/ssl/certificates/" + cert_id + "/pem?credentialId=" + credential_id
        raw = _http_request(_panel_api(pem_path), headers=_panel_headers())
        try:
            data = json.loads(raw)
        except Exception:
            return public.ReturnMsg(False, "解析证书响应失败")

        if not data.get("success"):
            return public.ReturnMsg(False, data.get("message", "获取证书内容失败"))

        public_key = (data.get("data") or {}).get("publicKey", "")
        private_key = (data.get("data") or {}).get("privateKey", "")
        if not public_key or not private_key:
            return public.ReturnMsg(False, "证书公钥或私钥为空")

        # Complete the chain before anything else: sources that hand over only a
        # leaf certificate would otherwise leave nginx serving a chain the
        # browser cannot build, and https would report 不安全.
        cert_dir_target = os.path.realpath(os.path.join("/www/server/panel/vhost/cert", site_name))
        public_key, added_count, chain_note = _complete_certificate_chain(
            public_key, site_name, cert_dir_target,
        )
        site_hosts = [site_name] + list(known_site.get("domains") or [])
        valid, validation_error = _validate_pem_pair(public_key, private_key, site_hosts)
        if not valid:
            return public.ReturnMsg(False, validation_error)

        # ── Downgrade protection ────────────────────────────────
        # The invariant: hostname coverage never shrinks, and among equally
        # covering certs the fresher one wins. This blocks a single-name cert
        # (account.example.com) from overwriting a wildcard (*.example.com)
        # the site relies on, and stops stale event replays of superseded
        # certs — while still allowing a wildcard to replace a narrower cert.
        # Manual deploys pass force=True; automatic sync keeps the invariant.
        if not force:
            installed = _installed_cert_summary(site_name)
            if installed and installed.get("expiry"):
                from datetime import datetime, timezone
                now_utc = datetime.now(timezone.utc)
                installed_days = (installed["expiry"] - now_utc).total_seconds() / 86400
                if installed_days > 1:  # only protect a still-valid cert
                    new_names = _cert_names_from_pem(public_key)
                    installed_names = installed.get("names") or []
                    if new_names and installed_names:
                        hosts = [str(h).strip() for h in site_hosts if str(h).strip()]
                        covered_new = {h for h in hosts if any(_name_covers(n, h) for n in new_names)}
                        covered_old = {h for h in hosts if any(_name_covers(n, h) for n in installed_names)}
                        new_expiry = _cert_not_after_from_pem(public_key)
                        skip_reason = ""
                        if covered_old - covered_new:
                            skip_reason = "当前证书覆盖更广（" + "、".join(sorted(covered_old - covered_new)) + "）"
                        elif covered_new == covered_old:
                            # Equal coverage: only a strictly fresher cert may replace.
                            if new_expiry is None or new_expiry <= installed["expiry"]:
                                if new_expiry is not None and new_expiry == installed["expiry"]:
                                    skip_reason = "证书未变化，无需重复部署"
                                else:
                                    skip_reason = "替换证书到期时间不晚于当前证书"
                        else:
                            # Strictly wider coverage — allow, but never swap in
                            # a cert that is about to expire.
                            if new_expiry is None or (new_expiry - now_utc).total_seconds() < 3 * 86400:
                                skip_reason = "替换证书有效期过短"
                        if skip_reason:
                            public.WriteLog(
                                "DNS面板SSL同步",
                                "跳过部署（防止降级覆盖）：站点 " + site_name + " " + skip_reason,
                            )
                            return {
                                "status": True, "skipped": True,
                                "msg": "已跳过：站点 " + site_name + " " + skip_reason
                                       + "，自动部署不会降低证书质量；如需强制替换请在「手动部署」选择后重试",
                            }

        # Write cert files to BaoTa vhost cert directory
        cert_dir = os.path.realpath(os.path.join("/www/server/panel/vhost/cert", site_name))
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        fullchain_path = cert_dir + "/fullchain.pem"
        privkey_path = cert_dir + "/privkey.pem"

        fingerprint = hashlib.sha256((public_key + "\x00" + private_key).encode("utf-8")).hexdigest()
        deployed_fingerprints = cfg.get("deployedFingerprints") or {}
        if deployed_fingerprints.get(site_name) == fingerprint and _cert_deployed(site_name):
            return public.ReturnMsg(True, "证书未变化，无需重复部署")

        backups = {}
        for target in (fullchain_path, privkey_path):
            backups[target] = None
            if os.path.exists(target):
                backup = target + ".dnspanel.bak"
                with open(target, "rb") as src:
                    _atomic_write(backup, src.read())
                backups[target] = backup
        try:
            _atomic_write(fullchain_path, public_key)
            _atomic_write(privkey_path, private_key)
        except Exception as e:
            self._rollback_deploy(backups, None)
            return public.ReturnMsg(False, "证书原子写入失败: " + str(e))

        # For reverse proxy sites, directly modify nginx config
        web_server = str(public.GetWebServer() or "").strip().lower()
        nginx_conf_backup = None
        if web_server in ("nginx", "openresty"):
            try:
                nginx_conf_backup = self._enable_nginx_ssl_for_proxy(site_name, fullchain_path, privkey_path)
            except Exception as e:
                possible_backup = "/www/server/panel/vhost/nginx/" + site_name + ".conf.dnspanel.bak"
                self._rollback_deploy(backups, possible_backup if os.path.exists(possible_backup) else nginx_conf_backup)
                return public.ReturnMsg(False, "更新 Nginx/OpenResty 配置失败，已恢复原证书: " + str(e))

        # Reload web server
        if web_server in ("nginx", "openresty"):
            nginx_bin = _find_executable([
                "/www/server/nginx/sbin/nginx",
                "/www/server/openresty/nginx/sbin/nginx",
                "nginx",
            ])
            if not nginx_bin:
                self._rollback_deploy(backups, nginx_conf_backup)
                return public.ReturnMsg(False, "未找到 Nginx/OpenResty 可执行文件，已恢复原证书和配置")
            test_ok, test_output = _run_checked([nginx_bin, "-t"])
            public.WriteLog("DNS面板SSL同步", "nginx配置测试: " + test_output)
            if test_ok:
                if subprocess.call([nginx_bin, "-s", "reload"]) != 0:
                    self._rollback_deploy(backups, nginx_conf_backup)
                    return public.ReturnMsg(False, "Nginx 重载失败，已恢复原证书和配置")
                public.WriteLog("DNS面板SSL同步", "nginx已重载")
            else:
                public.WriteLog("DNS面板SSL同步", "nginx配置测试失败，未重载")
                self._rollback_deploy(backups, nginx_conf_backup)
                return public.ReturnMsg(False, "Nginx 配置校验失败，已恢复原证书和配置")
        elif web_server == "apache":
            apache_bin = _find_executable([
                "/www/server/apache/bin/httpd",
                "/usr/sbin/httpd",
                "/usr/sbin/apache2ctl",
                "httpd",
                "apachectl",
            ])
            if not apache_bin:
                self._rollback_deploy(backups, None)
                return public.ReturnMsg(False, "未找到 Apache 可执行文件，已恢复原证书")
            test_ok, test_output = _run_checked([apache_bin, "-t"])
            public.WriteLog("DNS面板SSL同步", "apache配置测试: " + test_output)
            if test_ok:
                if subprocess.call([apache_bin, "-k", "graceful"]) != 0:
                    self._rollback_deploy(backups, None)
                    return public.ReturnMsg(False, "Apache 重载失败，已恢复原证书")
            else:
                self._rollback_deploy(backups, None)
                return public.ReturnMsg(False, "Apache 配置校验失败，已恢复原证书")
        else:
            self._rollback_deploy(backups, nginx_conf_backup)
            return public.ReturnMsg(False, "暂不支持当前 Web 服务: " + (web_server or "unknown"))

        # Only mark the site as SSL-enabled after config validation/reload succeeds.
        try:
            import panelMysql as pm
            db = pm.panelMysql().dbfile("/www/server/panel/data/default.db")
            site_info = db.query("SELECT id FROM sites WHERE name=? LIMIT 1", (site_name,))
            if site_info:
                site_id = site_info[0][0]
                db.execute("UPDATE sites SET ssl=1 WHERE id=?", (site_id,))
                public.WriteLog("DNS面板SSL同步", "数据库更新: ssl=1 for site_id=" + str(site_id))
            db.close()
        except Exception as e:
            public.WriteLog("DNS面板SSL同步", "数据库操作: " + str(e))

        deployed_fingerprints[site_name] = fingerprint
        _set_config("deployedFingerprints", deployed_fingerprints)
        for backup in backups.values():
            if backup:
                try:
                    os.remove(backup)
                except Exception:
                    pass
        if nginx_conf_backup:
            try:
                os.remove(nginx_conf_backup)
            except Exception:
                pass

        public.WriteLog("DNS面板SSL同步", "部署证书到站点 " + site_name + " (certId=" + cert_id + ")")
        success_message = "证书已部署并启用SSL，请刷新页面查看"
        if added_count:
            success_message += " (" + chain_note + ")"
        return public.ReturnMsg(True, success_message)

    def _rollback_deploy(self, backups, nginx_conf_backup):
        for target, backup in backups.items():
            try:
                if backup and os.path.exists(backup):
                    os.replace(backup, target) if hasattr(os, "replace") else os.rename(backup, target)
                elif not backup and os.path.exists(target):
                    os.remove(target)
            except Exception:
                pass
        if nginx_conf_backup:
            try:
                target = nginx_conf_backup[:-len(".dnspanel.bak")]
                os.replace(nginx_conf_backup, target) if hasattr(os, "replace") else os.rename(nginx_conf_backup, target)
            except Exception:
                pass

    def _enable_nginx_ssl_for_proxy(self, site_name, cert_path, key_path, cert_names=None):
        """Point every nginx/OpenResty vhost of the site at the given certificate.

        Handles both shapes: a config that already declares ssl_certificate
        (rewritten in place, including BaoTa's separate SSL include file) and a
        site that never had SSL configured (a generated HTTPS block is added).
        Returns the list of config backups that were created.
        """
        backups = []
        targets = []
        live_conf = None
        for conf_path in _site_vhost_conf_paths(site_name):
            text = _config_text(conf_path, site_name)
            if not text:
                continue
            if "listen 443" in text or "ssl_certificate" in text:
                targets.append(conf_path)
                if live_conf is None and "server {" in text:
                    live_conf = conf_path

        if not targets and live_conf is None:
            primary = "/www/server/panel/vhost/nginx/" + site_name + ".conf"
            if os.path.exists(primary):
                targets.append(primary)

        if not targets:
            _write_log("未找到可用的 nginx 配置文件，仅刷新证书文件：" + str(site_name))
            return backups

        for conf_path in targets:
            conf_content = _config_text(conf_path, site_name)
            if conf_content is None:
                continue
            conf_backup = conf_path + ".dnspanel.bak"
            _atomic_write(conf_backup, _portable_conf_copy(conf_path, conf_content, site_name))
            backups.append(conf_backup)

            if "ssl_certificate" in conf_content:
                new_content = _replace_ssl_certificate_directives(conf_content, cert_path, key_path)
                if "ssl_certificate_rsa" not in new_content:
                    pass
                else:
                    new_content = _insert_directive_into_server(new_content, "ssl_certificate_key_rsa", key_path)
                new_content = _dedupe_ssl_directives(new_content)
                _write_log("已更新站点证书路径：" + conf_path)
            elif "listen 443" in conf_content:
                new_content = conf_content
                _write_log("站点已监听 443 但未内联 ssl_certificate，保持配置不变：" + conf_path)
            else:
                lines = conf_content.split(chr(10))
                brace = 0
                depth = 0
                inserted = False
                for index, line in enumerate(lines):
                    stripped = line.strip()
                    if not inserted and "server" in stripped and "{" in stripped:
                        brace = 1
                    elif brace:
                        brace += stripped.count("{") - stripped.count("}")
                        if brace == 0:
                            indent = "    "
                            redirect = indent + "if ($server_port !~ 443){ return 301 https://$host$request_uri; }"
                            if redirect.strip() not in conf_content:
                                lines.insert(index, redirect)
                                inserted = True
                            break
                match = re.search(r"server_name" + chr(32) + r"+([^;]+);", conf_content)
                server_name_value = match.group(1).strip() if match else "~^"
                block = _https_server_block(site_name, cert_path, key_path, server_name_value, cert_names)
                block += "}"
                for location in re.findall(r"(location" + chr(32) + r"+[^{]+\{[^}]*\})", conf_content, re.DOTALL):
                    block += chr(10) + "    " + location + chr(10)
                new_content = chr(10).join(lines) + block + chr(10)
                _write_log("已添加 HTTPS server 块：" + conf_path)

            _atomic_write(conf_path, new_content)
        return backups
    def get_issue_options(self, args):
        """List credentials the panel exposes for issuing certificates.

        Two independent channels, mirroring the panel's own SSL page:
          • acme (Let's Encrypt): needs a DNS credential (cloudflare / dnspod /
            aliyun) — acme.sh drives DNS-01 itself. Only offered when the panel
            reports acme is available (Docker deploy).
          • tencent: a腾讯云 SSL credential申请免费 DV，面板自动加 DNS 验证记录。
        The DNS-01 automation + validation-record handling all happen server-
        side, so issuance here is 100% consistent with issuing on the panel.
        """
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return {"success": False, "message": "请先配置连接信息"}

        # DNS credentials usable by acme.sh (cloudflare / dnspod / aliyun).
        acme_supported = ("cloudflare", "dnspod", "dnspod_token", "aliyun")
        dns_creds = []
        acme_available = False
        try:
            dc = _panel_get("/dns-credentials?category=dns")
            if dc.get("success"):
                for r in (dc.get("data") or {}).get("credentials", []):
                    prov = str(r.get("provider") or "").strip().lower()
                    if prov in acme_supported:
                        dns_creds.append({
                            "id": r.get("id"),
                            "name": r.get("name"),
                            "provider": prov,
                        })
        except Exception:
            pass

        # Probe whether acme.sh is actually available on the panel: issue-acme
        # returns 503 when not. We infer availability cheaply — if there is at
        # least one usable DNS credential we surface the acme channel and let
        # the panel reject with a clear message if acme.sh is missing.
        acme_available = bool(dns_creds)

        # 腾讯云 SSL credentials (for free DV issuance via ApplyCertificate).
        ssl_creds = []
        try:
            sc = _panel_get("/ssl/credentials")
            if sc.get("success"):
                for r in (sc.get("data") or []):
                    ssl_creds.append({
                        "id": r.get("id"),
                        "name": r.get("name"),
                        "provider": r.get("provider"),
                    })
        except Exception:
            pass

        return {
            "success": True,
            "data": {
                "acmeAvailable": acme_available,
                "dnsCredentials": dns_creds,
                "sslCredentials": ssl_creds,
            },
        }

    def issue_cert(self, args):
        """Apply for a new certificate through the panel, then (optionally)
        deploy it to the matching BaoTa site once it's issued.

        channel='acme'    → POST /ssl/certificates/issue-acme  (Let's Encrypt)
        channel='tencent' → POST /ssl/certificates/apply       (腾讯云 免费 DV)

        Both are async on the panel (DNS-01 propagation), so we return the
        'applying' result immediately; the daily sync / 「立即同步」 deploys the
        cert once签发完成. This keeps the plugin's issuance flow identical to
        the panel's — same endpoints, same auto-DNS, same validation records.
        """
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")

        channel = str(getattr(args, "channel", "") or "").strip().lower() or "acme"
        domain = str(getattr(args, "domain", "") or "").strip().lower().rstrip(".")
        if not domain:
            return public.ReturnMsg(False, "请填写要申请证书的域名")

        import re

        if channel == "acme":
            dns_cred_id = str(getattr(args, "dnsCredentialId", "") or "").strip()
            key_length = str(getattr(args, "keyLength", "") or "2048").strip() or "2048"
            if not dns_cred_id:
                return public.ReturnMsg(False, "请选择用于 DNS 验证的 DNS 凭证")
            payload = {
                "domain": domain,
                "dnsCredentialId": _to_int(dns_cred_id),
                "keyLength": key_length,
            }
            # Optional SANs: comma / space separated.
            alt = str(getattr(args, "altNames", "") or "").strip()
            if alt:
                names = [x.strip().lower().rstrip(".") for x in re.split(r"[\s,]+", alt) if x.strip()]
                if names:
                    payload["altNames"] = names
            data = _panel_post("/ssl/certificates/issue-acme", payload, timeout=60)
            if data.get("success"):
                public.WriteLog("DNS面板SSL同步", "申请 Let's Encrypt 证书：" + domain)
                return public.ReturnMsg(True, data.get("message") or "已提交 Let's Encrypt 签发，请稍后在证书列表查看")
            return public.ReturnMsg(False, data.get("message", "申请失败"))

        if channel == "tencent":
            cred_id = str(getattr(args, "credentialId", "") or "").strip()
            if not cred_id:
                return public.ReturnMsg(False, "请选择腾讯云 SSL 凭证")
            payload = {
                "credentialId": _to_int(cred_id),
                "domain": domain,
                "dvAuthMethod": "DNS",
                "autoDnsRecord": True,
                "autoMatchDns": True,
            }
            data = _panel_post("/ssl/certificates/apply", payload, timeout=120)
            if data.get("success"):
                public.WriteLog("DNS面板SSL同步", "申请腾讯云免费证书：" + domain)
                return public.ReturnMsg(True, data.get("message") or "已提交腾讯云证书申请，请稍后在证书列表查看")
            return public.ReturnMsg(False, data.get("message", "申请失败"))

        return public.ReturnMsg(False, "未知的签发渠道：" + channel)

    # ── Manual sync trigger ──────────────────────────────────────
    def sync_now(self, args):
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")

        # Preferred incremental workflow: atomically claim deployment events,
        # deploy only changed certificates, and report success/failure so the
        # panel can retry with exponential backoff.
        event_mode = False
        event_deployed = 0
        event_failed = 0
        event_skipped = 0
        sites = _list_bt_sites()
        allowed_sites = set(str(x) for x in (cfg.get("allowedSites") or []) if str(x))
        allowed_sources = set(str(x).lower() for x in (cfg.get("allowedSources") or ["tencent", "letsencrypt"]))
        for _index in range(50):
            claim = _panel_post("/ssl/deployment-events/claim", {}, timeout=30)
            if not claim.get("success"):
                break
            event_mode = True
            event = claim.get("data")
            if not event:
                break
            event_id = event.get("id")
            domain = str(event.get("domain") or "").strip().lower()
            source = str(event.get("source") or "").strip().lower()
            matched_sites = _match_sites_for_domain(domain, sites)
            matched_names = [str(site.get("name") or "") for site in matched_sites if site.get("name")]
            allowed_matches = [site for site in matched_sites if not allowed_sites or str(site.get("name") or "") in allowed_sites]
            result_payload = {"status": "failed", "targetName": ", ".join(matched_names), "error": "未找到匹配站点"}
            if source not in allowed_sources:
                result_payload = {"status": "skipped", "error": "证书来源不在部署白名单"}
                event_skipped += 1
            elif matched_sites and not allowed_matches:
                result_payload = {"status": "skipped", "targetName": ", ".join(matched_names), "error": "匹配站点均不在部署白名单"}
                event_skipped += 1
            elif allowed_matches:
                successes = []
                failures = []
                deferred = []
                fingerprints = {}
                for site in allowed_matches:
                    matched = str(site.get("name") or "")
                    try:
                        deploy_args = type("A", (), {})()
                        deploy_args.certId = event.get("remoteCertId", "")
                        deploy_args.credentialId = str(event.get("credentialId", ""))
                        deploy_args.siteName = matched
                        deployed_result = self.deploy(deploy_args)
                        if deployed_result.get("skipped"):
                            # Downgrade protection refused the swap: record the
                            # site in the deferred list. The event itself is
                            # marked skipped (no auto-retry storm); the user can
                            # force-replace via manual deploy or retry from the
                            # panel task center if the situation changes.
                            deferred.append(matched + ": " + str(deployed_result.get("msg") or "跳过"))
                            continue
                        if deployed_result.get("status"):
                            fingerprint = ((_get_config() or {}).get("deployedFingerprints") or {}).get(matched, "")
                            fingerprints[matched] = fingerprint
                            successes.append(matched)
                            event_deployed += 1
                        else:
                            failures.append(matched + ": " + str(deployed_result.get("msg") or "部署失败"))
                            event_failed += 1
                    except Exception as e:
                        failures.append(matched + ": " + str(e))
                        event_failed += 1
                if deferred and not successes and not failures:
                    result_payload = {
                        "status": "skipped",
                        "targetName": ", ".join([str(site.get("name") or "") for site in allowed_matches]),
                        "error": "; ".join(deferred),
                    }
                    event_skipped += 1
                else:
                    result_payload = {
                        "status": "failed" if failures else "success",
                        "targetName": ", ".join([str(site.get("name") or "") for site in allowed_matches]),
                        "fingerprint": json.dumps(fingerprints, ensure_ascii=False, separators=(",", ":")),
                        "error": "; ".join(failures + deferred),
                    }
                    if failures and successes:
                        result_payload["error"] = "部分站点部署失败（成功: " + ", ".join(successes) + "）：" + result_payload["error"]
            else:
                event_failed += 1
            _panel_post("/ssl/deployment-events/" + str(event_id) + "/result", result_payload, timeout=30)

        if event_mode:
            _set_config("lastSyncAt", time.strftime("%Y-%m-%d %H:%M:%S"))
            public.WriteLog("DNS面板SSL同步", "增量同步完成：部署 " + str(event_deployed) + "，失败 " + str(event_failed) + "，跳过 " + str(event_skipped))
            return public.ReturnMsg(True, "增量同步完成：部署 " + str(event_deployed) + " 个，失败 " + str(event_failed) + " 个，跳过 " + str(event_skipped) + " 个")

        # Pull certs and auto-deploy to matching sites by domain
        raw = _http_request(
            _panel_api("/ssl/certificates?credentialId=all&page=1&limit=500"),
            headers=_panel_headers(),
        )
        try:
            data = json.loads(raw)
        except Exception:
            return public.ReturnMsg(False, "解析响应失败")

        if not data.get("success"):
            return public.ReturnMsg(False, data.get("message", "同步失败"))

        certs = data.get("data") or []
        # Deploy only the freshest cert per domain (most remaining validity).
        certs = _dedup_latest_by_domain(
            [c for c in certs if (c.get("status") == "issued" or c.get("isUploaded")) and _certificate_health(c, int(cfg.get("renewDays") or 30))["state"] != "expired"]
        )
        sites = _list_bt_sites()

        deployed = 0
        skipped = 0
        fallback_allowed_sites = set(str(x) for x in (cfg.get("allowedSites") or []) if str(x))
        fallback_allowed_sources = set(str(x).lower() for x in (cfg.get("allowedSources") or ["tencent", "letsencrypt"]))

        # Group deployable certs by the site they cover, choosing per site the
        # BEST candidate (widest hostname coverage, then longest validity) so a
        # lesser cert can never land first and trigger a swap chain.
        def _cert_score_for_hosts(cert, hosts):
            names = _cert_names_from_panel_cert(cert)
            score = _names_coverage_score(names, hosts)
            rem = _days_remaining(cert)
            return score, (rem if rem is not None else 99999)

        site_best: dict = {}
        for cert in certs:
            source = "letsencrypt" if cert.get("provider") == "acme" or cert.get("source") == "letsencrypt" else "tencent"
            if source not in fallback_allowed_sources:
                skipped += 1
                continue
            domain = (cert.get("domain") or "").strip().lower()
            matched_sites = _match_sites_for_domain(domain, sites)
            if not matched_sites:
                skipped += 1
                continue
            deployable_sites = [site for site in matched_sites if not fallback_allowed_sites or str(site.get("name") or "") in fallback_allowed_sites]
            if not deployable_sites:
                skipped += 1
                continue
            for site in deployable_sites:
                site_name = str(site.get("name") or "")
                hosts = [site_name] + [str(d).strip() for d in (site.get("domains") or []) if str(d).strip()]
                score = _cert_score_for_hosts(cert, hosts)
                if score[0] <= 0:
                    continue
                current = site_best.get(site_name)
                if current is None or score > current[0]:
                    site_best[site_name] = (score, cert, site)

        for site_name, (score, cert, site) in site_best.items():
            try:
                args_deploy = type("A", (), {})()
                args_deploy.certId = cert.get("remoteCertId", "")
                args_deploy.credentialId = str(cert.get("credentialId", ""))
                args_deploy.siteName = site_name
                result = self.deploy(args_deploy)
                if result.get("skipped"):
                    skipped += 1  # downgrade protection refused the swap
                elif result.get("status"):
                    deployed += 1
                else:
                    skipped += 1
            except Exception:
                skipped += 1

        # After deploying the fresh certs, ask the panel to prune superseded
        # certs (< keepDays remaining when a healthy newer one exists) and clean
        # up their leftover _dnsauth validation records. Guarded server-side so
        # it never deletes a domain's only/best cert. keepDays follows the
        # configured renew window so prune and renew share one threshold.
        keep_days = _to_int(cfg.get("renewDays")) if cfg.get("renewDays") else 7
        if not isinstance(keep_days, int):
            keep_days = 7
        pruned = 0
        if deployed > 0:
            try:
                praw = _http_request(
                    _panel_api("/ssl/certificates/prune-superseded"),
                    method="POST",
                    headers=_panel_headers(),
                    data={"keepDays": keep_days},
                )
                pdata = json.loads(praw)
                if pdata.get("success"):
                    pruned = len([p for p in (pdata.get("data") or {}).get("pruned", []) if not p.get("error")])
            except Exception:
                pass

        _set_config("lastSyncAt", time.strftime("%Y-%m-%d %H:%M:%S"))
        public.WriteLog("DNS面板SSL同步", "手动同步完成：部署 " + str(deployed) + "，跳过 " + str(skipped) + "，清理 " + str(pruned))
        msg = "同步完成：部署 " + str(deployed) + " 个，跳过 " + str(skipped) + " 个"
        if pruned:
            msg += "，清理过期证书 " + str(pruned) + " 个"
        return public.ReturnMsg(True, msg)

    # ── Auto-sync entry (called by cron) ─────────────────────────
    def auto_sync(self, args):
        cfg = _get_config() or {}
        if not cfg.get("autoSync"):
            return public.ReturnMsg(False, "自动同步未启用")
        # Renew window (days before expiry). Shared with the panel + prune step.
        renew_days = _to_int(cfg.get("renewDays")) if cfg.get("renewDays") else 7
        if not isinstance(renew_days, int):
            renew_days = 7
        # 1) Ask the panel to renew certs expiring within renew_days. The panel
        #    applies new certs and adds DNS validation; issuance completes
        #    asynchronously, so the freshly-issued cert is deployed on a later
        #    run. Safe to call daily — already-issued domains are skipped.
        try:
            _http_request(
                _panel_api("/ssl/certificates/renew-expired"),
                method="POST",
                headers=_panel_headers(),
                data={"renewDays": renew_days},
                timeout=180,
            )
        except Exception:
            pass
        # 2) Deploy the freshest issued cert per domain, then prune superseded
        #    (< renew_days) certs and clean their _dnsauth validation records.
        result = self.sync_now(args)
        # 3) Refresh the site certificate update-detection report so the
        #    overview card always reflects the latest state. Best-effort —
        #    a detection failure must not fail the whole sync run.
        try:
            self.check_site_certificates(type("A", (), {})())
        except Exception as e:
            public.WriteLog("DNS面板SSL同步", "站点证书检测失败: " + str(e))
        return result


# Allow running as a script from a cron task, e.g.:
#   /www/server/panel/pyenv/bin/python dnspanel_ssl_main.py auto_sync
if __name__ == "__main__":
    _action = sys.argv[1] if len(sys.argv) > 1 else "auto_sync"
    _inst = dnspanel_ssl_main()
    _fn = getattr(_inst, _action, None)
    if not _fn:
        print(json.dumps({"status": False, "msg": "unknown action: " + _action}, ensure_ascii=False))
    else:
        try:
            print(json.dumps(_fn(type("A", (), {})()), ensure_ascii=False))
        except Exception as _e:
            print(json.dumps({"status": False, "msg": str(_e)}, ensure_ascii=False))
