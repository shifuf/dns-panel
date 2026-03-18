from __future__ import annotations
import base64
import hashlib
import hmac
import io
import os
import struct
import time
import urllib.parse
import qrcode


def generate_base32_secret(num_bytes: int = 20) -> str:
    raw = os.urandom(max(10, int(num_bytes)))
    return base64.b32encode(raw).decode("ascii").replace("=", "")


def _base32_decode(secret: str) -> bytes:
    s = "".join(ch for ch in str(secret or "").strip().upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s.encode("ascii"))


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = _base32_decode(secret)
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, token: str, step: int = 30, window: int = 1, digits: int = 6) -> bool:
    tok = str(token or "").strip()
    if not tok.isdigit():
        return False
    now_counter = int(time.time() // max(1, step))
    for delta in range(-int(window), int(window) + 1):
        if hmac.compare_digest(_hotp(secret, now_counter + delta, digits), tok):
            return True
    return False


def make_otpauth_url(secret: str, username: str, issuer: str = "DNS Panel") -> str:
    label = f"{issuer}:{username}"
    return (
        "otpauth://totp/"
        + urllib.parse.quote(label, safe="")
        + "?secret="
        + urllib.parse.quote(secret, safe="")
        + "&issuer="
        + urllib.parse.quote(issuer, safe="")
        + "&algorithm=SHA1&digits=6&period=30"
    )


def make_qr_data_url(otpauth_url: str) -> str:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(otpauth_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"

