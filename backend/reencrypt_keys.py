"""Re-encrypt all stored secrets from one ENCRYPTION_KEY to another.

Why: credentials/2FA/SMTP secrets are AES-encrypted with ENCRYPTION_KEY. If the
key changes (e.g. moving from the local default key to a strong key for Docker),
every stored secret must be re-encrypted or it can no longer be decrypted.

Usage (PowerShell):
    $env:OLD_ENCRYPTION_KEY = "please-change-to-32-char-key!!"   # current key
    $env:NEW_ENCRYPTION_KEY = "<the new key>"
    python reencrypt_keys.py

Safe to re-run: rows already using the new key are detected and skipped.
A timestamped copy of the database is made before any change.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Columns holding AES-encrypted text: (table, primary key column, value column).
ENCRYPTED_COLUMNS = [
    ("dns_credentials", "id", "secrets"),
    ("users", "id", "twoFactorSecret"),
    ("users", "id", "cfApiToken"),
    ("users", "id", "smtpPass"),
]

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("REENCRYPT_DB", str((BASE_DIR / "db" / "database.db").resolve())))


def pad_key_32(text: str) -> bytes:
    return str(text or "").ljust(32, "0")[:32].encode("utf-8")


def encrypt_text(plain: str, key: str) -> str:
    raw = str(plain or "").encode("utf-8")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(pad_key_32(key)), modes.CBC(iv))
    enc = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(raw) + padder.finalize()
    body = enc.update(padded) + enc.finalize()
    return f"{iv.hex()}:{body.hex()}"


def decrypt_text(cipher_text: str, key: str) -> str:
    """Decrypt; raises on wrong key / malformed input (PKCS7 padding check)."""
    parts = str(cipher_text).split(":")
    if len(parts) < 2:
        raise ValueError("not encrypted")
    iv = bytes.fromhex(parts[0])
    body = bytes.fromhex(":".join(parts[1:]))
    cipher = Cipher(algorithms.AES(pad_key_32(key)), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(body) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


def main() -> int:
    old_key = os.getenv("OLD_ENCRYPTION_KEY", "please-change-to-32-char-key!!")
    new_key = os.getenv("NEW_ENCRYPTION_KEY") or os.getenv("ENCRYPTION_KEY")
    if not new_key:
        print("ERROR: set NEW_ENCRYPTION_KEY (the target key)", file=sys.stderr)
        return 2
    if old_key == new_key:
        print("OLD and NEW keys are identical — nothing to do.")
        return 0
    if not DB_PATH.is_file():
        print(f"ERROR: database not found: {DB_PATH}", file=sys.stderr)
        return 2

    backup = DB_PATH.with_suffix(f".db.bak-{int(time.time())}")
    shutil.copy2(DB_PATH, backup)
    print(f"Backed up database -> {backup}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    migrated = skipped = failed = 0
    try:
        existing = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table, pk, col in ENCRYPTED_COLUMNS:
            if table not in existing:
                continue
            rows = conn.execute(
                f"SELECT {pk} AS pk, {col} AS val FROM {table} WHERE {col} IS NOT NULL AND {col} != ''"
            ).fetchall()
            for row in rows:
                val = row["val"]
                try:
                    plain = decrypt_text(val, old_key)
                except Exception:
                    # Not decryptable with old key — already new key, or unrelated.
                    try:
                        decrypt_text(val, new_key)
                        skipped += 1
                    except Exception:
                        failed += 1
                        print(f"  ! {table}.{col} pk={row['pk']}: cannot decrypt with old or new key — left unchanged")
                    continue
                conn.execute(
                    f"UPDATE {table} SET {col} = ? WHERE {pk} = ?",
                    (encrypt_text(plain, new_key), row["pk"]),
                )
                migrated += 1
        conn.commit()
    finally:
        conn.close()

    print(f"Done. re-encrypted={migrated} already-new={skipped} unreadable={failed}")
    print(f"If anything looks wrong, restore from: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
