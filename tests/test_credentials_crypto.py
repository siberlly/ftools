"""Tests for opt-in credential decryption (``credentials_crypto``).

These are pure, self-contained unit tests: every container is generated from
synthetic key material at test time, so no real credential ever enters the
repository. They deliberately import only ``credentials_crypto`` (no FastAPI,
no ``fcntl``) so the decryption logic can be exercised on any analysis host.
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
from pathlib import Path

import pytest

from dfir_browser.core.browser_artifacts import credentials_crypto as cc

SECRET_USER = "rafael@example.test"
SECRET_PASS = "hunter2-SUPER-SECRET"

# Deterministic, synthetic key material only.
CHROMIUM_KEY = bytes(range(32))
FIREFOX_SALT = b"\x11" * 32


# ----------------------------------------------------------------------
# Synthetic container builders
# ----------------------------------------------------------------------
def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(payload)) + payload


def _der_seq(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def _der_octets(payload: bytes) -> bytes:
    return _der(0x04, payload)


def _der_int(value: int) -> bytes:
    if value == 0:
        return _der(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der(0x02, raw)


def _der_oid(dotted: str) -> bytes:
    parts = [int(part) for part in dotted.split(".")]
    payload = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        payload.extend(chunk)
    return _der(0x06, bytes(payload))


def _pbes2_container(
    *, entry_salt: bytes, iterations: int, key_length: int, iv: bytes, cipher: bytes
) -> bytes:
    """Build an NSS PBES2 (HMAC-SHA256/AES-256-CBC) container."""
    kdf = _der_seq(
        _der_oid(cc.OID_PBKDF2),
        _der_seq(
            _der_octets(entry_salt),
            _der_int(iterations),
            _der_int(key_length),
            _der_seq(_der_oid(cc.OID_HMAC_SHA256)),
        ),
    )
    encryption = _der_seq(_der_oid(cc.OID_AES_256_CBC), _der_octets(iv))
    return _der_seq(_der_seq(_der_oid(cc.OID_PBES2), _der_seq(kdf, encryption)), _der_octets(cipher))


def _pbkdf2_key(
    *, global_salt: bytes, entry_salt: bytes, iterations: int, key_length: int
) -> bytes:
    import hashlib

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    inner = hashlib.sha1(global_salt).digest()  # empty master password
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=entry_salt,
        iterations=iterations,
    ).derive(inner)


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _login_container(key: bytes, iv: bytes, plaintext: bytes) -> str:
    """Build a base64 NSS SDRM login blob wrapping ``plaintext``."""
    cipher = _aes_cbc_encrypt(key, iv, plaintext)
    blob = _der_seq(
        _der_octets(cc.CKA_ID),
        _der_seq(_der_oid(cc.OID_AES_256_CBC), _der_octets(iv)),
        _der_octets(cipher),
    )
    return base64.b64encode(blob).decode()


def _build_key4_db(path: Path, *, key_material: bytes, entry_salt: bytes = FIREFOX_SALT,
                   iterations: int = 1, tv: bytes = b"password-check\x02\x02") -> bytes:
    """Write a synthetic ``key4.db`` and return the derived SDRM key."""
    key_length = 32
    derived = _pbkdf2_key(
        global_salt=FIREFOX_SALT,
        entry_salt=entry_salt,
        iterations=iterations,
        key_length=key_length,
    )
    # NSS stores a 14-byte octet string; the cipher IV is 0x04 0x0e + those 14
    # bytes. Building it the same way keeps the fixture faithful to NSS.
    stored_iv = b"\x22" * 14
    iv = b"\x04\x0e" + stored_iv
    check_cipher = _aes_cbc_encrypt(derived, iv, tv)
    item2 = _pbes2_container(
        entry_salt=entry_salt,
        iterations=iterations,
        key_length=key_length,
        iv=stored_iv,
        cipher=check_cipher,
    )
    key_stored_iv = b"\x33" * 14
    key_iv = b"\x04\x0e" + key_stored_iv
    key_cipher = _aes_cbc_encrypt(derived, key_iv, key_material)
    a11 = _pbes2_container(
        entry_salt=entry_salt,
        iterations=iterations,
        key_length=key_length,
        iv=key_stored_iv,
        cipher=key_cipher,
    )
    connection = sqlite3.connect(str(path))
    connection.executescript(
        """
        CREATE TABLE metadata(item1 BLOB, item2 BLOB, id TEXT);
        CREATE TABLE nssPrivate(id INTEGER PRIMARY KEY, a11 BLOB, a102 BLOB);
        """
    )
    connection.execute(
        "INSERT INTO metadata VALUES (?, ?, 'password')", (FIREFOX_SALT, item2)
    )
    connection.execute(
        "INSERT INTO nssPrivate VALUES (1, ?, ?)", (a11, cc.CKA_ID)
    )
    connection.commit()
    connection.close()
    return key_material


# ----------------------------------------------------------------------
# Bounded helpers
# ----------------------------------------------------------------------
def test_clip_text_is_bounded():
    assert cc.clip_text("  hello\x00 ", 64) == "  hello\x00 "
    assert cc.clip_text(None, 64) is None
    assert cc.clip_text("x" * 10, 4) == "xxxx"
    assert cc.clip_text(b"bytes", 64) == "bytes"
    assert cc.clip_text(b"\xff\xfe", 64) == "\ufffd\ufffd"


def test_read_bytes_is_bounded(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"a" * 1000)
    assert len(cc.read_bounded_file(path, 1000)) == 1000
    # Over-limit artifacts are rejected, never silently truncated.
    with pytest.raises(cc.DecryptionFailed):
        cc.read_bounded_file(path, 64)


# ----------------------------------------------------------------------
# Chromium OSCrypt
# ----------------------------------------------------------------------
def _v10_blob(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = b"\x07" * 12
    return b"v10" + nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def test_chromium_v10_aes_gcm_roundtrip():
    blob = _v10_blob(CHROMIUM_KEY, SECRET_PASS.encode())
    status, plaintext, detail = cc.decrypt_chromium_blob(blob, CHROMIUM_KEY)
    assert status == cc.STATUS_OK
    assert plaintext == SECRET_PASS.encode()
    assert "AES-256-GCM" in detail


def test_chromium_v11_is_supported_too():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = b"\x09" * 12
    blob = b"v11" + nonce + AESGCM(CHROMIUM_KEY).encrypt(nonce, b"secret", None)
    status, plaintext, _detail = cc.decrypt_chromium_blob(blob, CHROMIUM_KEY)
    assert status == cc.STATUS_OK
    assert plaintext == b"secret"


def test_chromium_v10_without_key_is_unavailable():
    blob = _v10_blob(CHROMIUM_KEY, b"secret")
    status, plaintext, detail = cc.decrypt_chromium_blob(blob, None)
    assert status == cc.STATUS_UNAVAILABLE
    assert plaintext is None
    assert "Local State" in detail
    # The detail must never echo key material.
    assert CHROMIUM_KEY.hex() not in detail


def test_chromium_v10_wrong_key_fails_without_raising():
    blob = _v10_blob(CHROMIUM_KEY, b"secret")
    status, plaintext, detail = cc.decrypt_chromium_blob(blob, b"\x00" * 32)
    assert status == cc.STATUS_FAILED
    assert plaintext is None
    assert "authentication failed" in detail


def test_chromium_v10_truncated_blob():
    blob = b"v10" + b"\x00" * 8
    status, plaintext, detail = cc.decrypt_chromium_blob(blob, CHROMIUM_KEY)
    assert status == cc.STATUS_FAILED
    assert plaintext is None
    assert "truncated" in detail


def test_chromium_legacy_aes_cbc_and_plaintext():
    # Legacy pre-v10 container: no version prefix, fixed IV.
    cipher = _aes_cbc_encrypt(CHROMIUM_KEY[:32], cc.LEGACY_IV, b"legacy-secret")
    status, plaintext, detail = cc.decrypt_chromium_blob(cipher, CHROMIUM_KEY)
    assert status == cc.STATUS_OK
    assert plaintext == b"legacy-secret"
    assert "legacy" in detail

    status_p, plaintext_p, detail_p = cc.decrypt_chromium_blob(
        b"plaintext-password", None
    )
    assert status_p == cc.STATUS_OK
    assert plaintext_p == b"plaintext-password"

    assert cc.decrypt_chromium_blob(b"", CHROMIUM_KEY)[0] == cc.STATUS_SKIPPED


def test_chromium_oversized_blob_is_rejected():
    status, plaintext, detail = cc.decrypt_chromium_blob(
        b"v10" + b"x" * (cc.MAX_BLOB_BYTES + 1), CHROMIUM_KEY
    )
    assert status == cc.STATUS_FAILED
    assert plaintext is None
    assert "size limit" in detail


def test_load_chromium_key_from_local_state(tmp_path):
    bare_key = base64.b64encode(CHROMIUM_KEY).decode()
    path = tmp_path / "Local State"
    path.write_text(json.dumps({"os_crypt": {"encrypted_key": bare_key}}))
    resolved = cc.load_chromium_key(path)
    assert resolved.status == cc.STATUS_OK
    assert resolved.key == CHROMIUM_KEY
    assert "without a DPAPI wrapper" in resolved.details


def test_load_chromium_key_missing_or_malformed(tmp_path):
    assert cc.load_chromium_key(None).status == cc.STATUS_UNAVAILABLE
    missing = cc.load_chromium_key(tmp_path / "nope")
    assert missing.status == cc.STATUS_UNAVAILABLE
    assert missing.key is None

    empty = tmp_path / "Local State"
    empty.write_text(json.dumps({"os_crypt": {}}))
    assert cc.load_chromium_key(empty).status == cc.STATUS_UNAVAILABLE

    bad = tmp_path / "Local State"
    bad.write_text("{not json")
    assert cc.load_chromium_key(bad).status == cc.STATUS_FAILED

    bad64 = tmp_path / "Local State"
    bad64.write_text(json.dumps({"os_crypt": {"encrypted_key": "!!notb64!!"}}))
    assert cc.load_chromium_key(bad64).status == cc.STATUS_FAILED


def test_load_chromium_key_dpapi_wrapper_on_non_windows(tmp_path):
    """A DPAPI-wrapped key on a non-Windows host must be unavailable, not a crash."""
    if cc.sys.platform == "win32":
        pytest.skip("DPAPI path is exercised differently on Windows")
    wrapped = base64.b64encode(cc.DPAPI_PREFIX + b"\x77" * 40).decode()
    path = tmp_path / "Local State"
    path.write_text(json.dumps({"os_crypt": {"encrypted_key": wrapped}}))
    resolved = cc.load_chromium_key(path)
    assert resolved.status == cc.STATUS_UNAVAILABLE
    assert resolved.key is None


# ----------------------------------------------------------------------
# Firefox NSS SDRM
# ----------------------------------------------------------------------
def test_firefox_key4_and_login_decryption(tmp_path):
    key4 = tmp_path / "key4.db"
    sdr_key = _build_key4_db(key4, key_material=b"\x55" * 48)

    resolved = cc.load_firefox_key(key4)
    assert resolved.status == cc.STATUS_OK
    assert resolved.algorithm == "aes256-cbc"
    assert resolved.key == sdr_key[:32]
    assert "PBES2/AES-256" in resolved.details

    iv = b"\x0a" * 16
    username_blob = _login_container(sdr_key[:32], iv, SECRET_USER.encode())
    password_blob = _login_container(sdr_key[:32], iv, SECRET_PASS.encode())

    status_u, user, _detail_u = cc.decrypt_firefox_value(
        username_blob, resolved.key, resolved.algorithm
    )
    assert status_u == cc.STATUS_OK
    assert user == SECRET_USER.encode()

    status_p, password, detail_p = cc.decrypt_firefox_value(
        password_blob, resolved.key, resolved.algorithm
    )
    assert status_p == cc.STATUS_OK
    assert password == SECRET_PASS.encode()
    assert "aes256-cbc" in detail_p


def test_firefox_primary_password_mismatch_is_failed(tmp_path):
    """A wrong master password must fail the NSS password check, not crash."""
    key4 = tmp_path / "key4.db"
    _build_key4_db(key4, key_material=b"\x66" * 48)
    resolved = cc.load_firefox_key(key4, master_password="wrong-primary")
    assert resolved.status == cc.STATUS_FAILED
    assert resolved.key is None
    assert "Primary Password" in resolved.details
    # The message must never contain the master password that was tried.
    assert "wrong-primary" not in resolved.details


def test_firefox_missing_key4_is_unavailable(tmp_path):
    resolved = cc.load_firefox_key(tmp_path / "key4.db")
    assert resolved.status == cc.STATUS_UNAVAILABLE
    assert resolved.key is None

    empty = tmp_path / "key4.db"
    empty.write_bytes(b"not a database")
    assert cc.load_firefox_key(empty).status == cc.STATUS_FAILED


def test_firefox_value_without_key_is_unavailable():
    status, plaintext, detail = cc.decrypt_firefox_value("AAAA", None, None)
    assert status == cc.STATUS_UNAVAILABLE
    assert plaintext is None
    assert "SDRM key" in detail


def test_firefox_wrong_key_fails_cleanly(tmp_path):
    iv = b"\x0b" * 16
    blob = _login_container(b"\x77" * 32, iv, b"secret")
    status, plaintext, detail = cc.decrypt_firefox_value(
        blob, b"\x88" * 32, "aes256-cbc"
    )
    assert status == cc.STATUS_FAILED
    assert plaintext is None
    assert "decryption failed" in detail


def test_firefox_bad_base64_and_unknown_cipher():
    assert cc.decrypt_firefox_value("!!!!", b"\x00" * 32, "aes256-cbc")[0] == cc.STATUS_FAILED
    assert cc.decrypt_firefox_value("AAAA", b"\x00" * 32, "rot13")[0] == cc.STATUS_FAILED
    assert cc.decrypt_firefox_value("", b"\x00" * 32, "aes256-cbc")[0] == cc.STATUS_SKIPPED


def test_firefox_legacy_3des_container(tmp_path):
    """The legacy pbeWithSHA1AndTripleDES-CBC key container must still parse."""
    import hashlib
    import hmac as hmac_mod

    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    global_salt = b"\x44" * 32
    entry_salt = b"\x99" * 20
    master = b""

    # Reimplement the documented key3.db derivation to build a valid container.
    hp = hashlib.sha1(global_salt + master).digest()
    pes = entry_salt + b"\x00" * (20 - len(entry_salt))
    chp = hashlib.sha1(hp + entry_salt).digest()
    k1 = hmac_mod.new(chp, pes + entry_salt, hashlib.sha1).digest()
    tk = hmac_mod.new(chp, pes, hashlib.sha1).digest()
    k2 = hmac_mod.new(chp, tk + entry_salt, hashlib.sha1).digest()
    key = (k1 + k2)[:24]
    iv = (k1 + k2)[-8:]

    padder = padding.PKCS7(64).padder()
    padded = padder.update(b"password-check\x02\x02") + padder.finalize()
    encryptor = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    cipher = encryptor.update(padded) + encryptor.finalize()

    container = _der_seq(
        _der_seq(
            _der_oid(cc.OID_PBE_3DES),
            _der_seq(_der_octets(entry_salt), _der_int(1)),
        ),
        _der_octets(cipher),
    )
    clear = cc._pbe_decrypt(container, global_salt, master)
    assert clear == b"password-check\x02\x02"


# ----------------------------------------------------------------------
# Export safety
# ----------------------------------------------------------------------
def _sample_record() -> cc.RevealedCredential:
    return cc.RevealedCredential(
        website="https://accounts.example.test",
        action_url="https://accounts.example.test/login",
        brand="chrome",
        engine="chromium",
        profile="Default",
        os_user="Alice",
        username=SECRET_USER,
        password=SECRET_PASS,
        username_status=cc.STATUS_OK,
        password_status=cc.STATUS_OK,
        username_detail="OSCrypt v10 AES-256-GCM",
        password_detail="OSCrypt v10 AES-256-GCM",
        protection_status="OSCRYPT_AES_GCM",
        inode=12345,
        source_path="Users/Alice/.../Login Data",
        evidence_id="ev_0123456789ab",
    )


def test_csv_export_neutralizes_formula_injection():
    record = _sample_record()
    record.username = "=cmd|calc"
    text = cc.export_reveal_csv([record])
    assert "'=cmd|calc" in text
    assert SECRET_PASS in text  # an explicit export does contain plaintext


def test_write_reveal_export_is_0600(tmp_path):
    target_dir = tmp_path / "exports" / "credentials"
    path = cc.write_reveal_export(
        target_dir, "reveal_ev_01", fmt="csv", payload="a,b\n1,2\n"
    )
    assert path.is_file()
    if os.name == "posix":
        # Windows cannot express POSIX modes; the target is Linux (see README).
        assert (os.stat(path).st_mode & 0o777) == 0o600
        assert (os.stat(target_dir).st_mode & 0o777) == 0o700
    assert path.read_text() == "a,b\n1,2\n"

    json_path = cc.write_reveal_export(
        target_dir, "reveal_ev_02", fmt="json", payload='{"a": 1}'
    )
    assert json_path.suffix == ".json"
    if os.name == "posix":
        assert (os.stat(json_path).st_mode & 0o777) == 0o600


def test_reveal_result_serialization_counters():
    result = cc.RevealResult(
        evidence_id="ev_0123456789ab",
        records=[_sample_record()],
        key_status=[{"profile": "Default", "status": cc.STATUS_OK, "details": "ok"}],
        total_records=1,
        decrypted_usernames=1,
        decrypted_passwords=1,
        browsers_found=["Google Chrome"],
        profiles_found=["Default"],
        note="explicit",
    )
    payload = result.to_dict()
    assert payload["total_records"] == 1
    assert payload["decrypted_passwords"] == 1
    assert payload["records"][0]["password"] == SECRET_PASS
    assert payload["trust"] == "untrusted_evidence_data"
