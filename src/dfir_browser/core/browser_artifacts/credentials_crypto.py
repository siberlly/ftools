"""Bounded, opt-in decryption of saved browser credentials.

This module is the *only* place where encrypted browser credential material is
ever decrypted. It is deliberately isolated from the default credential
inspection path (``credentials.py``) so the running web UI, the MCP server and
the redacted exports keep their invariant: credential secrets are never
decrypted or returned unless an analyst explicitly opts in.

Forensic rules enforced here:

- Evidence is never modified. Every function takes an already-extracted working
  copy (mode ``0600``) and opens it read-only with
  ``mode=ro&immutable=1`` where applicable.
- Nothing is executed and no network call is made. Windows DPAPI is reached
  through ``ctypes``/``crypt32.dll`` only, on the analyst's own host.
- Decryption never raises into the request path: a failure returns a structured
  ``CredentialDecryption`` outcome with a status and a bounded, redacted
  message, so a corrupt or foreign-profile artifact cannot break a job.
- Passwords and derived keys are never logged, never written to the audit log
  and never placed in an error message. Only counts and status values are.
- An unverifiable algorithm is reported as ``UNKNOWN``/``UNAVAILABLE`` instead
  of guessing.

Supported containers:

``chromium``
    Chromium `Login Data` (Chrome, Chromium, Edge, Brave, Opera). ``v10`` and
    ``v11`` prefixes use AES-256-GCM with a master key stored in ``Local State``
    (``os_crypt.encrypted_key``, DPAPI protected on Windows). Pre-``v10``/``v11``
    blobs are legacy AES-256-CBC with a fixed IV, and a ``0x01`` DWORD header is
    a bare DPAPI blob.

``firefox``
    Firefox ``logins.json`` (NSS SDRM). Needs ``key4.db`` from the same profile.
    Both the legacy ``pbeWithSHA1AndTripleDES-CBC`` container and the current
    ``pkcs5 pbes2`` / PBES2-HMAC-SHA256 / AES-256-CBC container are supported,
    with a pure-Python implementation of the NSS key hierarchy (no ``libnss3``).
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger("dfir_browser.credentials_crypto")

# Bounded work limits: a hostile or corrupt artifact must not stall a request.
MAX_RECORDS = 5_000
MAX_BLOB_BYTES = 64 * 1024
MAX_PASSWORD_CHARS = 4_096
MAX_USERNAME_CHARS = 1_024
MAX_URL_CHARS = 4_096

# Chromium OSCrypt.
OSCRYPT_V10 = b"v10"
OSCRYPT_V11 = b"v11"
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
LEGACY_IV = b" " * 16
DPAPI_MAGIC = b"\x01\x00\x00\x00"
DPAPI_PREFIX = b"DPAPI"
LOCAL_STATE_KEY_MIN_BYTES = 16

# Firefox NSS / SDRM.
CKA_ID = bytes.fromhex("f8000000000000000000000000000001")
NSS_PASSWORD_CHECK = b"password-check\x02\x02"
OID_PBE_3DES = "1.2.840.113549.1.12.5.1.3"
OID_PBES2 = "1.2.840.113549.1.5.13"
OID_PBKDF2 = "1.2.840.113549.1.5.12"
OID_HMAC_SHA256 = "1.2.840.113549.2.9"
OID_AES_256_CBC = "2.16.840.1.101.3.4.1.42"

STATUS_OK = "decrypted"
STATUS_UNAVAILABLE = "unavailable"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"


class UnsupportedCredentialContainer(Exception):
    """The container is recognized but this build cannot decrypt it."""


class DecryptionFailed(Exception):
    """The key material was available but the container did not decrypt."""


# ----------------------------------------------------------------------
# Bounded helpers
# ----------------------------------------------------------------------
def read_bounded_file(path: Path, limit: int) -> bytes:
    """Read at most ``limit`` bytes, refusing an artifact that exceeds it.

    A ``logins.json`` can legally be large; an unbounded read of an on-disk
    evidence copy is not acceptable inside a request, so an oversize file is
    rejected instead of silently truncated into invalid JSON.
    """
    size = path.stat().st_size
    if size > limit:
        raise DecryptionFailed(
            f"artifact is {size} bytes, above the {limit}-byte read limit"
        )
    with open(path, "rb") as handle:
        return handle.read(limit)


def clip_text(value: Any, limit: int) -> str | None:
    """Decode a decrypted value to bounded text for reporting.

    This is the single place a decrypted secret becomes a string; every caller
    passes an explicit character budget.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            text = bytes(value).decode("utf-8", "replace")
    else:
        text = str(value)
    if not text:
        return None
    return text[:limit] if limit > 0 else text


def determine_status_label(blob: bytes | None, key_status: str) -> str:
    """Human-facing protection label reused by the redacted analysis path."""
    if blob:
        if blob.startswith(OSCRYPT_V10) or blob.startswith(OSCRYPT_V11):
            return "OSCRYPT_AES_GCM"
        if blob.startswith(DPAPI_MAGIC):
            return "WINDOWS_DPAPI"
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text.isprintable():
            return "PLAINTEXT"
        return "UNKNOWN"
    if key_status == STATUS_OK:
        return "NSS_ENCRYPTED"
    return "UNKNOWN"


def _crypto():
    """Import ``cryptography`` lazily so the module stays importable without it."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes, padding
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise UnsupportedCredentialContainer(
            "the 'cryptography' package is required for credential decryption"
        ) from exc
    return Cipher, AESGCM, PBKDF2HMAC, hashes, padding


def _triple_des():
    """TripleDES moved to ``decrepit`` in cryptography 48; support both."""
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    return TripleDES


def _cbc_decrypt(algorithm, iv: bytes, ciphertext: bytes) -> bytes:
    """PKCS#7-unpad a CBC ciphertext. Raises DecryptionFailed on bad padding."""
    Cipher, _AESGCM, _PBKDF2, _hashes, padding = _crypto()
    from cryptography.hazmat.primitives.ciphers import modes

    if not iv:
        raise DecryptionFailed("missing CBC IV")
    # AES uses 16-byte blocks and 3DES 8-byte blocks; the unpadder must match.
    block_size = (getattr(algorithm, "block_size", 128) or 128) // 8
    if block_size <= 0 or len(ciphertext) % block_size:
        raise DecryptionFailed("ciphertext is not a CBC block multiple")
    decryptor = Cipher(algorithm, modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise DecryptionFailed("padding check failed") from exc


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import algorithms

    return _cbc_decrypt(algorithms.AES(key), iv, ciphertext)


def _des3_cbc_decrypt(key24: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return _cbc_decrypt(_triple_des()(key24), iv, ciphertext)


# ----------------------------------------------------------------------
# Windows DPAPI (ctypes only; no extra dependency, no subprocess)
# ----------------------------------------------------------------------
class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _dpapi_unprotect(blob: bytes) -> bytes:
    """Call ``CryptUnprotectData`` for the current Windows user context."""
    if sys.platform != "win32":
        raise UnsupportedCredentialContainer(
            "Windows DPAPI is only available on a Windows analysis host"
        )
    if len(blob) > MAX_BLOB_BYTES:
        raise DecryptionFailed("DPAPI blob exceeds the size limit")
    crypt32 = ctypes.util.find_library("crypt32") or "crypt32.dll"
    try:
        library = ctypes.WinDLL(crypt32)  # type: ignore[attr-defined]
    except (AttributeError, OSError) as exc:
        raise UnsupportedCredentialContainer(
            "crypt32.dll is not available on this host"
        ) from exc

    in_blob = _DataBlob(
        len(blob), ctypes.cast(ctypes.create_string_buffer(blob), ctypes.POINTER(ctypes.c_char))
    )
    out_blob = _DataBlob()
    library.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(_DataBlob),
    ]
    library.CryptUnprotectData.restype = ctypes.c_int
    # CRYPTPROTECT_UI_FORBIDDEN: never show a prompt during an investigation.
    if not library.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0x1, ctypes.byref(out_blob)
    ):
        raise DecryptionFailed(
            "Windows DPAPI could not decrypt the blob for this user context"
        )
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        try:
            kernel32 = ctypes.WinDLL("kernel32.dll")  # type: ignore[attr-defined]
            kernel32.LocalFree(out_blob.pbData)
        except Exception:  # noqa: BLE001 - freeing is best effort
            pass


# ----------------------------------------------------------------------
# Chromium OSCrypt
# ----------------------------------------------------------------------
@dataclass(slots=True)
class ChromiumKey:
    """A resolved Chromium master key plus how it was obtained."""

    status: str
    details: str
    key: bytes | None = None


def load_chromium_key(local_state_path: Path | None) -> ChromiumKey:
    """Resolve the OSCrypt master key from a Chromium ``Local State`` file.

    The key is never returned in a log or an error message; only the status and
    a bounded description are.
    """
    if local_state_path is None:
        return ChromiumKey(
            STATUS_UNAVAILABLE,
            "no Local State file was found next to this profile",
        )
    if not local_state_path.is_file():
        return ChromiumKey(
            STATUS_UNAVAILABLE, "Local State file is missing from this profile"
        )
    try:
        raw = read_bounded_file(local_state_path, MAX_BLOB_BYTES)
        data = json.loads(raw.decode("utf-8", "replace"))
    except (OSError, ValueError) as exc:
        return ChromiumKey(
            STATUS_FAILED, f"Local State could not be read: {type(exc).__name__}"
        )
    os_crypt = data.get("os_crypt") if isinstance(data, dict) else None
    if not isinstance(os_crypt, dict):
        return ChromiumKey(
            STATUS_UNAVAILABLE, "Local State has no os_crypt section"
        )
    raw_key = os_crypt.get("encrypted_key")
    if not isinstance(raw_key, str) or not raw_key:
        return ChromiumKey(
            STATUS_UNAVAILABLE,
            "Local State has no os_crypt.encrypted_key (DPAPI-off profile or "
            "key rotation not captured)",
        )
    try:
        decoded = base64.b64decode(raw_key, validate=True)
    except (ValueError, TypeError):
        return ChromiumKey(STATUS_FAILED, "encrypted_key is not valid base64")

    dpapi_protected = decoded.startswith(DPAPI_PREFIX)
    payload = decoded[len(DPAPI_PREFIX):] if dpapi_protected else decoded
    if not payload:
        return ChromiumKey(STATUS_FAILED, "encrypted_key is empty")
    if not dpapi_protected:
        # A profile on Windows normally DPAPI-wraps the key. A bare key only
        # happens when the capture already contains it unwrapped.
        if len(payload) < LOCAL_STATE_KEY_MIN_BYTES:
            return ChromiumKey(
                STATUS_UNAVAILABLE,
                "unwrapped oscrypt key is shorter than the minimum key length",
            )
        return ChromiumKey(
            STATUS_OK,
            "Local State key is stored without a DPAPI wrapper",
            payload,
        )
    try:
        key = _dpapi_unprotect(payload)
    except UnsupportedCredentialContainer as exc:
        return ChromiumKey(STATUS_UNAVAILABLE, str(exc))
    except DecryptionFailed as exc:
        return ChromiumKey(STATUS_FAILED, str(exc))
    if len(key) < LOCAL_STATE_KEY_MIN_BYTES:
        return ChromiumKey(
            STATUS_FAILED, "DPAPI unwrapped an implausibly short OSCrypt key"
        )
    return ChromiumKey(
        STATUS_OK, "OSCrypt master key unwrapped from Local State via DPAPI", key
    )


def decrypt_chromium_blob(
    blob: bytes, key: bytes | None
) -> tuple[str, bytes | None, str]:
    """Decrypt one Chromium ``password_value``.

    Returns ``(status, plaintext, detail)``. ``plaintext`` is ``None`` whenever
    the status is not :data:`STATUS_OK`, so a caller can never accidentally
    render a partial result as success.
    """
    if not blob:
        return STATUS_SKIPPED, None, "no password value stored"
    if len(blob) > MAX_BLOB_BYTES:
        return STATUS_FAILED, None, "password blob exceeds the size limit"
    if blob.startswith(OSCRYPT_V10) or blob.startswith(OSCRYPT_V11):
        version = blob[:3].decode("ascii", "replace")
        if key is None:
            return (
                STATUS_UNAVAILABLE,
                None,
                f"OSCrypt {version} blob needs the Local State master key",
            )
        body = blob[3:]
        if len(body) <= GCM_NONCE_BYTES + GCM_TAG_BYTES:
            return STATUS_FAILED, None, f"OSCrypt {version} blob is truncated"
        nonce = body[:GCM_NONCE_BYTES]
        ciphertext = body[GCM_NONCE_BYTES:]
        try:
            plaintext = _gcm_open(key, nonce, ciphertext)
        except Exception:  # noqa: BLE001 - invalid tag and provider errors
            return (
                STATUS_FAILED,
                None,
                f"OSCrypt {version} authentication failed (wrong key or "
                "corrupt blob)",
            )
        return STATUS_OK, plaintext, f"OSCrypt {version} AES-256-GCM"
    if blob.startswith(DPAPI_MAGIC):
        try:
            plaintext = _dpapi_unprotect(blob)
        except UnsupportedCredentialContainer as exc:
            return STATUS_UNAVAILABLE, None, str(exc)
        except DecryptionFailed as exc:
            return STATUS_FAILED, None, str(exc)
        return STATUS_OK, plaintext, "Windows DPAPI crypt32 blob"
    if key is not None and blob and len(blob) % 16 == 0:
        # Pre-v10 legacy: AES-256-CBC, fixed IV, whole blob is ciphertext.
        try:
            plaintext = _aes_cbc_decrypt(key[:32], LEGACY_IV, blob)
        except Exception:  # noqa: BLE001 - a wrong key surfaces as bad padding
            return (
                STATUS_FAILED,
                None,
                "legacy AES-256-CBC blob did not decrypt with the Local State key",
            )
        return STATUS_OK, plaintext, "legacy AES-256-CBC (pre-v10 OSCrypt)"
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return STATUS_FAILED, None, "unrecognized protection format"
    if text.isprintable():
        return STATUS_OK, blob, "unencrypted plaintext"
    return STATUS_FAILED, None, "unrecognized protection format"


def _gcm_open(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-256-GCM open. Raises on a bad tag; the caller maps it to a status."""
    _Cipher, AESGCM, _pbkdf2, _hashes, _padding = _crypto()
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ----------------------------------------------------------------------
# Firefox NSS SDRM (portable, no libnss3)
# ----------------------------------------------------------------------
def _der_read(data: bytes, offset: int = 0) -> tuple[int, int, bytes, int]:
    """Read one DER TLV. Returns ``(tag, length, payload, next_offset)``."""
    if offset + 2 > len(data):
        raise DecryptionFailed("truncated DER header")
    tag = data[offset]
    length = data[offset + 1]
    cursor = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise DecryptionFailed("unsupported DER length form")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    end = cursor + length
    if end > len(data):
        raise DecryptionFailed("DER value runs past the buffer")
    return tag, length, data[cursor:end], end


def _der_children(payload: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(payload):
        tag, _length, body, cursor = _der_read(payload, cursor)
        items.append((tag, body))
    return items


def _der_oid(payload: bytes) -> str:
    """Decode an OBJECT IDENTIFIER payload into dotted decimal form."""
    if not payload:
        return ""
    first = payload[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in payload[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _decode_login_container(blob_b64: str) -> tuple[bytes, bytes, bytes]:
    """Decode Firefox ``encryptedUsername``/``encryptedPassword`` base64 ASN.1.

    Layout (NSS SDRM)::

        SEQUENCE {
          OCTETSTRING key_id (CKA_ID)
          SEQUENCE {
            OBJECTIDENTIFIER des-ede3-cbc or aes256-CBC
            OCTETSTRING iv
          }
          OCTETSTRING encrypted
        }
    """
    try:
        raw = base64.b64decode(blob_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise DecryptionFailed("credential value is not valid base64") from exc
    if len(raw) > MAX_BLOB_BYTES:
        raise DecryptionFailed("credential value exceeds the size limit")
    tag, _length, body, _end = _der_read(raw)
    if tag != 0x30:
        raise DecryptionFailed("credential value is not a DER sequence")
    items = _der_children(body)
    if len(items) < 3:
        raise DecryptionFailed("credential sequence is missing members")
    key_id = items[0][1]
    alg_items = _der_children(items[1][1])
    if len(alg_items) < 2:
        raise DecryptionFailed("credential algorithm block is incomplete")
    ciphertext = items[2][1]
    iv = alg_items[1][1]
    return key_id, iv, ciphertext


def _nss_decrypt_3des(
    global_salt: bytes, master_password: bytes, entry_salt: bytes, ciphertext: bytes
) -> bytes:
    hp = hashlib.sha1(global_salt + master_password).digest()
    pes = entry_salt + b"\x00" * (20 - len(entry_salt))
    chp = hashlib.sha1(hp + entry_salt).digest()
    k1 = hmac.new(chp, pes + entry_salt, hashlib.sha1).digest()
    tk = hmac.new(chp, pes, hashlib.sha1).digest()
    k2 = hmac.new(chp, tk + entry_salt, hashlib.sha1).digest()
    key = (k1 + k2)[:24]
    iv = (k1 + k2)[-8:]
    return _des3_cbc_decrypt(key, iv, ciphertext)


def _nss_decrypt_pbes2(
    global_salt: bytes,
    master_password: bytes,
    entry_salt: bytes,
    iterations: int,
    key_length: int,
    iv_raw: bytes,
    ciphertext: bytes,
) -> bytes:
    Cipher, _AESGCM, PBKDF2HMAC, hashes, _padding = _crypto()
    k = hashlib.sha1(global_salt + master_password).digest()
    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=entry_salt,
        iterations=iterations,
    ).derive(k)
    # NSS reuses the DER OCTETSTRING header (0x04 0x0e) as the first two bytes
    # of the AES-CBC IV, so the effective IV is the stored 14 bytes plus that
    # prefix. Reproducing the stored bytes verbatim is what NSS expects.
    iv = _nss_iv(iv_raw)
    return _aes_cbc_decrypt(derived[:32], iv, ciphertext)


def _nss_iv(iv_raw: bytes) -> bytes:
    """Reconstruct the 16-byte NSS AES-CBC IV from the stored octet string."""
    if len(iv_raw) == 16:
        return iv_raw
    if len(iv_raw) == 14:
        return b"\x04\x0e" + iv_raw
    raise DecryptionFailed(f"unexpected NSS IV length ({len(iv_raw)} bytes)")


def _decode_pbe_container(der: bytes) -> tuple[str, dict[str, Any]]:
    """Parse a ``SEQUENCE { SEQUENCE { OID, params }, OCTETSTRING }`` PBE blob."""
    tag, _length, body, _end = _der_read(der)
    if tag != 0x30:
        raise DecryptionFailed("PBE container is not a DER sequence")
    items = _der_children(body)
    if len(items) < 2:
        raise DecryptionFailed("PBE container is missing members")
    alg = _der_children(items[0][1])
    if len(alg) < 2:
        raise DecryptionFailed("PBE algorithm block is incomplete")
    oid = _der_oid(alg[0][1])
    params = alg[1][1]
    ciphertext = items[1][1]
    return oid, {"params": params, "ciphertext": ciphertext}


def _pbe_decrypt(
    container: bytes, global_salt: bytes, master_password: bytes
) -> bytes:
    oid, parts = _decode_pbe_container(container)
    if oid == OID_PBE_3DES:
        param_items = _der_children(parts["params"])
        if not param_items:
            raise DecryptionFailed("3DES PBE entry salt is missing")
        entry_salt = param_items[0][1]
        return _nss_decrypt_3des(
            global_salt, master_password, entry_salt, parts["ciphertext"]
        )
    if oid == OID_PBES2:
        outer = _der_children(parts["params"])
        if len(outer) < 2:
            raise DecryptionFailed("PBES2 parameter block is incomplete")
        kdf_items = _der_children(outer[0][1])
        enc_items = _der_children(outer[1][1])
        if len(kdf_items) < 2 or len(enc_items) < 2:
            raise DecryptionFailed("PBES2 KDF or encryption OID is missing")
        kdf_oid = _der_oid(kdf_items[0][1])
        if kdf_oid != OID_PBKDF2:
            raise DecryptionFailed(f"unsupported PBES2 KDF {kdf_oid}")
        kdf_params = _der_children(kdf_items[1][1])
        if len(kdf_params) < 3:
            raise DecryptionFailed("PBKDF2 parameters are incomplete")
        entry_salt = kdf_params[0][1]
        iterations = int.from_bytes(kdf_params[1][1], "big") or 1
        key_length = int.from_bytes(kdf_params[2][1], "big")
        if key_length <= 0 or key_length > 64:
            raise DecryptionFailed("implausible PBKDF2 key length")
        enc_oid = _der_oid(enc_items[0][1])
        if enc_oid != OID_AES_256_CBC:
            raise DecryptionFailed(f"unsupported PBES2 cipher {enc_oid}")
        iv_raw = enc_items[1][1]
        return _nss_decrypt_pbes2(
            global_salt,
            master_password,
            entry_salt,
            iterations,
            key_length,
            iv_raw,
            parts["ciphertext"],
        )
    raise DecryptionFailed(f"unsupported PBE algorithm {oid}")


@dataclass(slots=True)
class FirefoxKey:
    """The resolved SDRM key hack: AES-256 or 3DES, plus a status."""

    status: str
    details: str
    key: bytes | None = None
    algorithm: str | None = None


def load_firefox_key(
    key4_path: Path | None, master_password: str = ""
) -> FirefoxKey:
    """Derive the NSS SDRM key from ``key4.db``.

    ``key4.db`` is a plain SQLite database, so this is a pure-Python read. The
    master password is empty for the overwhelmingly common case (no Primary
    Password configured); a non-empty password must be supplied by the analyst.
    """
    if key4_path is None or not key4_path.is_file():
        return FirefoxKey(
            STATUS_UNAVAILABLE,
            "key4.db is not present in this profile (Firefox < 58 or a "
            "Primary-Password profile whose key database was not captured)",
        )
    master = (master_password or "").encode("utf-8")
    try:
        connection = sqlite3.connect(
            f"file:{key4_path}?mode=ro&immutable=1", uri=True, timeout=5.0
        )
    except sqlite3.Error as exc:
        return FirefoxKey(
            STATUS_FAILED, f"key4.db could not be opened: {type(exc).__name__}"
        )
    try:
        row = connection.execute(
            "SELECT item1, item2 FROM metadata WHERE id = 'password'"
        ).fetchone()
        if row is None:
            return FirefoxKey(
                STATUS_FAILED, "key4.db has no metadata password row"
            )
        global_salt = bytes(row[0]) if row[0] is not None else b""
        item2 = bytes(row[1]) if row[1] is not None else b""
        if not global_salt or not item2:
            return FirefoxKey(STATUS_FAILED, "key4.db metadata row is empty")
        try:
            clear = _pbe_decrypt(item2, global_salt, master)
        except DecryptionFailed as exc:
            # A wrong master password and a corrupt container both fail here.
            # The tool cannot distinguish them, so it names both possibilities
            # instead of asserting one.
            return FirefoxKey(
                STATUS_FAILED,
                "NSS password check could not be decrypted "
                f"({exc}): either a Primary Password is set and was not "
                "supplied, or key4.db does not belong to this logins.json",
            )
        if clear != NSS_PASSWORD_CHECK:
            return FirefoxKey(
                STATUS_FAILED,
                "password check failed: a Primary Password is set or key4.db "
                "does not belong to this logins.json",
            )

        key_row = None
        for candidate in connection.execute(
            "SELECT a11, a102 FROM nssPrivate"
        ):
            if candidate[0] is not None:
                key_row = candidate
                if candidate[1] is not None and bytes(candidate[1]) == CKA_ID:
                    break
        if key_row is None:
            return FirefoxKey(
                STATUS_UNAVAILABLE, "nssPrivate holds no stored SDRM key"
            )
        if key_row[1] is None or bytes(key_row[1]) != CKA_ID:
            return FirefoxKey(
                STATUS_UNAVAILABLE,
                "nssPrivate has no entry for the SDRM key id (no saved logins)",
            )
        a11 = bytes(key_row[0])
        material = _pbe_decrypt(a11, global_salt, master)
        if len(material) == 48:
            return FirefoxKey(
                STATUS_OK,
                "NSS SDRM key recovered (PBES2/AES-256, 48-byte payload)",
                material[:32],
                "aes256-cbc",
            )
        if len(material) == 32:
            return FirefoxKey(
                STATUS_OK,
                "NSS SDRM key recovered (legacy 3DES, 32-byte payload)",
                material[:24],
                "des-ede3-cbc",
            )
        return FirefoxKey(
            STATUS_FAILED,
            f"unexpected SDRM key length ({len(material)} bytes)",
        )
    except DecryptionFailed as exc:
        return FirefoxKey(STATUS_FAILED, str(exc))
    except sqlite3.Error as exc:
        return FirefoxKey(
            STATUS_FAILED, f"key4.db query failed: {type(exc).__name__}"
        )
    finally:
        connection.close()


def decrypt_firefox_value(
    blob_b64: str, key: bytes | None, algorithm: str | None
) -> tuple[str, str | None, str]:
    """Decrypt one Firefox ``encryptedUsername``/``encryptedPassword`` value.

    Returns ``(status, plaintext, detail)``.
    """
    if not blob_b64:
        return STATUS_SKIPPED, None, "no value stored"
    if key is None:
        return (
            STATUS_UNAVAILABLE,
            None,
            "NSS SDRM key is not available for this profile",
        )
    if algorithm not in {"aes256-cbc", "des-ede3-cbc"}:
        return STATUS_FAILED, None, "unknown SDRM cipher"
    try:
        key_id, iv, ciphertext = _decode_login_container(blob_b64)
    except DecryptionFailed as exc:
        return STATUS_FAILED, None, str(exc)
    if key_id != CKA_ID:
        return STATUS_FAILED, None, "credential key id does not match the SDRM key"
    try:
        if algorithm == "aes256-cbc":
            plaintext = _aes_cbc_decrypt(key[:32], iv, ciphertext)
        else:
            plaintext = _des3_cbc_decrypt(key[:24], iv, ciphertext)
    except Exception:  # noqa: BLE001 - wrong key surfaces as padding failure
        return (
            STATUS_FAILED,
            None,
            "NSS SDRM decryption failed (wrong key or corrupt container)",
        )
    return STATUS_OK, plaintext, f"NSS SDRM {algorithm}"


# ----------------------------------------------------------------------
# Result models
# ----------------------------------------------------------------------
@dataclass(slots=True)
class RevealedCredential:
    """One decrypted credential. Never serialized without an explicit export."""

    website: str
    action_url: str | None
    brand: str
    engine: str
    profile: str
    os_user: str | None
    username: str | None
    password: str | None
    username_status: str
    password_status: str
    username_detail: str
    password_detail: str
    protection_status: str
    created_time_utc: str | None = None
    last_used_time_utc: str | None = None
    password_changed_utc: str | None = None
    times_used: int = 0
    source_path: str = ""
    source_artifact_name: str = ""
    inode: int | None = None
    partition_offset: int | None = None
    sha256: str | None = None
    evidence_id: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": "untrusted_evidence_data",
            "website": self.website,
            "action_url": self.action_url,
            "brand": self.brand,
            "engine": self.engine,
            "profile": self.profile,
            "os_user": self.os_user,
            "username": self.username,
            "password": self.password,
            "username_status": self.username_status,
            "password_status": self.password_status,
            "username_detail": self.username_detail,
            "password_detail": self.password_detail,
            "protection_status": self.protection_status,
            "created_time_utc": self.created_time_utc,
            "last_used_time_utc": self.last_used_time_utc,
            "password_changed_utc": self.password_changed_utc,
            "times_used": self.times_used,
            "source_path": self.source_path,
            "source_artifact_name": self.source_artifact_name,
            "inode": self.inode,
            "partition_offset": self.partition_offset,
            "sha256": self.sha256,
            "evidence_id": self.evidence_id,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class RevealResult:
    evidence_id: str
    records: list[RevealedCredential]
    key_status: list[dict[str, str]]
    total_records: int
    decrypted_usernames: int
    decrypted_passwords: int
    browsers_found: list[str]
    profiles_found: list[str]
    warnings: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": "untrusted_evidence_data",
            "evidence_id": self.evidence_id,
            "records": [r.to_dict() for r in self.records],
            "key_status": list(self.key_status),
            "total_records": self.total_records,
            "decrypted_usernames": self.decrypted_usernames,
            "decrypted_passwords": self.decrypted_passwords,
            "browsers_found": list(self.browsers_found),
            "profiles_found": list(self.profiles_found),
            "warnings": list(self.warnings),
            "note": self.note,
        }


# ----------------------------------------------------------------------
# Export helpers (written to a 0600 file, never returned inline as HTML)
# ----------------------------------------------------------------------
REVEAL_CSV_COLUMNS = [
    "website",
    "action_url",
    "brand",
    "engine",
    "profile",
    "os_user",
    "username",
    "password",
    "username_status",
    "password_status",
    "protection_status",
    "created_time_utc",
    "last_used_time_utc",
    "password_changed_utc",
    "times_used",
    "source_path",
    "inode",
    "partition_offset",
    "sha256",
    "evidence_id",
]


def _csv_cell(value: Any) -> str:
    """Neutralize spreadsheet formula injection in exported credential cells."""
    if value is None:
        return ""
    text = str(value)
    if text[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + text
    return text


def export_reveal_csv(records: Iterable[RevealedCredential]) -> str:
    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(REVEAL_CSV_COLUMNS)
    for record in records:
        row = record.to_dict()
        writer.writerow([_csv_cell(row.get(column)) for column in REVEAL_CSV_COLUMNS])
    return buffer.getvalue()


def export_reveal_json(result: RevealResult) -> str:
    payload = result.to_dict()
    payload["note"] = (
        "Plaintext credentials. Produced by an explicit, audited analyst "
        "request. Handle as sensitive evidence; never commit or share."
    )
    return json.dumps(payload, indent=2, ensure_ascii=False)


def write_reveal_export(
    directory: Path, filename_stem: str, *, fmt: str, payload: str
) -> Path:
    """Write a decrypted export with mode ``0600`` under a ``0700`` directory."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    suffix = "csv" if fmt.lower() == "csv" else "json"
    target = directory / f"{filename_stem}.{suffix}"
    # O_EXCL-free but exclusive creation with 0600 from the first byte.
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.chmod(target, 0o600)
        data = payload.encode("utf-8")
        while data:
            written = os.write(descriptor, data)
            data = data[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target
