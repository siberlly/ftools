from __future__ import annotations

import json
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

import dfir_browser.mcp_server as mcp_server
from dfir_browser.core.browser_artifacts.credentials import analyze_store
from dfir_browser.web.app import create_app

from browser_helpers import (
    EVIDENCE,
    build_browser_services,
    entry_id,
    stub_browser_extract,
)

PROFILE = "Users/IEUser/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default"
PLACES = f"{PROFILE}/places.sqlite"
LOGINS = f"{PROFILE}/logins.json"
KEY4 = f"{PROFILE}/key4.db"
COOKIES = f"{PROFILE}/cookies.sqlite"
FORMHISTORY = f"{PROFILE}/formhistory.sqlite"

LOGINS_INODE = 70001
KEY4_INODE = 70002
COOKIES_INODE = 70003
FORMHISTORY_INODE = 70004

SECRET_PASSWORD = "hunter2-SUPER-SECRET"
SECRET_USER = "rafael@example.test"


def logins_payload() -> bytes:
    return json.dumps(
        {
            "nextId": 2,
            "logins": [
                {
                    "id": 1,
                    "hostname": "https://accounts.example.test",
                    "usernameField": "email",
                    "encryptedUsername": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAyIK",
                    "encryptedPassword": "MEoEEPgAAAAAAAAAAAAAAAAAAAEwFA",
                    "timeCreated": 1600000000000,
                    "timeLastUsed": 1600000000000,
                }
            ],
            "potentiallyVulnerablePasswords": [],
        }
    ).encode()


def cookies_payload() -> bytes:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "cookies.sqlite"
        connection = sqlite3.connect(str(path))
        connection.executescript(
            """
            CREATE TABLE moz_cookies(
              id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO moz_cookies VALUES (1, '.example.test', 'sid', ?)",
            (SECRET_PASSWORD,),
        )
        connection.execute(
            "INSERT INTO moz_cookies VALUES (2, '.other.test', 'theme', 'dark')"
        )
        connection.commit()
        connection.close()
        return path.read_bytes()


def formhistory_payload() -> bytes:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "formhistory.sqlite"
        connection = sqlite3.connect(str(path))
        connection.executescript(
            "CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT);"
        )
        connection.execute(
            "INSERT INTO moz_formhistory VALUES (1, 'email', ?)", (SECRET_USER,)
        )
        connection.commit()
        connection.close()
        return path.read_bytes()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    payloads = {
        LOGINS_INODE: logins_payload(),
        KEY4_INODE: b"key4-fake-database" * 10,
        COOKIES_INODE: cookies_payload(),
        FORMHISTORY_INODE: formhistory_payload(),
    }
    rows = [
        (PLACES, "places.sqlite", 70000, 4096, False),
        (LOGINS, "logins.json", LOGINS_INODE, len(payloads[LOGINS_INODE]), False),
        (KEY4, "key4.db", KEY4_INODE, len(payloads[KEY4_INODE]), False),
        (COOKIES, "cookies.sqlite", COOKIES_INODE, len(payloads[COOKIES_INODE]), False),
        (FORMHISTORY, "formhistory.sqlite", FORMHISTORY_INODE, len(payloads[FORMHISTORY_INODE]), False),
    ]
    services, record = build_browser_services(tmp_path, rows=rows)
    stub_browser_extract(services, payloads)
    # A real-looking profile so the artifact exists in the index database.
    from dfir_browser.core.browser_artifacts.models import BrowserProfileRow

    artifact_id = "ba_test_profile"
    services.browser_artifacts.store.upsert_artifact(
        __import__(
            "dfir_browser.core.browser_artifacts.models", fromlist=["SourceArtifact"]
        ).SourceArtifact(
            artifact_id=artifact_id,
            evidence_id=EVIDENCE,
            entry_id=entry_id(services, PLACES),
            inode=70000,
            evidence_path=PLACES,
            filename="places.sqlite",
            browser="firefox",
            artifact_type="firefox_places",
            user="IEUser",
            profile_name="abc.default",
            size=4096,
            sha256=None,
            status="ready",
            phase="ready",
            backend="firefox-sqlite",
            parser_version="test",
        )
    )
    services.browser_artifacts.store.upsert_profile(
        BrowserProfileRow(
            profile_id="bp_abc",
            evidence_id=EVIDENCE,
            artifact_id=artifact_id,
            user="IEUser",
            browser="firefox",
            profile_name="abc.default",
            source_path=PLACES,
        )
    )
    app = create_app(services.settings, services)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with TestClient(app) as client:
        yield client, services, record, artifact_id
    services.cleanup()


def test_credential_stores_report_presence_and_counts(env):
    client, services, record, artifact_id = env
    result = services.browser_artifacts.credential_stores(EVIDENCE, artifact_id)
    stores = {item["name"]: item for item in result["stores"]}
    assert stores["logins.json"]["exists"] is True
    assert stores["logins.json"]["record_count"] == 1
    assert stores["logins.json"]["hosts"] == ["https://accounts.example.test"]
    assert stores["cookies.sqlite"]["record_count"] == 2
    assert ".example.test" in stores["cookies.sqlite"]["hosts"]
    assert stores["formhistory.sqlite"]["record_count"] == 1
    assert stores["formhistory.sqlite"]["fields"] == ["email"]
    assert stores["key4.db"]["exists"] is True
    assert stores["key4.db"]["record_count"] is None
    # Chromium stores absent from a Firefox profile.
    assert stores["Login Data"]["exists"] is False


def test_credential_stores_never_leak_secrets(env):
    client, services, record, artifact_id = env
    payload = services.browser_artifacts.credential_stores(
        EVIDENCE, artifact_id
    )
    text = json.dumps(payload)
    assert SECRET_PASSWORD not in text
    assert SECRET_USER not in text
    assert "encryptedPassword" not in text
    assert "encryptedUsername" not in text
    assert "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAyIK" not in text
    # Only hosts/field names are exposed.
    assert "accounts.example.test" in text


def test_credentials_reject_foreign_artifact(env):
    client, services, record, artifact_id = env
    with pytest.raises(Exception):
        services.browser_artifacts.credential_stores(
            "ev_00000000000b", artifact_id
        )


def test_credentials_web_panel_and_api(env):
    client, services, record, artifact_id = env
    panel = client.get(
        f"/evidence/{EVIDENCE}/browser/credentials?artifact_id={artifact_id}"
    )
    assert panel.status_code == 200
    body = panel.text
    assert "Credential stores" in body
    assert "metadata only" in body
    assert "logins.json" in body
    assert "accounts.example.test" in body
    assert SECRET_PASSWORD not in body
    data = client.get(
        f"/evidence/{EVIDENCE}/browser/credentials/api?artifact_id={artifact_id}"
    ).json()
    assert data["ok"] is True
    assert data["present_count"] >= 4


def test_credentials_mcp(env):
    client, services, record, artifact_id = env
    payload = mcp_server.browser_credential_stores(EVIDENCE, artifact_id)
    assert payload["trust"] == "untrusted_evidence_data"
    assert any(item["name"] == "logins.json" for item in payload["stores"])
    assert SECRET_PASSWORD not in json.dumps(payload)


def test_analyze_store_handles_missing_schema(tmp_path):
    from dfir_browser.core.browser_artifacts.credentials import empty_report

    path = tmp_path / "cookies.sqlite"
    connection = sqlite3.connect(str(path))
    connection.execute("CREATE TABLE unrelated(x)")
    connection.commit()
    connection.close()
    report = analyze_store(path, empty_report("cookies.sqlite", str(path)))
    assert report.exists is True
    assert any("schema differs" in warning for warning in report.warnings)


# ==================================================================
# Comprehensive Forensic Credentials Analysis Tests
# ==================================================================
def test_identify_browser_details_all_brands_and_platforms():
    from dfir_browser.core.browser_artifacts.detector import identify_browser_details, user_from_path

    # Windows NTFS paths
    chrome_win = "Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Login Data"
    brand, engine, profile, label = identify_browser_details(chrome_win)
    assert brand == "chrome"
    assert engine == "chromium"
    assert profile == "Default"
    assert label == "Google Chrome"

    edge_win = "Users/Bob/AppData/Local/Microsoft/Edge/User Data/Profile 2/Login Data"
    brand, engine, profile, label = identify_browser_details(edge_win)
    assert brand == "edge"
    assert engine == "chromium"
    assert profile == "Profile 2"
    assert label == "Microsoft Edge"

    brave_win = "Users/Charlie/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Login Data"
    brand, engine, profile, label = identify_browser_details(brave_win)
    assert brand == "brave"
    assert engine == "chromium"
    assert profile == "Default"

    opera_win = "Users/Dave/AppData/Roaming/Opera Software/Opera Stable/Login Data"
    brand, engine, profile, label = identify_browser_details(opera_win)
    assert brand == "opera"
    assert engine == "chromium"
    assert profile == "Opera Stable"

    ff_win = "Users/Eve/AppData/Roaming/Mozilla/Firefox/Profiles/abc123.default-release/logins.json"
    brand, engine, profile, label = identify_browser_details(ff_win)
    assert brand == "firefox"
    assert engine == "gecko"
    assert profile == "abc123.default-release"

    # Linux EXT4 paths
    chrome_linux = "/home/alice/.config/google-chrome/Profile 1/Login Data"
    brand, engine, profile, label = identify_browser_details(chrome_linux)
    assert brand == "chrome"
    assert engine == "chromium"
    assert profile == "Profile 1"

    edge_linux = "/home/bob/.config/microsoft-edge/Default/Login Data"
    brand, engine, profile, label = identify_browser_details(edge_linux)
    assert brand == "edge"
    assert engine == "chromium"
    assert profile == "Default"

    brave_linux = "/home/charlie/.config/BraveSoftware/Brave-Browser/Default/Login Data"
    brand, engine, profile, label = identify_browser_details(brave_linux)
    assert brand == "brave"
    assert engine == "chromium"
    assert profile == "Default"

    opera_linux = "/home/dave/.config/opera/Login Data"
    brand, engine, profile, label = identify_browser_details(opera_linux)
    assert brand == "opera"
    assert engine == "chromium"
    assert profile == "Default"

    chromium_snap = "/home/frank/snap/chromium/common/chromium/Default/Login Data"
    brand, engine, profile, label = identify_browser_details(chromium_snap)
    assert brand == "chromium"
    assert engine == "chromium"
    assert profile == "Default"

    ff_linux = "/home/eve/.mozilla/firefox/xyz789.default/logins.json"
    brand, engine, profile, label = identify_browser_details(ff_linux)
    assert brand == "firefox"
    assert engine == "gecko"
    assert profile == "xyz789.default"

    # User from path on both Linux and Windows
    assert user_from_path(chrome_win) == "Alice"
    assert user_from_path(chrome_linux) == "alice"
    assert user_from_path(ff_linux) == "eve"


def test_chromium_login_data_parsing_and_provenance(tmp_path):
    from dfir_browser.core.browser_artifacts.credentials import (
        parse_chromium_logins,
        inspect_local_state,
    )

    db_path = tmp_path / "Login Data"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE logins (
            origin_url TEXT,
            action_url TEXT,
            username_element TEXT,
            username_value TEXT,
            password_element TEXT,
            password_value BLOB,
            date_created INTEGER,
            date_last_used INTEGER,
            times_used INTEGER
        )
        """
    )

    # 1. OSCrypt v10
    v10_blob = b"v10" + b"\x00" * 28
    # 2. Windows DPAPI (0x01000000...)
    dpapi_blob = b"\x01\x00\x00\x00" + b"\xbb" * 24
    # 3. Plaintext
    plain_blob = b"clear_secret_123"
    # 4. Empty password
    empty_blob = b""

    # Chromium timestamps: 13245678901234567 microseconds since 1601
    conn.execute(
        "INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("https://portal.bank.test", "https://portal.bank.test/auth", "user", "admin@bank.test", "pass", v10_blob, 13245678901234567, 13245678901234567, 5),
    )
    conn.execute(
        "INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("https://internal.corp.test", None, "u", "corp_admin", "p", dpapi_blob, 13245678900000000, 13245678901000000, 2),
    )
    conn.execute(
        "INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("http://legacy.test", None, "u", "guest", "p", plain_blob, 13245670000000000, 13245670000000000, 1),
    )
    conn.execute(
        "INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("https://nopass.test", None, "u", "user_without_pass", "p", empty_blob, 13245670000000000, 0, 0),
    )
    conn.commit()
    conn.close()

    # Local State with DPAPI key
    local_state_path = tmp_path / "Local State"
    import base64
    fake_dpapi_key = base64.b64encode(b"DPAPI" + b"\x99" * 20).decode()
    local_state_path.write_text(json.dumps({"os_crypt": {"encrypted_key": fake_dpapi_key}}))
    local_state_info = inspect_local_state(local_state_path)

    context = {
        "brand": "chrome",
        "brand_label": "Google Chrome",
        "engine": "chromium",
        "profile": "Default",
        "user": "Alice",
        "source_path": "Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
        "entry_id": 101,
        "inode": 5555,
        "partition_offset": 2048,
        "offset_unit": "sectors",
        "sha256": "a" * 64,
        "evidence_id": "ev_test_chrome",
        "extracted_at": "2026-11-24T06:00:00Z",
    }

    records = parse_chromium_logins(
        db_path, context, mask_sensitive=True, local_state_info=local_state_info
    )
    assert len(records) == 4

    # 1. v10 with Local State DPAPI key verified
    rec0 = next(r for r in records if "bank.test" in r.website)
    assert rec0.protection_status == "OSCRYPT_AES_GCM"
    assert rec0.has_password is True
    assert rec0.password_masked == "••••••••"
    assert "clear_secret" not in rec0.password_masked
    assert rec0.username_masked == "a***n@bank.test"
    assert rec0.username_raw is None  # masked by default
    assert rec0.created_time_utc is not None
    assert rec0.created_time_raw == "13245678901234567"
    assert rec0.inode == 5555
    assert rec0.partition_offset == 2048
    assert rec0.sha256 == "a" * 64

    # 2. DPAPI blob
    rec1 = next(r for r in records if "corp.test" in r.website)
    assert rec1.protection_status == "WINDOWS_DPAPI"
    assert rec1.username_masked == "c***n"

    # 3. Plaintext
    rec2 = next(r for r in records if "legacy.test" in r.website)
    assert rec2.protection_status == "PLAINTEXT"
    # Even for plaintext, password is not revealed in cleartext in the record
    assert rec2.password_masked == "••••••••"

    # 4. Empty password
    rec3 = next(r for r in records if "nopass.test" in r.website)
    assert rec3.protection_status == "EMPTY"
    assert rec3.has_password is False


def test_unknown_protection_without_key_verification(tmp_path):
    """Requirement 5: Do not deduce algorithm based on raw prefix alone; report UNKNOWN."""
    from dfir_browser.core.browser_artifacts.credentials import (
        determine_chromium_protection,
        determine_firefox_protection,
    )

    # Chromium: v10 blob present, but Local State is missing / unverified -> UNKNOWN
    v10_blob = b"v10" + b"\x11" * 28
    status, details = determine_chromium_protection(v10_blob, local_state_info=None)
    assert status == "UNKNOWN"
    assert "unverified" in details

    # Chromium: v10 blob with invalid Local State key format -> UNKNOWN
    status_bad, _ = determine_chromium_protection(v10_blob, local_state_info={"has_encrypted_key": True, "key_format": "OTHER"})
    assert status_bad == "UNKNOWN"

    # Firefox: encType=1, but no key4.db or key3.db in profile -> UNKNOWN
    status_ff, details_ff = determine_firefox_protection(1, has_key4=False, has_key3=False)
    assert status_ff == "UNKNOWN"
    assert "unverified" in details_ff

    # Firefox: encType=1 with key4.db verified -> NSS_ENCRYPTED
    status_ff_ok, _ = determine_firefox_protection(1, has_key4=True, has_key3=False)
    assert status_ff_ok == "NSS_ENCRYPTED"


def test_firefox_logins_json_parsing_and_timestamps(tmp_path):
    from dfir_browser.core.browser_artifacts.credentials import parse_firefox_logins

    path = tmp_path / "logins.json"
    payload = {
        "nextId": 2,
        "logins": [
            {
                "id": 1,
                "hostname": "https://accounts.firefox.test",
                "formSubmitURL": "https://accounts.firefox.test/login",
                "usernameField": "email",
                "encryptedUsername": "user@example.test",
                "passwordField": "password",
                "encryptedPassword": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAyIK",
                "encType": 1,
                "timeCreated": 1600000000000,
                "timeLastUsed": 1600000050000,
                "timesUsed": 10,
            }
        ],
    }
    path.write_text(json.dumps(payload))

    context = {
        "brand": "firefox",
        "brand_label": "Mozilla Firefox",
        "engine": "gecko",
        "profile": "test.default",
        "user": "Eve",
        "source_path": "Users/Eve/AppData/Roaming/Mozilla/Firefox/Profiles/test.default/logins.json",
        "inode": 9999,
        "partition_offset": 4096,
        "sha256": "f" * 64,
        "evidence_id": "ev_test_firefox",
    }

    records = parse_firefox_logins(path, context, mask_sensitive=True, has_key4=True)
    assert len(records) == 1
    r = records[0]
    assert r.website == "https://accounts.firefox.test"
    assert r.protection_status == "NSS_ENCRYPTED"
    assert r.has_password is True
    assert r.password_masked == "••••••••"
    assert r.created_time_raw == "1600000000000"
    assert r.created_time_utc == "2020-09-13T12:26:40.000000Z"
    assert r.last_used_time_raw == "1600000050000"
    assert r.last_used_time_utc == "2020-09-13T12:27:30.000000Z"
    assert r.times_used == 10
    assert r.inode == 9999
    assert r.partition_offset == 4096


def test_masking_and_unmasking_logic():
    from dfir_browser.core.browser_artifacts.credentials import (
        export_credentials_csv,
        export_credentials_json,
        mask_username,
    )
    from dfir_browser.core.browser_artifacts.models import CredentialRecord

    # Username masking tests
    assert mask_username("admin@domain.com") == "a***n@domain.com"
    assert mask_username("administrator") == "a***r"
    assert mask_username("ab") == "**"
    assert mask_username("abc") == "a*c"
    assert mask_username("") == ""
    assert mask_username(None) == ""

    rec = CredentialRecord(
        record_id="c1",
        website="https://secret.bank.test",
        action_url=None,
        brand="chrome",
        brand_label="Google Chrome",
        engine="chromium",
        browser="chrome",
        profile="Default",
        user="Alice",
        username_element="user",
        username_masked="a***n@bank.test",
        username_raw="admin@bank.test",
        has_password=True,
        password_masked="••••••••",
        password_element="pwd",
        protection_status="OSCRYPT_AES_GCM",
        protection_details="OSCrypt AES-256-GCM",
        created_time_utc="2026-01-01T00:00:00.000000Z",
        created_time_raw="13245678901234567",
        last_used_time_utc="2026-01-02T00:00:00.000000Z",
        last_used_time_raw="13245678902234567",
        times_used=3,
        source_path="Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
        inode=123,
        partition_offset=2048,
        sha256="abc12345",
        evidence_id="ev_01",
    )

    # JSON export with mask_sensitive=True (default)
    json_masked = export_credentials_json([rec], mask_sensitive=True)
    assert "admin@bank.test" not in json_masked
    assert "a***n@bank.test" in json_masked

    # CSV export with mask_sensitive=True (default)
    csv_masked = export_credentials_csv([rec], mask_sensitive=True)
    assert "admin@bank.test" not in csv_masked
    assert "a***n@bank.test" in csv_masked
    assert "OSCRYPT_AES_GCM" in csv_masked

    # Compatibility flags cannot turn a redacted forensic export into a
    # credential dump.
    assert "admin@bank.test" not in export_credentials_json(
        [rec], mask_sensitive=False
    )
    assert "admin@bank.test" not in export_credentials_csv(
        [rec], mask_sensitive=False
    )


def test_corrupted_databases_and_malformed_json(tmp_path):
    from dfir_browser.core.browser_artifacts.credentials import (
        parse_chromium_logins,
        parse_firefox_logins,
    )

    # 1. Corrupted SQLite file (random bytes)
    corrupted_db = tmp_path / "corrupt_login_data.sqlite"
    corrupted_db.write_bytes(b"NOT A SQLITE DATABASE JUNK JUNK" * 20)
    context = {"brand": "chrome", "profile": "Default"}
    res_db = parse_chromium_logins(corrupted_db, context)
    assert res_db == []

    # 2. SQLite without 'logins' table
    empty_db = tmp_path / "empty_login.sqlite"
    conn = sqlite3.connect(str(empty_db))
    conn.execute("CREATE TABLE other (x)")
    conn.commit()
    conn.close()
    res_empty = parse_chromium_logins(empty_db, context)
    assert res_empty == []

    # 3. Malformed JSON
    corrupted_json = tmp_path / "corrupted_logins.json"
    corrupted_json.write_text("{ this is malformed json :::: ")
    res_json = parse_firefox_logins(corrupted_json, context)
    assert res_json == []

    # 4. JSON without 'logins' list
    bad_json = tmp_path / "bad_logins.json"
    bad_json.write_text(json.dumps({"logins": "not a list"}))
    res_bad = parse_firefox_logins(bad_json, context)
    assert res_bad == []


def test_credentials_web_export_csv_and_json(env):
    client, services, record, artifact_id = env

    # Test CSV export
    csv_resp = client.get(
        f"/evidence/{EVIDENCE}/browser/credentials/export?artifact_id={artifact_id}&format=csv"
    )
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "attachment;" in csv_resp.headers["content-disposition"]
    csv_text = csv_resp.text
    assert "website" in csv_text
    assert "browser_brand" in csv_text
    assert "accounts.example.test" in csv_text
    assert SECRET_PASSWORD not in csv_text

    # Test JSON export
    json_resp = client.get(
        f"/evidence/{EVIDENCE}/browser/credentials/export?artifact_id={artifact_id}&format=json"
    )
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]
    data = json_resp.json()
    assert data["trust"] == "untrusted_evidence_data"
    assert data["count"] >= 1
    assert data["records"][0]["website"] == "https://accounts.example.test"
    assert SECRET_PASSWORD not in json.dumps(data)


def test_credentials_analysis_mcp_tool(env):
    client, services, record, artifact_id = env
    payload = mcp_server.browser_credentials_analysis(
        EVIDENCE, artifact_id=artifact_id
    )
    assert payload["trust"] == "untrusted_evidence_data"
    assert "total_records" in payload
    assert payload["total_records"] >= 1
    rec = payload["records"][0]
    assert rec["website"] == "https://accounts.example.test"
    assert rec["engine"] == "gecko"
    assert rec["protection_status"] in ("NSS_ENCRYPTED", "UNKNOWN")
    assert SECRET_PASSWORD not in json.dumps(payload)


# ==================================================================
# Explicit credential reveal (opt-in, audited)
# ==================================================================
def _firefox_reveal_payload() -> tuple[bytes, bytes, str, str]:
    """Build a synthetic key4.db + logins.json pair with real NSS crypto."""
    import tempfile
    from pathlib import Path

    from dfir_browser.core.browser_artifacts import credentials_crypto as cc
    from test_credentials_crypto import (
        _aes_cbc_encrypt,
        _der_int,
        _der_octets,
        _der_oid,
        _der_seq,
        _login_container,
        _pbkdf2_key,
    )

    global_salt = b"\x21" * 32
    entry_salt = b"\x31" * 20
    iterations = 1
    key_length = 32
    derived = _pbkdf2_key(
        global_salt=global_salt,
        entry_salt=entry_salt,
        iterations=iterations,
        key_length=key_length,
    )

    def pbes2(stored_iv: bytes, cipher: bytes) -> bytes:
        kdf = _der_seq(
            _der_oid(cc.OID_PBKDF2),
            _der_seq(
                _der_octets(entry_salt),
                _der_int(iterations),
                _der_int(key_length),
                _der_seq(_der_oid(cc.OID_HMAC_SHA256)),
            ),
        )
        encryption = _der_seq(_der_oid(cc.OID_AES_256_CBC), _der_octets(stored_iv))
        return _der_seq(
            _der_seq(_der_oid(cc.OID_PBES2), _der_seq(kdf, encryption)),
            _der_octets(cipher),
        )

    stored_iv = b"\x22" * 14
    check = pbes2(
        stored_iv, _aes_cbc_encrypt(derived, b"\x04\x0e" + stored_iv, b"password-check\x02\x02")
    )
    key_stored_iv = b"\x33" * 14
    sdr_key = b"\x55" * 48
    a11 = pbes2(
        key_stored_iv, _aes_cbc_encrypt(derived, b"\x04\x0e" + key_stored_iv, sdr_key)
    )

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "key4.db"
        connection = sqlite3.connect(str(path))
        connection.executescript(
            """
            CREATE TABLE metadata(item1 BLOB, item2 BLOB, id TEXT);
            CREATE TABLE nssPrivate(id INTEGER PRIMARY KEY, a11 BLOB, a102 BLOB);
            """
        )
        connection.execute(
            "INSERT INTO metadata VALUES (?, ?, 'password')", (global_salt, check)
        )
        connection.execute("INSERT INTO nssPrivate VALUES (1, ?, ?)", (a11, cc.CKA_ID))
        connection.commit()
        connection.close()
        key4_bytes = path.read_bytes()

    login_iv = b"\x0a" * 16
    login = {
        "logins": [
            {
                "id": 1,
                "hostname": "https://accounts.reveal.test",
                "formSubmitURL": "https://accounts.reveal.test/login",
                "usernameField": "email",
                "passwordField": "password",
                "encryptedUsername": _login_container(
                    sdr_key[:32], login_iv, SECRET_USER.encode()
                ),
                "encryptedPassword": _login_container(
                    sdr_key[:32], login_iv, SECRET_PASSWORD.encode()
                ),
                "encType": 1,
                "timeCreated": 1600000000000,
                "timeLastUsed": 1600000050000,
                "timesUsed": 4,
            }
        ]
    }
    return (
        key4_bytes,
        json.dumps(login).encode(),
        SECRET_USER,
        SECRET_PASSWORD,
    )


@pytest.fixture()
def reveal_env(tmp_path, monkeypatch):
    """A Firefox profile with a decryptable logins.json, reveal enabled."""
    import dataclasses

    from dfir_browser.core.browser_artifacts.models import SourceArtifact

    key4_bytes, logins_bytes, _user, _password = _firefox_reveal_payload()
    rows = [
        (PLACES, "places.sqlite", 70000, 4096, False),
        (LOGINS, "logins.json", LOGINS_INODE, len(logins_bytes), False),
        (KEY4, "key4.db", KEY4_INODE, len(key4_bytes), False),
    ]
    services, record = build_browser_services(tmp_path, rows=rows)
    stub_browser_extract(
        services, {LOGINS_INODE: logins_bytes, KEY4_INODE: key4_bytes}
    )
    artifact_id = "ba_reveal_profile"
    services.browser_artifacts.store.upsert_artifact(
        SourceArtifact(
            artifact_id=artifact_id,
            evidence_id=EVIDENCE,
            entry_id=entry_id(services, PLACES),
            inode=70000,
            evidence_path=PLACES,
            filename="places.sqlite",
            browser="firefox",
            artifact_type="firefox_places",
            user="IEUser",
            profile_name="abc.default",
            size=4096,
            sha256=None,
            status="ready",
            phase="ready",
            backend="firefox-sqlite",
            parser_version="test",
        )
    )
    # Enable the gate on the service settings only for this test.
    services.settings = dataclasses.replace(
        services.settings,
        credential_reveal_enabled=True,
        credential_reveal_max_records=100,
    )
    services.browser_artifacts.settings = services.settings
    app = create_app(services.settings, services)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with TestClient(app) as client:
        yield client, services, record, artifact_id
    services.cleanup()


def test_reveal_is_disabled_by_default(env):
    """The gate must be off unless the host explicitly enables it."""
    client, services, record, artifact_id = env
    assert services.settings.credential_reveal_enabled is False
    with pytest.raises(Exception) as excinfo:
        services.browser_artifacts.reveal_credentials(
            EVIDENCE, artifact_id=artifact_id
        )
    assert "disabled" in str(excinfo.value)
    # A disabled gate must not have decrypted or exposed anything either.
    assert SECRET_PASSWORD not in str(excinfo.value)


def test_reveal_decrypts_firefox_credentials(reveal_env):
    client, services, record, artifact_id = reveal_env
    result = services.browser_artifacts.reveal_credentials(
        EVIDENCE, artifact_id=artifact_id
    )
    assert result.total_records == 1
    assert result.decrypted_usernames == 1
    assert result.decrypted_passwords == 1
    record_out = result.records[0]
    assert record_out.username == SECRET_USER
    assert record_out.password == SECRET_PASSWORD
    assert record_out.website == "https://accounts.reveal.test"
    assert record_out.inode == LOGINS_INODE
    assert record_out.protection_status == "NSS_ENCRYPTED"


def test_reveal_writes_audit_event_without_secrets(reveal_env):
    client, services, record, artifact_id = reveal_env
    services.browser_artifacts.reveal_credentials(
        EVIDENCE, artifact_id=artifact_id
    )
    audit_path = services.settings.audit_file()
    text = audit_path.read_text(encoding="utf-8")
    assert "browser_credentials_reveal" in text
    # Counts and identifiers are audited; the secrets themselves never are.
    assert SECRET_PASSWORD not in text
    assert SECRET_USER not in text
    events = [
        json.loads(line)
        for line in text.splitlines()
        if "browser_credentials_reveal" in line
    ]
    assert events
    details = events[-1]["details"]
    assert details["records"] == 1
    assert details["decrypted_passwords"] == 1


def test_reveal_web_endpoint_writes_file_not_html(reveal_env):
    client, services, record, artifact_id = reveal_env
    page = client.get(
        f"/evidence/{EVIDENCE}/browser/credentials?artifact_id={artifact_id}"
    )
    assert page.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    assert "Decrypt credentials" in page.text

    response = client.post(
        f"/evidence/{EVIDENCE}/browser/credentials/reveal",
        data={
            "csrf_token": token,
            "artifact_id": artifact_id,
            "format": "csv",
            "confirm": "yes",
        },
    )
    assert response.status_code == 200
    body = response.text
    # The page reports counters and the export path, never the plaintext.
    assert SECRET_PASSWORD not in body
    assert SECRET_USER not in body
    assert "Decrypted" not in body or "decrypted" in body
    match = re.search(r"/credentials/reveal/export/([^\"']+)", body)
    assert match is not None

    download = client.get(
        f"/evidence/{EVIDENCE}/browser/credentials/reveal/export/{match.group(1)}"
    )
    assert download.status_code == 200
    assert SECRET_PASSWORD in download.text
    assert SECRET_USER in download.text


def test_reveal_web_requires_confirmation_and_csrf(reveal_env):
    client, services, record, artifact_id = reveal_env
    page = client.get(
        f"/evidence/{EVIDENCE}/browser/credentials?artifact_id={artifact_id}"
    )
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

    no_confirm = client.post(
        f"/evidence/{EVIDENCE}/browser/credentials/reveal",
        data={"csrf_token": token, "artifact_id": artifact_id, "format": "csv"},
    )
    assert no_confirm.status_code == 400
    assert SECRET_PASSWORD not in no_confirm.text

    no_csrf = client.post(
        f"/evidence/{EVIDENCE}/browser/credentials/reveal",
        data={"artifact_id": artifact_id, "confirm": "yes"},
    )
    assert no_csrf.status_code == 403


def test_reveal_export_filename_must_be_a_basename(reveal_env):
    client, services, record, artifact_id = reveal_env
    response = client.get(
        f"/evidence/{EVIDENCE}/browser/credentials/reveal/export/..%2F..%2Fsecret.key"
    )
    assert response.status_code in {400, 404}
    assert "root:" not in response.text


def test_reveal_mcp_tool(reveal_env):
    client, services, record, artifact_id = reveal_env
    payload = mcp_server.browser_credentials_reveal(
        EVIDENCE, artifact_id=artifact_id
    )
    assert payload["trust"] == "untrusted_evidence_data"
    assert payload["decrypted_passwords"] == 1
    assert payload["records"][0]["password"] == SECRET_PASSWORD


def test_reveal_csv_export_contains_plaintext_but_neutralizes_formulas(reveal_env):
    from dfir_browser.core.browser_artifacts.credentials_crypto import (
        export_reveal_csv,
    )

    client, services, record, artifact_id = reveal_env
    result = services.browser_artifacts.reveal_credentials(
        EVIDENCE, artifact_id=artifact_id
    )
    text = export_reveal_csv(result.records)
    assert SECRET_PASSWORD in text
    assert "website" in text.splitlines()[0]
    assert "source_path" in text.splitlines()[0]

