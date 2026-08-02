"""
Automated verification tests for the remediated application
(app/secure_app_fixed.py).

Each test maps directly to a finding in reports/SECURITY_REVIEW_REPORT.md
and proves the corresponding fix actually works — not just that the code
"looks" fixed.

Run with:
    pytest tests/ -v
"""

import json
import os
import sys
from io import BytesIO

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-for-pytest")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh app + fresh throwaway SQLite DB for every test."""
    from app import secure_app_fixed as m

    db_path = tmp_path / "test_shop.db"
    monkeypatch.setattr(m, "DB_PATH", str(db_path))
    upload_dir = tmp_path / "uploads"
    monkeypatch.setattr(m, "UPLOAD_DIR", str(upload_dir))

    m.init_db()
    with m.app.test_client() as c:
        yield c


def register(client, username="alice", password="password123"):
    return client.post("/register", data={"username": username, "password": password})


class TestAuthentication:
    def test_register_then_login_succeeds(self, client):
        assert register(client).status_code == 200
        r = client.post("/login", data={"username": "alice", "password": "password123"})
        assert r.status_code == 302
        assert r.headers["Location"] == "/dashboard"

    def test_login_with_wrong_password_rejected(self, client):
        register(client)
        r = client.post("/login", data={"username": "alice", "password": "wrong"})
        assert r.status_code == 401

    def test_dashboard_route_resolves(self, client):
        """Regression test: earlier version redirected to a route that
        did not exist, producing a 404 after a successful login."""
        assert client.get("/dashboard").status_code == 200


class TestSQLInjection:
    def test_classic_sqli_payload_does_not_bypass_login(self, client):
        register(client)
        r = client.post(
            "/login",
            data={"username": "alice' OR '1'='1' --", "password": "anything"},
        )
        assert r.status_code == 401

    def test_sqli_payload_does_not_break_query_execution(self, client):
        """A vulnerable string-built query would either error out or leak
        rows; a parameterized query just treats it as a literal username."""
        register(client)
        r = client.post(
            "/login",
            data={"username": "'; DROP TABLE users; --", "password": "x"},
        )
        assert r.status_code == 401
        # Table must still exist / still usable afterward
        r2 = client.post("/login", data={"username": "alice", "password": "password123"})
        assert r2.status_code == 302


class TestPasswordHashing:
    def test_password_is_not_stored_as_plain_md5(self, client, tmp_path):
        import sqlite3

        register(client, password="password123")
        from app import secure_app_fixed as m

        conn = sqlite3.connect(m.DB_PATH)
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("alice",)
        ).fetchone()
        conn.close()

        import hashlib

        md5_of_password = hashlib.md5(b"password123").hexdigest()
        assert row[0] != md5_of_password
        # werkzeug PBKDF2 hashes are salted -> never match a bare hash of the input
        assert row[0].startswith("pbkdf2:") or row[0].startswith("scrypt:")

    def test_short_passwords_rejected(self, client):
        r = client.post("/register", data={"username": "bob", "password": "123"})
        assert r.status_code == 400


class TestXSS:
    def test_script_tag_is_escaped_in_search_output(self, client):
        r = client.get("/search", query_string={"q": "<script>alert(1)</script>"})
        assert b"<script>" not in r.data
        assert b"&lt;script&gt;" in r.data


class TestCommandInjection:
    def test_disallowed_host_rejected(self, client):
        r = client.get("/ping", query_string={"host": "127.0.0.1; rm -rf /"})
        assert r.status_code == 400

    def test_shell_metacharacters_cannot_chain_commands(self, client):
        r = client.get("/ping", query_string={"host": "127.0.0.1 && whoami"})
        assert r.status_code == 400

    def test_allowed_host_does_not_500(self, client):
        r = client.get("/ping", query_string={"host": "127.0.0.1"})
        # Either it runs ping successfully (200) or the binary is missing
        # in this environment (503) — it must never crash with a 500.
        assert r.status_code in (200, 503)


class TestInsecureDeserialization:
    def test_cart_accepts_valid_json(self, client):
        r = client.post(
            "/load_cart",
            data=json.dumps({"sku": "abc123", "qty": 2}),
            content_type="application/json",
        )
        assert r.status_code == 200
        assert r.get_json()["items"]["sku"] == "abc123"

    def test_cart_rejects_non_json_payload(self, client):
        """A pickle-based endpoint would attempt to deserialize (and
        potentially execute) this. json.loads must just fail safely."""
        r = client.post(
            "/load_cart",
            data=b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.",  # pickle opcode bytes
            content_type="application/octet-stream",
        )
        assert r.status_code == 400


class TestFileUpload:
    def test_allowed_extension_accepted(self, client):
        r = client.post(
            "/upload",
            data={"file": (BytesIO(b"fake image bytes"), "photo.png")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200

    def test_disallowed_extension_rejected(self, client):
        r = client.post(
            "/upload",
            data={"file": (BytesIO(b"<?php system($_GET['c']); ?>"), "shell.php")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 400

    def test_path_traversal_filename_is_sanitized(self, client, tmp_path):
        from app import secure_app_fixed as m

        r = client.post(
            "/upload",
            data={"file": (BytesIO(b"data"), "../../etc/passwd.png")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 200
        # secure_filename() must strip path components - file should land
        # directly inside UPLOAD_DIR, not escape it.
        saved_files = os.listdir(m.UPLOAD_DIR)
        assert all(".." not in f and "/" not in f for f in saved_files)


class TestConfiguration:
    def test_secret_key_is_not_the_old_hardcoded_value(self):
        from app import secure_app_fixed as m

        assert m.app.secret_key != "supersecret123"

    def test_app_raises_if_secret_key_env_var_missing(self, monkeypatch):
        """Confirms the fail-closed behavior added in the fix."""
        import importlib

        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
        from app import secure_app_fixed as m

        with pytest.raises(RuntimeError):
            importlib.reload(m)
        # restore for subsequent tests in the same process
        monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret-for-pytest")
        importlib.reload(m)
