import json
import pytest
from app import app
from database import init_db, connect
from verification import verify_release
from manifest_utils import canonical_manifest
from crypto_utils import sign_bytes
from pathlib import Path

@pytest.fixture
def client(tmp_path, monkeypatch):
    import config, database
    monkeypatch.setattr(config, "DATABASE", tmp_path / "test.db")
    monkeypatch.setattr(config, "UPLOAD_FOLDER", tmp_path / "uploads")
    monkeypatch.setattr(config, "KEY_FOLDER", tmp_path / "keys")
    # database module imported DATABASE by value; patch its reference too.
    monkeypatch.setattr(database, "DATABASE", tmp_path / "test.db")
    app.config["TESTING"] = True
    init_db()
    with app.test_client() as c:
        yield c

def make_release(client, product, version, content):
    response = client.post("/releases", data={
        "product": product, "version": str(version), "publisher_id": "1",
        "package": ( __import__("io").BytesIO(content), f"v{version}.txt")
    }, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    with connect() as con:
        return con.execute("SELECT id FROM releases ORDER BY id DESC LIMIT 1").fetchone()["id"]

def test_first_release_advances_version(client):
    rid = make_release(client, "App", 1, b"one")
    ok, _ = verify_release(rid)
    assert ok
    with connect() as con:
        assert con.execute("SELECT version FROM trusted_versions WHERE product='App'").fetchone()["version"] == 1

def test_rollback_rejected_and_state_preserved(client):
    r1 = make_release(client, "App", 1, b"one")
    assert verify_release(r1)[0]
    r2 = make_release(client, "App", 2, b"two")
    assert verify_release(r2)[0]
    assert not verify_release(r1)[0]
    with connect() as con:
        assert con.execute("SELECT version FROM trusted_versions WHERE product='App'").fetchone()["version"] == 2

def test_tamper_rejected(client):
    rid = make_release(client, "App", 1, b"original")
    with connect() as con:
        path = con.execute("SELECT stored_path FROM releases WHERE id=?", (rid,)).fetchone()["stored_path"]
    with open(path, "ab") as f: f.write(b"tampered")
    assert not verify_release(rid)[0]

def test_delete_does_not_reset_trusted_version(client):
    rid = make_release(client, "App", 1, b"one")
    assert verify_release(rid)[0]
    client.post(f"/release/{rid}/delete", follow_redirects=True)
    with connect() as con:
        assert con.execute("SELECT version FROM trusted_versions WHERE product='App'").fetchone()["version"] == 1
