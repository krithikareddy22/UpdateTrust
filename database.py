import sqlite3
from config import DATABASE

def connect():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DATABASE, timeout=10, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS publishers(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
          public_key_pem TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          trusted INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS releases(
          id INTEGER PRIMARY KEY AUTOINCREMENT, product TEXT NOT NULL, version INTEGER NOT NULL,
          filename TEXT NOT NULL, stored_path TEXT NOT NULL, sha256 TEXT NOT NULL,
          publisher_id INTEGER NOT NULL, manifest_json TEXT NOT NULL, signature TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(publisher_id) REFERENCES publishers(id)
        );
        CREATE TABLE IF NOT EXISTS trusted_versions(
          product TEXT PRIMARY KEY, version INTEGER NOT NULL, release_id INTEGER,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, status TEXT NOT NULL,
          message TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_releases_product ON releases(product, version);
        """)
        row = con.execute("SELECT id FROM publishers WHERE name=?", ("Demo Publisher",)).fetchone()
        if not row:
            from crypto_utils import generate_keypair
            private_pem, public_pem = generate_keypair()
            # Demo key is intentionally generated locally; private key is never returned by a route.
            from config import KEY_FOLDER
            KEY_FOLDER.mkdir(parents=True, exist_ok=True)
            private_path = KEY_FOLDER / "demo_publisher_private.pem"
            public_path = KEY_FOLDER / "demo_publisher_public.pem"
            if not private_path.exists(): private_path.write_bytes(private_pem)
            if not public_path.exists(): public_path.write_bytes(public_pem)
            con.execute("INSERT INTO publishers(name, public_key_pem) VALUES(?,?)", ("Demo Publisher", public_pem.decode()))
        con.commit()

def log_event(category, status, message):
    with connect() as con:
        con.execute("INSERT INTO events(category,status,message) VALUES(?,?,?)", (category, status, message))
        con.commit()
