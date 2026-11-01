import json
from database import connect, log_event
from manifest_utils import sha256_file, canonical_manifest
from crypto_utils import verify_bytes

def verify_release(release_id):
    with connect() as con:
        release = con.execute("""SELECT r.*, p.name AS publisher_name, p.public_key_pem, p.trusted
            FROM releases r JOIN publishers p ON p.id=r.publisher_id WHERE r.id=?""", (release_id,)).fetchone()
        if not release:
            return False, "Release not found."
        try:
            manifest = json.loads(release["manifest_json"])
        except Exception:
            return False, "Malformed manifest."
        actual_hash = sha256_file(release["stored_path"])
        if actual_hash != manifest.get("sha256") or actual_hash != release["sha256"]:
            log_event("verification", "REJECTED", f"Release #{release_id}: package hash mismatch")
            return False, "Package hash mismatch: file may have been tampered with."
        if not release["trusted"]:
            log_event("verification", "REJECTED", f"Release #{release_id}: publisher is untrusted")
            return False, "Publisher is not trusted."
        if not verify_bytes(release["public_key_pem"].encode(), canonical_manifest(manifest), release["signature"]):
            log_event("verification", "REJECTED", f"Release #{release_id}: invalid signature")
            return False, "Invalid digital signature."
        product, version = release["product"], release["version"]
        con.execute("BEGIN IMMEDIATE")
        current = con.execute("SELECT version FROM trusted_versions WHERE product=?", (product,)).fetchone()
        if current and version <= current["version"]:
            con.execute("ROLLBACK")
            reason = "Rollback/replay rejected: release version must be newer than the trusted version."
            log_event("verification", "REJECTED", f"Release #{release_id}: {reason}")
            return False, reason
        con.execute("""INSERT INTO trusted_versions(product,version,release_id,updated_at)
            VALUES(?,?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(product) DO UPDATE SET version=excluded.version, release_id=excluded.release_id, updated_at=CURRENT_TIMESTAMP""",
            (product, version, release_id))
        con.execute("COMMIT")
        log_event("verification", "ACCEPTED", f"Release #{release_id} verified; trusted version is now {version}")
        return True, f"Signature and hash valid. Accepted version {version}; trusted version advanced."
