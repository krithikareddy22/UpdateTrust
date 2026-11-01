import json, os, time, hashlib
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
from config import SECRET_KEY, UPLOAD_FOLDER, KEY_FOLDER, MAX_CONTENT_LENGTH
from database import connect, init_db, log_event
from crypto_utils import sign_bytes, verify_bytes
from manifest_utils import sha256_file, canonical_manifest
from verification import verify_release

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {".txt", ".zip", ".bin", ".dat", ".json"}

@app.before_request
def setup():
    init_db()

def get_rows(query, args=()):
    with connect() as con:
        return con.execute(query, args).fetchall()

@app.route("/")
def index():
    releases = get_rows("""SELECT r.*, p.name publisher_name FROM releases r JOIN publishers p ON p.id=r.publisher_id
                         ORDER BY r.id DESC LIMIT 8""")
    products = get_rows("SELECT * FROM trusted_versions ORDER BY product")
    events = get_rows("SELECT * FROM events ORDER BY id DESC LIMIT 8")
    stats = {
        "releases": get_rows("SELECT COUNT(*) n FROM releases")[0]["n"],
        "products": len(products),
        "accepted": get_rows("SELECT COUNT(*) n FROM events WHERE status='ACCEPTED'")[0]["n"],
        "rejected": get_rows("SELECT COUNT(*) n FROM events WHERE status='REJECTED'")[0]["n"],
    }
    return render_template("index.html", releases=releases, products=products, events=events, stats=stats, page="dashboard")

@app.route("/releases", methods=["GET", "POST"])
def releases():
    if request.method == "POST":
        product = request.form.get("product", "").strip()
        publisher_id = request.form.get("publisher_id", type=int)
        version = request.form.get("version", type=int)
        upload = request.files.get("package")
        if not product or not version or version < 1 or not upload or not upload.filename:
            flash("Enter a product, positive version, publisher, and package file.", "error")
            return redirect(url_for("releases"))
        suffix = Path(upload.filename).suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            flash("Unsupported file type. Allowed: " + ", ".join(sorted(ALLOWED_EXTENSIONS)), "error")
            return redirect(url_for("releases"))
        safe_name = secure_filename(upload.filename)
        stored_name = f"{int(time.time()*1000)}_{safe_name}"
        path = UPLOAD_FOLDER / stored_name
        UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
        upload.save(path)
        digest = sha256_file(path)
        with connect() as con:
            publisher = con.execute("SELECT * FROM publishers WHERE id=? AND trusted=1", (publisher_id,)).fetchone()
            if not publisher:
                path.unlink(missing_ok=True)
                flash("Choose a trusted publisher.", "error")
                return redirect(url_for("releases"))
            manifest = {
                "format_version": 1, "product": product, "version": version,
                "filename": safe_name, "sha256": digest, "publisher": publisher["name"],
                "publisher_id": publisher_id, "created_unix": int(time.time()),
                "release_id": hashlib.sha256(f"{product}:{version}:{digest}:{time.time_ns()}".encode()).hexdigest()[:24]
            }
            private_path = KEY_FOLDER / "demo_publisher_private.pem"
            if publisher["name"] != "Demo Publisher" or not private_path.exists():
                path.unlink(missing_ok=True)
                flash("This demo can sign releases only with the local Demo Publisher key. Add signing-key management before production use.", "error")
                return redirect(url_for("releases"))
            signature = sign_bytes(private_path.read_bytes(), canonical_manifest(manifest))
            cur = con.execute("""INSERT INTO releases(product,version,filename,stored_path,sha256,publisher_id,manifest_json,signature)
                VALUES(?,?,?,?,?,?,?,?)""", (product, version, safe_name, str(path), digest, publisher_id,
                json.dumps(manifest, sort_keys=True), signature))
            release_id = cur.lastrowid
            con.commit()
        log_event("release", "CREATED", f"Created release #{release_id}: {product} v{version}")
        flash(f"Release #{release_id} created and signed. Verify it to enforce the trusted version.", "success")
        return redirect(url_for("releases"))
    rows = get_rows("""SELECT r.*,p.name publisher_name FROM releases r JOIN publishers p ON p.id=r.publisher_id ORDER BY r.id DESC""")
    publishers = get_rows("SELECT * FROM publishers ORDER BY name")
    return render_template("releases.html", releases=rows, publishers=publishers, page="releases")

@app.route("/verify/<int:release_id>", methods=["POST"])
def verify(release_id):
    ok, message = verify_release(release_id)
    flash(message, "success" if ok else "error")
    return redirect(request.referrer or url_for("releases"))

@app.route("/release/<int:release_id>/delete", methods=["POST"])
def delete_release(release_id):
    with connect() as con:
        row = con.execute("SELECT * FROM releases WHERE id=?", (release_id,)).fetchone()
        if not row:
            flash("Release not found.", "error")
            return redirect(url_for("releases"))
        con.execute("DELETE FROM releases WHERE id=?", (release_id,))
        con.commit()
    try:
        Path(row["stored_path"]).unlink(missing_ok=True)
    except OSError:
        pass
    # Intentionally preserve trusted_versions: deleting evidence must never lower rollback protection.
    log_event("release", "DELETED", f"Deleted release #{release_id}; trusted version state was preserved")
    flash("Release and package file deleted. Trusted version state was preserved.", "success")
    return redirect(url_for("releases"))

@app.route("/publishers", methods=["GET", "POST"])
def publishers():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Publisher name is required.", "error")
        elif name == "Demo Publisher":
            flash("Demo Publisher already exists.", "error")
        else:
            with connect() as con:
                con.execute("INSERT OR IGNORE INTO publishers(name,public_key_pem,trusted) VALUES(?,?,0)", (name, ""))
                con.commit()
            log_event("publisher", "CREATED", f"Added untrusted publisher record: {name}")
            flash("Publisher added as untrusted. This demo UI does not import external keys.", "success")
        return redirect(url_for("publishers"))
    rows = get_rows("SELECT id,name,created_at,trusted FROM publishers ORDER BY id")
    return render_template("publishers.html", publishers=rows, page="publishers")

@app.route("/publishers/<int:publisher_id>/toggle", methods=["POST"])
def toggle_publisher(publisher_id):
    with connect() as con:
        row = con.execute("SELECT * FROM publishers WHERE id=?", (publisher_id,)).fetchone()
        if row and row["name"] != "Demo Publisher":
            new = 0 if row["trusted"] else 1
            con.execute("UPDATE publishers SET trusted=? WHERE id=?", (new, publisher_id))
            con.commit()
            log_event("publisher", "UPDATED", f"Publisher {row['name']} trust set to {new}")
    return redirect(url_for("publishers"))

@app.route("/attack-lab", methods=["GET", "POST"])
def attack_lab():
    if request.method == "POST":
        rid = request.form.get("release_id", type=int)
        attack = request.form.get("attack")
        with connect() as con:
            row = con.execute("SELECT * FROM releases WHERE id=?", (rid,)).fetchone()
            if not row:
                flash("Select an existing release.", "error")
                return redirect(url_for("attack_lab"))
            if attack == "tamper":
                with open(row["stored_path"], "ab") as f: f.write(b"\nTAMPERED_BY_DEMO")
                log_event("attack", "SIMULATED", f"Tamper simulation applied to release #{rid}")
                flash("Tampering simulated. Verify the release to see hash mismatch.", "success")
            elif attack == "signature":
                con.execute("UPDATE releases SET signature=? WHERE id=?", ("invalid-signature-demo", rid))
                con.commit()
                log_event("attack", "SIMULATED", f"Invalid signature simulation applied to release #{rid}")
                flash("Signature altered. Verification should reject it.", "success")
            elif attack == "manifest":
                manifest = json.loads(row["manifest_json"])
                manifest["version"] = int(manifest["version"]) + 10
                con.execute("UPDATE releases SET manifest_json=? WHERE id=?", (json.dumps(manifest, sort_keys=True), rid))
                con.commit()
                log_event("attack", "SIMULATED", f"Manifest tamper simulation applied to release #{rid}")
                flash("Manifest altered without a valid signature. Verification should reject it.", "success")
        return redirect(url_for("attack_lab"))
    rows = get_rows("SELECT id,product,version,filename FROM releases ORDER BY id DESC")
    return render_template("attack_lab.html", releases=rows, page="attack")

@app.route("/events")
def events():
    rows = get_rows("SELECT * FROM events ORDER BY id DESC LIMIT 250")
    return render_template("events.html", events=rows, page="events")

@app.route("/benchmarks", methods=["GET", "POST"])
def benchmarks():
    results = []
    if request.method == "POST":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        results = []
        for size in (1024, 102400, 1048576, 10485760):
            payload = os.urandom(size)
            start = time.perf_counter()
            digest = hashlib.sha256(payload).hexdigest()
            hash_ms = (time.perf_counter()-start)*1000
            start = time.perf_counter(); sig = key.sign(payload); sign_ms = (time.perf_counter()-start)*1000
            start = time.perf_counter(); pub.verify(sig, payload); verify_ms = (time.perf_counter()-start)*1000
            results.append({"size":size,"hash_ms":round(hash_ms,4),"sign_ms":round(sign_ms,4),"verify_ms":round(verify_ms,4),"digest":digest[:16]})
        log_event("benchmark", "COMPLETED", "Ran local SHA-256 and Ed25519 benchmark")
    return render_template("benchmarks.html", results=results, page="benchmarks")

@app.route("/docs")
def docs():
    return render_template("docs.html", page="docs")

@app.errorhandler(413)
def too_large(_):
    flash("Upload is too large. Maximum size is 16 MB.", "error")
    return redirect(url_for("releases"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
