# UpdateTrust
### Ed25519-Based Software Update Verification with Rollback Attack Prevention

UpdateTrust is a local educational web application that demonstrates software-update authenticity, integrity, publisher trust, and version rollback protection. It uses Flask, SQLite, SHA-256, and Ed25519 signatures.

> **Safety:** Uploaded packages are treated as opaque files and are never executed. This is a classroom demonstration, not a production update service. Use harmless sample files only.

## Features
- Create and sign a release manifest with product, version, filename, SHA-256, publisher, timestamp, and release identifier.
- Verify package hash and Ed25519 signature.
- Track the highest accepted version per product in SQLite.
- Reject same-version replays and older-version rollback attempts.
- Preserve trusted version state when a release record is deleted.
- Simulate package tampering, invalid signatures, and manifest tampering.
- View publisher trust records and an event log.
- Run local SHA-256/Ed25519 timing benchmarks at 1 KB, 100 KB, 1 MB, and 10 MB.
- Automated tests for core security rules.

## Requirements
Python 3.10+ (tested design target: Python 3.12), Windows/macOS/Linux.

## Run on Windows CMD
Open Command Prompt and run:

```bat
cd path\to\UpdateTrust
py -3.12 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser. If `py -3.12` is not available, use the full path to your Python executable.

## First demo
1. Open **Releases**.
2. Create a product named `CampusApp`, version `1`, publisher `Demo Publisher`, and upload a harmless `.txt` file.
3. Click **Verify**. A successful verification records trusted version 1.
4. Create version `2` and verify it. The trusted version advances to 2.
5. Try verifying version 1 again: it is rejected as rollback/replay.
6. Use **Attack Lab** to tamper with a release or alter its signature, then verify it and observe rejection.
7. Delete a release and confirm the trusted-version record remains.

## Run tests
```bat
python -m pytest -q
```

## Important design notes
- Manifest JSON is canonicalized using sorted keys and compact separators before signing.
- The verifier checks the package hash, publisher trust, and Ed25519 signature before applying version policy.
- `BEGIN IMMEDIATE` protects the trusted-version update from concurrent verification races.
- Failed verification never advances the trusted version.
- Deleting a release does not delete or lower the independent `trusted_versions` record.
- The app only signs releases with its local Demo Publisher private key. New publisher records are untrusted and require real key-management functionality to be production-ready.
- The included development Flask secret key must be changed before any deployment beyond localhost.
- For real deployment, add authentication/authorization, CSRF protection, secret management or hardware-backed keys, HTTPS, audit-log protection, key rotation/revocation, database migrations, and stronger concurrency/security tests.
