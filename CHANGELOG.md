# Changelog

All notable changes to the **Kenya Farmer Hash Registry** project will be documented in this file.

---

## [1.2.0] - 2026-10-15 (Audit Round 2 Hardening)

### Added
- **Strict Signature v2 Enforcement:**
  - Deleted legacy `compute_request_signature` (v1) body-only signing fallback.
  - Required `X-Timestamp`, `X-Nonce`, and `X-Signature` on all partner requests; returns 401 `"Missing signature headers"` if absent.
  - Verification sequence hardened: signature verified *before* recording nonce in database. Concurrent replays caught via `uq_partner_nonce` IntegrityError.
- **Strict Production Security Gates:**
  - `ENV` defaults to `production`. Development mode must be explicitly specified (`ENV=development`).
  - Added strict production startup validation: refuses startup if `SERVER_KEY`, `ADMIN_KEY`, `DASHBOARD_PASSWORD`, or `DATABASE_URL` are missing, shorter than 32 characters, contain `CHANGE_ME`, match committed insecure keys, use SQLite, have `SEED_TEST_PARTNERS=True`, or use admin password $<16$ characters.
  - `.env.example` updated with explicit `CHANGE_ME` values that can never pass production gates.
- **Accurate Database Reset Logging:**
  - `scripts/reset_db.py` queries actual seeded partner records and reports true count and names instead of unconditionally printing.
- **Scenario 9 (Legacy Signature Rejection):**
  - Added `legacy-signature` scenario to `simulator/scenarios.py` verifying body-only HMAC signatures are rejected with 401.

### Changed
- **Credit Attribution on Link Reactivation:**
  - On reactivation of a previously withdrawn partner link, `received_at` resets to current server UTC time (`received_at = now`). First-to-onboard credit stays with the continuous active partner.
- **Bulk CSV Upload Date Parsing:**
  - In `app/routes/farmers.py`, `parse_iso_datetime` raises `ValueError` on unparseable date strings. Unparseable dates reject only that row (`rows_rejected += 1`) without logging row content or PII. Empty `onboarded_at` remains permitted and uses upload time.
- **Dashboard Layout & Neutral Test Partners:**
  - Balanced `<div>` tags in `app/templates/dashboard.html` (closing tag added, restoring the 3-tile single-row layout).
  - Replaced legacy test partners with neutral `test_partner_a`, `test_partner_b`, `test_partner_c` across `app/main.py`, simulator, and tests.
  - Sanitized real organisation names from repository documentation.
- **Pinned Dependencies & Dev Endpoint Protection:**
  - Pinned exact dependency versions in `requirements.txt`.
  - Added test coverage ensuring `GET /dev/console` and `GET /dev/unsuppressed-metrics` return 200 in development and 404 in production.

---

## [1.1.0] - 2026-10-15 (Review Fixes Release)

### Added
- **Alembic Migrations:**
  - `0002_add_received_at_and_active.py`: Adds `received_at` timestamp column to `partner_link` and `active` integer column to `partner`.
  - `0003_add_request_nonce.py`: Adds `request_nonce` table with unique constraint on `(partner_id, nonce)` for anti-replay protection.
- **Request Signature v2 & Anti-Replay Protection:**
  - Implemented `sign_request` in Python SDK (`sdk/python/hasher.py`) and JavaScript SDK (`sdk/js/hasher.js`).
  - Added HTTP headers `X-Timestamp` and `X-Nonce`.
  - Authenticator verifies canonical HMAC-SHA256 signature across method, path, query, timestamp, nonce, and payload SHA-256 digest.
  - Replayed nonces within a 10-minute caching window and timestamps outside a 300-second tolerance window return HTTP 401.
- **Partner Management CLI:**
  - Added `app/cli.py` with commands `add-partner`, `list-partners`, and `disable-partner`.
  - Generates cryptographically secure API keys, stores only their SHA-256 digest, and prints the key once.
  - Disabled partners immediately receive HTTP 401 on all API endpoints.
- **Key Generation Utility:**
  - Added `scripts/generate_keys.py` to generate 32-byte hex-encoded secrets (`PARTNER_KEY`, `SERVER_KEY`, `ADMIN_KEY`, `DASHBOARD_PASSWORD`) and write local `.env` with `--write-env`.
- **Local Developer Experience & Web Test Console:**
  - `make local`: One-command startup on SQLite (`http://localhost:8008`) with random `.env` generation and neutral test partner seeding.
  - `make local-reset`: Cross-platform local database reset and test partner re-seeding (`scripts/reset_db.py`).
  - `GET /dev/console`: Interactive browser test console with WebCrypto client hashing, action buttons (register, resend, overlap, backdate, withdraw, bulk upload, replay test), and live unsuppressed metrics panel. Returns 404 in non-development environments.
  - `make scenarios` / `simulator/scenarios.py`: 8 automated end-to-end scenarios covering single registration, shared phones, multi-SIM, consent withdrawals, first-to-onboard attribution, CSV duplicates, replay prevention, and partner deactivation.
- **Sample Data & Reference Inputs:**
  - Added `samples/sample_registration_batch.csv` with 20 realistic rows (shared phones, multi-SIM, invalid county, invalid gender, future date).
  - Added `samples/sample_hashes.json` with pre-computed test hashes for curl/API testing.
  - Added `samples/README.md` documenting expected outcomes for every row.
  - Added `--phone` and `--key` CLI options to `sdk/python/hasher.py`.
- **Comprehensive Documentation:**
  - Added `docs/LOCAL_TESTING.md` walkthrough for developers and non-technical stakeholders.

### Changed
- **Bulk CSV Upload Isolation & In-File Deduplication:**
  - `app/routes/farmers.py`: Tracks in-file batch hashes to handle repeats as idempotent resends.
  - Enclosed each row in its own nested savepoint (`db.begin_nested()`) and flushes per row to isolate failures.
  - Updated response payload schema to `{"rows_received": n, "rows_accepted": a, "rows_rejected": r}`.
- **Tamper-Proof First-to-Onboard Attribution:**
  - First-to-onboard credit across all endpoints (`/dashboard`, `/v1/partners/me/summary`, `/admin/lookup`) is strictly ordered by server arrival time (`received_at.asc()`).
  - Validates `onboarded_at`: rejects dates earlier than `PILOT_START_DATE` (`2026-10-01`) or more than 5 minutes in the future.
- **Secret Hardening & Production Validation:**
  - Removed all default secrets from `app/config.py` and `docker-compose.yml`.
  - Added `validate_production_security()` to `Settings`: refuses startup in non-development environments if keys are missing, shorter than 32 characters, or match known committed test keys.
  - Added `.env.example` with placeholders; verified `.env` is ignored in `.gitignore`.
- **Neutral Test Partners:**
  - Removed automatic seeding of real organisation names.
  - Replaced with neutral "Test Partner A", "Test Partner B", "Test Partner C" seeded only when `ENV=development` and `SEED_TEST_PARTNERS=true`.
- **Dashboard Authentication & Accurate Privacy Display:**
  - Added HTTP Basic Authentication to `/dashboard` via `DASHBOARD_USER` and `DASHBOARD_PASSWORD` using constant-time comparison.
  - Updated $k$-anonymity formatting: counts $< 5$ are rendered as `"<5"` with suppressed chart points. Real zeros remain `0`.
  - Renamed metric tile to "Active Partner Registrations".
- **Mathematical Simulation Reconciliation:**
  - Rewrote reconciliation calculation in `simulator/runner.py` to derive expected count from the ground truth file:
    $$\text{Expected} = \text{Distinct Numbers Submitted} - \text{Farmers Whose Every Link Was Withdrawn}$$
  - Prints all 8 intermediate reconciliation steps and exits with non-zero code if difference is not 0.
- **Docker Hardening:**
  - Removed exposed port 5432 and host volume mounts from `docker-compose.yml`.
  - Moved development overrides into `docker-compose.dev.yml`.
  - Updated `Dockerfile` to create and run as non-root user `appuser`.
