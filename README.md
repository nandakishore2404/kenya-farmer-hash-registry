# Kenya Farmer Hash Registry

A zero-knowledge, privacy-preserving farmer registry built for agricultural advisory pilots in Kenya.

The registry de-duplicates and counts each farmer **exactly once** across multiple delivery partners **without ever receiving, transmitting, or storing phone numbers, names, national IDs, or partner farmer lists**.

---

## Key Highlights & Security Hardening (Review of 15 October 2026)

- **Strict Zero-Knowledge:** Central registry holds only double-keyed codes ($H(\text{SERVER\_KEY}, H(\text{PARTNER\_KEY}, \text{phone}))$). Zero PII or single-hashed phone numbers ever hit storage or logs.
- **Bulk CSV Isolation & In-File Deduplication:** In-file repeats within the same CSV upload are handled idempotently without duplicate link errors. Every row runs in its own nested savepoint; rejected rows never rollback accepted rows. Accurate counts are returned: `{"rows_received": n, "rows_accepted": a, "rows_rejected": r}`.
- **Tamper-Proof First-to-Onboard Credit:** Discovery attribution is anchored exclusively to the registry's server UTC arrival timestamp (`received_at`). Partner-supplied `onboarded_at` is preserved for historical reporting only and strictly validated against future dates and pilot start boundaries.
- **Replay Protection (Signature v2):** Every request is signed with HMAC-SHA256 over method, path, query, timestamp, nonce, and payload hash. Replayed nonces and timestamps older than 300 seconds are rejected with HTTP 401.
- **Zero Hardcoded Secrets & Production Safety:** All default secrets removed. Refuses startup outside `ENV=development` if keys are missing, shorter than 32 characters, or match insecure test strings.
- **Role-Based Partner Management CLI:** Automated creation of hardcoded partner credentials removed. Use `python -m app.cli` to provision, list, or disable delivery partner accounts.
- **Secured Analytics Dashboard:** Protected with HTTP Basic Authentication (`DASHBOARD_USER` / `DASHBOARD_PASSWORD`) using constant-time digest comparison. Strict $k$-anonymity displays counts $< 5$ as `"<5"` with suppressed chart points. Real zeros remain `0`.
- **Local Developer Experience (Zero-Docker Option):** Run `make local` to launch on SQLite (`http://localhost:8008`) with an interactive Test Console at `/dev/console` and an 8-part scenario runner via `make scenarios`.

---

## How a Partner Connects in 3 Steps

### Step 1: Obtain Partner Credentials & Shared Pilot Secret
Your organization will receive:
1. **`PARTNER_KEY`**: A high-entropy cryptographic secret shared exclusively among participating delivery partners for the pilot. *(Note: The central registry server never possesses this key).*
2. **`Partner API Key`**: A private API key assigned to your organization (e.g. `test_partner_a_api_key_2026`).

---

### Step 2: Normalise & Hash Farmer Phone Numbers Client-Side
Use the lightweight SDK (available for Python and JavaScript). Cleartext phone numbers **never leave your infrastructure**.

#### In Python:
```python
from sdk.python.hasher import hash_phone

PARTNER_KEY = "partner_shared_pilot_secret"
farmer_hash = hash_phone("0712-345-678", PARTNER_KEY)
# -> Returns 64-character hex string: HMAC-SHA256(PARTNER_KEY, "ke-farmer:v1:+254712345678")
```

#### In JavaScript / Node.js:
```javascript
const { hashPhone } = require('./sdk/js/hasher');

const farmerHash = hashPhone("0712-345-678", PARTNER_KEY);
```

---

### Step 3: Sign & Send Hashed Registration to Registry
Send the 64-character hash along with non-identifying demographic attributes (`gender`, `age_band`, `county_code`). Sign the request using Signature v2:

```python
import json, requests
from sdk.python.hasher import hash_phone, sign_request

PARTNER_KEY = "partner_shared_pilot_secret"
API_KEY = "test_partner_a_api_key_2026"

payload = {
    "hash": hash_phone("0712-345-678", PARTNER_KEY),
    "gender": "F",              # "F", "M", or "U"
    "age_band": "25-34",        # "<18", "18-24", "25-34", "35-44", "45-54", "55-64", "65+", "U"
    "county_code": "047",       # Kenyan county code (047 Nairobi, 032 Nakuru, 019 Nyeri, 042 Kisumu)
    "onboarded_at": "2026-10-15T10:00:00Z"
}

body_bytes = json.dumps(payload).encode("utf-8")
headers = sign_request(API_KEY, "POST", "/v1/farmers", "", body_bytes)
headers["Content-Type"] = "application/json"

response = requests.post("http://localhost:8008/v1/farmers", data=body_bytes, headers=headers)
print(response.json())
# -> ALWAYS returns: {"status": "accepted"} with HTTP 200
```

> **Zero-Knowledge Guarantee:** The endpoint **always** returns HTTP 200 `{"status": "accepted"}` regardless of whether the farmer was already registered by another partner. Partners cannot probe the API to discover other partners' farmers.

---

## Architectural & Privacy Design

```
+-------------------------------------------------------------+
| Delivery Partners (Hold PARTNER_KEY)                        |
|   1. Normalise Kenyan Phone: ^\+254(7|1)\d{8}$              |
|   2. Compute Partner Hash:                                  |
|      hex(HMAC-SHA256(PARTNER_KEY, "ke-farmer:v1:" + phone)) |
|   3. Sign Request (Signature v2 with Nonce & Timestamp)     |
+-------------------------------------------------------------+
                            |
           POST /v1/farmers | (Only incoming partner hash & demographics)
                            v
+-------------------------------------------------------------+
| Central Registry Service (Holds SERVER_KEY)                 |
|   1. Verify Signature v2 & Nonce Replay Check (10-min cache)|
|   2. Record Registry Arrival Time (received_at = UTC NOW)   |
|   3. Server Re-keying (Double Hashing):                     |
|      farmer_code = hex(HMAC-SHA256(SERVER_KEY, partner_hash))
|   4. Query & Store ONLY `farmer_code` in DB                 |
|   5. Zero Cleartext Data Stored                             |
+-------------------------------------------------------------+
```

---

## Local Development & Testing Commands

### 1. One-Command Local Run (No Docker Required)
```bash
make local
```
Starts the app on `http://localhost:8008` with SQLite (`local.db`), creates `.env` with random development keys if missing, seeds Test Partners A, B, and C, and prints the startup access block.

To reset the local database:
```bash
make local-reset
```

### 2. Interactive Test Console (Web UI)
Open **`http://localhost:8008/dev/console`** in your browser (`ENV=development` only).
- Register, resend, and cross-register farmers in real time.
- Test back-dated attribution and verify `received_at` keeps first-to-onboard credit.
- Test consent withdrawals and cascade deletion.
- Upload 20-row sample batch CSV.
- Trigger simulated replay attacks with live HTTP 401 verification.
- Inspect live unsuppressed database counts in the side panel.

### 3. Scenario Test Runner
```bash
make scenarios
```
Runs 8 end-to-end automated scenarios and outputs a pass/fail table:
1. `single-registration`
2. `shared-phone`
3. `second-sim`
4. `consent-withdrawal`
5. `first-to-onboard`
6. `csv-duplicates`
7. `replay-attack`
8. `disabled-partner`

### 4. Run Pytest Suite
```bash
make test
```
Executes all unit, integration, SDK, and security tests.

### 5. Run 3,000-Farmer Simulator
```bash
make demo
```
Runs full pilot simulation with 3,000 synthetic Kenyan farmers, realistic anomalies (shared phones, multi-SIM, withdrawals), and generates `simulator/report.md` with 100% exact mathematical reconciliation (0 discrepancy).

---

## Administration CLI

Provision and manage delivery partner credentials from the command line:

```bash
# Add a new delivery partner (prints API key once)
python -m app.cli add-partner --id partner_xyz --name "Agricultural Partner XYZ"

# List all registered partners and status
python -m app.cli list-partners

# Disable an existing partner account (subsequent requests get 401)
python -m app.cli disable-partner --id partner_xyz
```

---

## Docker Deployment

### Production Compose (Hardened)
```bash
make up
# Or: docker compose up -d --build
```
Runs the application as non-root user `appuser`. The database port 5432 is internal-only and source volumes are omitted.

### Local Development Compose Override
```bash
make up-dev
# Or: docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```
Publishes PostgreSQL on port 5432 and mounts the local workspace for live code reloading.

---

## API Reference Summary

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/farmers` | Register / link farmer | `X-Partner-Key`, `X-Timestamp`, `X-Nonce`, `X-Signature` |
| `POST` | `/v1/farmers:upload` | Multipart / raw CSV backfill | `X-Partner-Key`, `X-Timestamp`, `X-Nonce`, `X-Signature` |
| `DELETE`| `/v1/farmers/{hash}` | Withdraw partner consent | `X-Partner-Key`, `X-Timestamp`, `X-Nonce`, `X-Signature` |
| `GET` | `/v1/partners/me/summary` | Partner's own totals & credit | `X-Partner-Key`, `X-Timestamp`, `X-Nonce`, `X-Signature` |
| `GET` | `/admin/lookup?hash=...` | Admin linkage inspection (audited) | `X-Admin-Key` |
| `GET` | `/dashboard` | HTML visualization dashboard | HTTP Basic (`DASHBOARD_USER`, `DASHBOARD_PASSWORD`) |
| `GET` | `/dev/console` | Interactive Test Console | Development mode only (`ENV=development`) |
| `GET` | `/health` | Service health status | Public |
