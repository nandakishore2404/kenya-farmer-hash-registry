# Kenya Farmer Hash Registry (Prototype)

A zero-knowledge, privacy-preserving farmer registry built for agricultural advisory pilots in Kenya.

The registry de-duplicates and counts each farmer **exactly once** across multiple delivery partners **without ever receiving, transmitting, or storing phone numbers, names, national IDs, or partner farmer lists**.

---

## How a Partner Connects in 3 Steps

Connecting your field application or backend service to the Farmer Hash Registry takes 3 simple steps:

### Step 1: Obtain Your Partner Credentials & Shared Pilot Secret
Your organization will receive:
1. **`PARTNER_KEY`**: A high-entropy cryptographic secret shared exclusively among participating delivery partners for the pilot. *(Note: The central registry server never possesses this key).*
2. **`Partner API Key`**: A private API key assigned to your organization (e.g. `alpha_api_key_pilot_2026`).

---

### Step 2: Normalise & Hash Farmer Phone Numbers Client-Side
Use the lightweight SDK (available for Python and JavaScript) in your own systems. Cleartext phone numbers **never leave your infrastructure**.

#### In Python:
```python
from sdk.python.hasher import hash_phone

# Your secrets
PARTNER_KEY = "partner_shared_pilot_secret"
partner_api_key = "alpha_api_key_pilot_2026"

# Raw phone in any Kenyan format (e.g. "0712-345-678", "+254 712 345 678", "254712345678")
farmer_hash = hash_phone("0712-345-678", PARTNER_KEY)
# -> Returns 64-character hex string: HMAC-SHA256(PARTNER_KEY, "ke-farmer:v1:+254712345678")
```

#### In JavaScript / Node.js:
```javascript
const { hashPhone } = require('./sdk/js/hasher');

const farmerHash = hashPhone("0712-345-678", PARTNER_KEY);
```

---

### Step 3: Send Hashed Registration to the Registry
Send the 64-character hash along with non-identifying demographic attributes (`gender`, `age_band`, `county_code`). Sign the request body using your `Partner API Key`.

```python
import hmac, hashlib, json, requests

payload = {
    "hash": farmer_hash,
    "gender": "F",              # "F", "M", or "U"
    "age_band": "25-34",        # "<18", "18-24", "25-34", "35-44", "45-54", "55-64", "65+", "U"
    "county_code": "047",       # Kenyan county code (e.g. 047 Nairobi, 032 Nakuru)
    "onboarded_at": "2026-10-15T10:00:00Z"
}

body = json.dumps(payload).encode("utf-8")
signature = hmac.new(partner_api_key.encode("utf-8"), body, hashlib.sha256).hexdigest()

headers = {
    "X-Partner-Key": partner_api_key,
    "X-Signature": signature,
    "Content-Type": "application/json"
}

response = requests.post("http://registry:8000/v1/farmers", data=body, headers=headers)
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
|   3. Sign Request with Partner API Key                      |
+-------------------------------------------------------------+
                            |
           POST /v1/farmers | (Only incoming partner hash & demographics)
                            v
+-------------------------------------------------------------+
| Central Registry Service (Holds SERVER_KEY)                 |
|   1. Verify Request Signature (X-Signature)                 |
|   2. Server Re-keying (Double Hashing):                     |
|      hash_key = hex(HMAC-SHA256(SERVER_KEY, incoming_hash)) |
|   3. Query & Store ONLY `hash_key` in PostgreSQL            |
|   4. Zero Cleartext Data Stored                             |
+-------------------------------------------------------------+
```

### Why Keyed Hashes (HMAC-SHA256)?
Kenyan mobile numbers are bounded to approximately **200 million combinations** (`+254 7...` and `+254 1...` followed by 8 digits). A modern computer can precompute plain SHA-256 hashes for all 200 million numbers in under 1 second.
- Using a keyed hash with `PARTNER_KEY` prevents external rainbow table and dictionary inversion attacks.
- Re-keying on the server with `SERVER_KEY` ensures that even a complete database dump reveals neither phone numbers nor partner hashes.

---

## Quickstart & Verification Commands

### 1. Launch Services
```bash
make up
# Or: docker compose up -d --build
```
The FastAPI registry starts on `http://localhost:8000` backed by PostgreSQL 16.

### 2. Run Test Suite
```bash
make test
# Or: python -m pytest tests/ -v
```
Verifies:
- Phone normalisation and HMAC equivalence across Python and JavaScript SDKs.
- All registration branches (new farmer, same-partner duplicate, cross-partner link).
- Idempotency and bulk CSV backfill (`POST /v1/farmers:upload`).
- Consent withdrawal and cascade deletion (`DELETE /v1/farmers/{hash}`).
- Authentication security (bad signatures and unknown keys rejected with 401).
- **Zero-knowledge database leak scanner:** Scans all tables, indexes, and logs to verify no cleartext phone numbers or incoming partner hashes touch persistent storage.

### 3. Run Pilot Simulator
```bash
make demo
# Or: python simulator/runner.py http://localhost:8000
```
- Generates 3,000 synthetic Kenyan farmers across 4 counties.
- Injects 12% 2-partner overlap, 3% 3-partner overlap, 5% shared household phones, 3% second SIM cards, mixed phone formats, CSV backfilling, and 1% consent withdrawals.
- Reconciles ground truth with registry counts and outputs `simulator/report.md`.

---

## Dashboard (`/dashboard`)
Access `http://localhost:8000/dashboard` in your browser:
- Built with clean HTML + Chart.js from CDN.
- Real-time metrics: Total registrations, unique farmers, cross-partner overlap rate.
- Demographics: Gender, age band, and county distributions.
- Attribution: First-to-onboard discovery credit per partner.
- **Privacy Protection:** Strict $k$-anonymity suppression ($k < 5$ counts suppressed).

---

## API Reference Summary

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/farmers` | Register / link farmer | `X-Partner-Key`, `X-Signature` |
| `POST` | `/v1/farmers:upload` | Multipart / raw CSV backfill | `X-Partner-Key`, `X-Signature` |
| `DELETE`| `/v1/farmers/{hash}` | Withdraw partner consent | `X-Partner-Key`, `X-Signature` |
| `GET` | `/v1/partners/me/summary` | Partner's own totals only | `X-Partner-Key`, `X-Signature` |
| `GET` | `/admin/lookup?hash=...` | Admin linkage inspection (audited) | `X-Admin-Key` |
| `GET` | `/dashboard` | HTML visualization dashboard | Public / Browser |
| `GET` | `/health` | Service health status | Public |
