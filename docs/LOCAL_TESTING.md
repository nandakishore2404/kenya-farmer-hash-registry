# Kenya Farmer Hash Registry: Local Testing & Developer Experience Guide

This step-by-step guide is designed for developers, PMs, and non-technical team members to spin up, interact with, and verify all deduplication and privacy behaviors of the Kenya Farmer Hash Registry on a local laptop—without needing Docker.

---

## 1. Quick Start (One Command)

To initialize your local SQLite environment, generate keys, and start the service:

```bash
make local
```

*Or directly with Python:*
```bash
python scripts/generate_keys.py --write-env
python -m uvicorn app.main:app --host 127.0.0.1 --port 8008 --reload
```

At startup, the service outputs a clean configuration banner:
```
========================================================================
 KENYA FARMER HASH REGISTRY - LOCAL DEVELOPMENT ENVIRONMENT
========================================================================
 Registry URL:    http://localhost:8008
 Dashboard URL:   http://localhost:8008/dashboard
 Test Console:    http://localhost:8008/dev/console
 Health Check:    http://localhost:8008/health
------------------------------------------------------------------------
 Dashboard Login: admin / dev_dashboard_password
------------------------------------------------------------------------
 Seeded Test Partners:
   1. ID: test_partner_a (Test Partner A)
      API Key: test_partner_a_api_key_2026
   2. ID: test_partner_b (Test Partner B)
      API Key: test_partner_b_api_key_2026
   3. ID: test_partner_c (Test Partner C - CSV)
      API Key: test_partner_c_api_key_2026
------------------------------------------------------------------------
 Shared Pilot Key: partner_shared_pilot_secret
========================================================================
```

---

## 2. Interactive Test Console (Web UI)

Open your browser to:
👉 **[http://localhost:8008/dev/console](http://localhost:8008/dev/console)** *(Only accessible when `ENV=development`)*

The Test Console enables full manual verification with live, unsuppressed database metrics in the side panel:

### Core Behaviours to Test:

1. **Hash and Register a Single Farmer:**
   - Leave phone as `0712 345 678` with `test_partner_a`.
   - Click **`1. Register Farmer`**.
   - Notice the client-side HMAC hash, the generated `X-Signature` (v2), and the HTTP `200 accepted` response.
   - Look at the right panel: **Unique Farmers: 1, Active Links: 1**.

2. **Test Idempotency (Resend Same Farmer):**
   - Click **`2. Resend Same Partner`**.
   - The response returns `200 accepted`.
   - Look at the metrics: **Unique Farmers remains 1, Active Links remains 1**. No duplicate record is created.

3. **Test Cross-Partner Overlap:**
   - Click **`3. Register Overlap Partner`** (sends the identical phone using Test Partner B).
   - Response returns `200 accepted`.
   - Look at the metrics: **Active Links increases to 2**, but **Unique Farmers remains 1**. De-duplication has occurred across partners with zero knowledge of the phone number.

4. **Verify First-to-Onboard Attribution:**
   - Click **`4. Back-date Test`** (Partner B attempts to claim first-to-onboard credit by sending an older date `2026-10-02`).
   - Check partner summaries: Test Partner A retains first-to-onboard credit because credit is strictly determined by server UTC arrival time (`received_at`).

5. **Test Consent Withdrawal:**
   - Click **`5. Withdraw Consent`**.
   - Test Partner A's link is removed. The farmer remains in the registry because Test Partner B still holds an active link.
   - Switch dropdown to Test Partner B and click **`5. Withdraw Consent`**. Because the last active partner link was deleted, the farmer record is permanently purged from the registry.

6. **Test CSV Bulk Backfill:**
   - Click **`Load & Upload Sample`** to upload the 20-row sample batch.
   - The response shows `{"rows_received": 20, "rows_accepted": 17, "rows_rejected": 3}`.
   - Invalid rows (e.g. invalid county, invalid gender, future date) are rejected without aborting valid rows.

7. **Test Replay Protection (Signature v2):**
   - Click **`7. Replay Attack Test`**.
   - The previous request is replayed with the identical `X-Nonce` and `X-Timestamp`.
   - The registry rejects it with HTTP `401 Unauthorized: Replay attack detected: nonce already used`.

---

## 3. Scenario Test Runner (Command Line)

To run the automated scenario test suite:

```bash
make scenarios
```

*Or run individual scenarios:*
```bash
make scenario NAME=first-to-onboard
make scenario NAME=replay-attack
```

### Scenarios Included:
1. `single-registration`: Validates single registration, hashing, and attribution.
2. `shared-phone`: Validates that 2 household members sharing 1 handset produce 1 farmer record and 2 partner links.
3. `second-sim`: Validates that a farmer with 2 SIM cards generates 2 distinct codes.
4. `consent-withdrawal`: Validates cascade purge only when the final active link is removed.
5. `first-to-onboard`: Validates that credit is anchored to server arrival time (`received_at`), not partner-supplied `onboarded_at`.
6. `csv-duplicates`: Validates in-file deduplication and per-row savepoint isolation.
7. `replay-attack`: Validates nonce replay prevention and timestamp tolerance window (300s).
8. `disabled-partner`: Validates immediate 401 rejection for deactivated delivery partners.
9. `legacy-signature`: Validates that legacy body-only signatures (omitting `X-Timestamp` and `X-Nonce`) are strictly rejected with HTTP 401.

---

## 4. Full 3,000-Farmer Pilot Simulation

Run the end-to-end synthetic simulator:

```bash
make demo
```

The simulator creates 3,000 synthetic individuals with realistic anomalies (5% shared household phones, 3% multi-SIM users, 1% KDPA withdrawals), posts them via direct API calls and CSV backfill, and performs a 100% exact mathematical reconciliation:

$$\text{Expected} = \text{Distinct Numbers Submitted} - \text{Fully Withdrawn Farmers} = 2,911$$
$$\text{Observed} = 2,911 \implies \text{Difference} = 0$$

The report is written to `simulator/report.md`.

---

## 5. Troubleshooting & Maintenance

- **Resetting the Local Database:**
  Run `make local-reset` to wipe `local.db` and re-seed the test partners.
- **Port 8008 Already in Use:**
  In Windows PowerShell, find and kill the process:
  ```powershell
  Get-NetTCPConnection -LocalPort 8008 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
  ```
- **Checking Pytest Suite:**
  ```bash
  make test
  ```
