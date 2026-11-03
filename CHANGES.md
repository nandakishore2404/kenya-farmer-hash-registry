# Production Hardening Changes Log (Work Order v2)

**Repository:** `nandakishore2404/kenya-farmer-hash-registry`  
**Base:** `fix/review-2026-10-15` (`b426f50`)  
**Branch:** `feat/production-hardening`  
**Date:** 3 November 2026  

---

## 1. Summary of Changes & Rationale

| File Path | Nature of Change | Architectural & Security Rationale |
|---|---|---|
| `sdk/python/voprf_client.py` | **P0.1 Offline Queue Privacy & Shredding** | Implemented `EphemeralStoreAndForwardQueue` (default, in-memory, never deliberately written to disk) for cloud partner backends. Implemented `EncryptedStoreAndForwardQueue` using AES-256-GCM authenticated encryption with random overwrite shredding and explicit SQLite `VACUUM` for edge devices. Updated module documentation with honest memory guarantees (disabling host swap & core dumps). |
| `app/models.py` | **P1.1, P3.5 Quota & Scheme Models** | Added `PartnerEvaluationQuota` table with composite index `ix_partner_quota_window` (`partner_id`, `evaluated_at`) for persistent rolling-window rate limits. Renamed cryptographic scheme from `voprf_ristretto255` to canonical `voprf_secp256k1`. |
| `app/config.py` | **P1.1, P2.2, P3.1, P3.6 Configuration Validation** | Removed single-key master `EVALUATOR_SECRET_K` and added strict startup refusal if set. Configured 2-of-3 Shamir split keys (`EVALUATOR_PARTY_ID`, `EVALUATOR_PARTY_INDEX`, `EVALUATOR_SHARE_K`, `EVALUATOR_PEER_PUBKEYS`, `EVALUATOR_AGGREGATE_PUB`). Enforced matching derived $K_i$ against published peer public keys. Added `CURVE_BACKEND` (`pure_python` default for dev, refusing startup in prod if native binding missing). Widened clock skew to 900s (`MAX_CLOCK_SKEW_SECONDS`). Added SIM recycling dormancy threshold (`SIM_REASSIGNMENT_DORMANCY_DAYS = 90`). |
| `app/crypto/voprf.py` | **P2.1, P2.3, P3.1 RFC 9380 & Dual Engine** | Implemented RFC 9380 Simplified Shallue-van de Woestijne-Ulas (SSWU) hash-to-curve for `secp256k1_XMD:SHA-256_SSWU_RO_`. Eliminated all try-and-increment loops. Unified implementation into `app.crypto.voprf`. Added 2-of-3 Shamir secret sharing and Lagrange polynomial interpolation (`lagrange_at_zero`, `combine_evaluations`, `combine_public_keys`) rejecting duplicate indices. Added dual-engine dispatch with `coincurve` (libsecp256k1 C bindings) achieving 126x speedup. |
| `prototype_voprf/crypto/voprf_engine.py` | **P2.1 Codebase Deduplication** | Deprecated duplicated and vulnerable prototype implementation; re-exported canonical functions directly from `app.crypto.voprf`. |
| `app/routes/evaluator.py` | **P1.1, P2.2 Split-Key Evaluator Service** | Replaced in-memory dictionary `PARTNER_QUOTAS` with database-backed 24-hour rolling window query (`PartnerEvaluationQuota`). Integrated `EVALUATOR_SHARE_K` and individual DLEQ proofs. Added `/v1/evaluator/public-key` endpoint returning all party public keys and aggregate public key. |
| `app/routes/farmers.py` | **P1.2, P3.5, P4.1 Concurrency & SIM Check** | Hardened `register_farmer_voprf_token` and CSV bulk upload with `begin_nested()` and `IntegrityError` rollback handling. Integrated non-blocking SIM recycling dormancy check (flagging `potential_sim_reassignment_flagged` if farmer re-registered after >90 days dormancy). Renamed token scheme to `voprf_secp256k1`. |
| `app/routes/dev.py` | **P3.5 Scheme Alignment** | Updated dev test console and reset scripts to use `voprf_secp256k1`. |
| `app/auth.py` | **P3.6 Clock Skew Tolerance** | Widened timestamp clock skew validation window to 900 seconds. Provided actionable error guidance instructing clients to sync clocks against `GET /v1/time`. |
| `app/main.py` | **P3.6 Server Time Endpoint** | Added unauthenticated `GET /v1/time` endpoint for edge devices and field agents to synchronize clock drift against server NTP time. |
| `app/audit.py` | **P3.2 Audit Durability** | Preserved paused event state in asynchronous audit worker so unit tests and dead-letter queue operations function deterministically. |
| `scripts/deal_shares.py` | **P2.4 Split-Key Ceremony Tool** | Created air-gapped 2-of-3 Shamir polynomial dealing script generating split keys with restricted 0600 POSIX file permissions and memory zeroization. |
| `scripts/verify_share.py` | **P2.4 Share Verification Tool** | Created verification utility validating party shares against published public keys without revealing private scalars. |
| `scripts/generate_keys.py` | **Deprecation Cleanup** | Removed deprecated `EVALUATOR_SECRET_K` generation; directed operators to `scripts/deal_shares.py`. |
| `.dockerignore` | **P1.3 Container Hygiene** | Excluded Git files, local environments, databases, cache directories, and test artifacts from container builds. |
| `.github/workflows/ci.yml` | **P1.4 Automated CI Pipeline** | Configured GitHub Actions workflow running linting, security scans, and test suite on Python 3.11 with PostgreSQL test services. |
| `tests/test_acceptance_work_order_v2.py` | **Acceptance Verification** | Added comprehensive test suite verifying all 18 Acceptance Tests specified in Work Order v2. |
| `tests/test_voprf_integration.py` | **Integration Hardening** | Updated integration tests to work with 2-of-3 split keys and RFC 9380 hash-to-curve. |
| `tests/test_security_audit_remediation.py` | **Regression Hardening** | Updated config tests to assert startup refusal when `EVALUATOR_SECRET_K` is present and validate share encoding constraints. |
| `tests/test_replay_and_signature_v2.py` | **Skew Tolerance Alignment** | Updated timestamp test to verify rejection past the widened 900s clock skew window. |

---

## 2. Official RFC 9380 Test Vectors (secp256k1_XMD:SHA-256_SSWU_RO_)

Verified against RFC 9380 Appendix J.8.1 with DST `QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_`:

### Vector 1:
- **Input (msg):** `b""`
- **P.x:** `0xC1CAE290E291AEE617EBAEF1BE6D73861479C48B841EABA9B7B5852DDFEB1346`
- **P.y:** `0x64FA678E07AE116126F08B022A94AF6DE15985C996C3A91B64C406A960E51067`
- **Status:** **PASS (Identical across pure-Python and native coincurve)**

### Vector 2:
- **Input (msg):** `b"abc"`
- **P.x:** `0x3377E01EAB42DB296B512293120C6CEE72B6ECF9F9205760BD9FF11FB3CB2C4B`
- **P.y:** `0x7F95890F33EFEBD1044D382A01B1BEE0900FB6116F94688D487C6C7B9C8371F6`
- **Status:** **PASS (Identical across pure-Python and native coincurve)**

### Vector 3:
- **Input (msg):** `b"abcdef0123456789"`
- **P.x:** `0xBAC54083F293F1FE08E4A70137260AA90783A5CB84D3F35848B324D0674B0E3A`
- **P.y:** `0x4436476085D4C3C4508B60FCF4389C40176ADCE756B398BDEE27BCA19758D828`
- **Status:** **PASS (Identical across pure-Python and native coincurve)**

### Vector 4:
- **Input (msg):** `b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"`
- **P.x:** `0xE2167BC785333A37AA562F021F1E881DEFB853839BABF52A7F72B102E41890E9`
- **P.y:** `0xF2401DD95CC35867FFED4F367CD564763719FBC6A53E969FB8496A1E6685D873`
- **Status:** **PASS (Identical across pure-Python and native coincurve)**

---

## 3. Explicit SDK Platform Assumption

- **Target Deployment Platform:** The Python SDK (`sdk/python/voprf_client.py`) is primarily deployed on **Partner Cloud Backend Servers** integrating via REST/Beckn APIs, and secondarily on **Field Worker Laptops / Sync Hubs**. Field enumerators on the ground use mobile collection forms (e.g. ODK Collect / Android) communicating with partner servers.
- **Queueing Architecture:**
  - **Cloud Backends (Default):** Utilizes `EphemeralStoreAndForwardQueue` (in-memory deque). Plaintext phone numbers are **never deliberately written to disk**. To eliminate accidental disk persistence via virtual memory, hosting operating systems must run with swap disabled (`swapoff -a`) and core dumps disabled (`ulimit -c 0`).
  - **Edge / Field Devices (Opt-In):** Utilizes `EncryptedStoreAndForwardQueue` using AES-256-GCM encryption with local hardware-backed keys. Records are shredded using cryptographically pseudo-random byte overwriting and SQLite `VACUUM`.

---

## 4. Measured Throughput Benchmarks

Measured on local CPU environment:

| Operation | Pure-Python Engine | Native Engine (`coincurve` / `libsecp256k1`) | Throughput Speedup |
|---|---|---|---|
| Point Multiplication (`point_mul`) | **6.217 ms** / op | **0.0377 ms** / op | **165x** faster |
| Evaluator per Element (Mul + DLEQ) | **17.13 ms** / element | **0.136 ms** / element | **126x** faster |
| Batch of 500 Elements | **8.56 s** of CPU core | **0.068 s** of CPU core | **126x** faster |
| 50,000 Pilot 1 Capacity | ~14.3 minutes of single core | **~6.8 seconds** of single core | **Real-time capable** |
| 200,000 Pilot 2 Capacity | ~57.1 minutes of single core | **~27.2 seconds** of single core | **Real-time capable** |

---

## 5. P4 Policy Items for SAFIC Decision

The following operational and policy decisions are finalized for SAFIC sign-off:

1. **SIM Card Recycling & Reassignment Policy:**
   - **Technical Baseline:** Safaricom/Airtel Kenya recycle inactive MSISDNs after 90–120 days.
   - **Registry Policy:** Implemented a non-blocking 90-day dormancy threshold (`SIM_REASSIGNMENT_DORMANCY_DAYS = 90`). If a farmer registers with a phone number that was inactive for >90 days and matches an existing token, the registration succeeds normally, but sets `potential_sim_reassignment_flagged = True` in telemetry. This alerts partner human field agents to verify identity without denying services to genuine returning farmers.
2. **Telecom Direct Integration Boundary:**
   - **Architecture Boundary:** The Farmer Hash Registry operates strictly as an identity deduplication and consent registry. It does not initiate outbound HTTP calls to telecom gateways or aggregators. Delivery partners remain responsible for the physical SMS/USSD delivery channels, presenting authenticated cryptographic signatures to the registry PEP endpoint (`/v1/consent/check`).
3. **Evaluator Hardware Standard:**
   - **Key Protection:** All 3 evaluator parties (Safic, Operator, Independent) must store their respective Shamir secret share `EVALUATOR_SHARE_K` inside FIPS 140-2 Level 3 Hardware Security Modules (HSMs) or AWS CloudHSM / GCP Cloud KMS with non-exportable private keys.
4. **Repository Governance:**
   - **Protection Rules:** Enforce signed commits, require 2 approving reviews on PRs, and configure branch protection on `main` and release branches preventing direct pushes or history rewrites.
