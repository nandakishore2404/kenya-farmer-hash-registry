# Changelog

All notable changes to the **Kenya Farmer Hash Registry** project will be documented in this file.

---

## [1.4.0] - 2026-10-28 (Audit Round 3: Key Custody, Authorization & Test Isolation Remediation)

### Security - Critical Remediations
- **Purged Hardcoded Secret Scalars from Repository (Critical 1):**
  - **Issue:** The Evaluator secret scalar $k$ was previously hardcoded as a source literal in `app/routes/evaluator.py` and `prototype_voprf/evaluator/service.py`. Because this repository is public, anyone reading GitHub could extract $k$ and compute $N = k \cdot H(x)$ and $T = \text{Finalize}(x, N)$ entirely offline without querying the Evaluator.
  - **Remediation:** Completely purged hardcoded literals from the codebase. Evaluator secret key scalar $k$ is now loaded strictly at runtime from `EVALUATOR_SECRET_K` (environment variable or AWS CloudHSM / HashiCorp Vault transit engine in production).
  - **Fail-Loud Gate:** Both production and development environments refuse startup if `EVALUATOR_SECRET_K` is missing, empty, matches `CHANGE_ME`, or matches known burned scalars (`0x7a2f...`, `0x5d8a...`). Added automated regression tests verifying failure on missing/burned keys and absence of literals in source code.
  - **Key Epoch Rotation:** Rotated to fresh Evaluator epoch `ke-pilot-v3` generated outside version control. Previous keys $k_{v1}$ and $k_{v2}$ in git history are permanently marked burned and unusable.

- **Enforced Active Quarantine Filtering (High 2):**
  - Updated all entity/token resolution queries in `app/routes/farmers.py`, `app/routes/dev.py`, and `prototype_voprf/registry/service.py` to enforce `TokenAlias.status == 'active'`.
  - Compromised legacy aliases marked `compromised_v1_legacy` are ignored and will never resolve as authoritative.

- **Enforced Key Epoch Validation at Registration (High 3):**
  - In `app/routes/farmers.py :: register_farmer_voprf_token` and `prototype_voprf/registry/service.py`, requests with `key_id != EVALUATOR_KEY_ID` (`ke-pilot-v3`) are strictly rejected with HTTP 400.
  - Prevents minting or binding compromised $v1$ or $v2$ tokens to existing entities.

- **Namespaced Legacy-HMAC Scheme (High 4):**
  - Assigned legacy-HMAC its own dedicated key namespace: `key_id = "legacy-hmac-v1"`.
  - Scoped Alembic migration `0004_deprecate_compromised_v1_epoch.py` strictly to VOPRF schemes (`voprf_ristretto255`, `voprf_secp256k1`), preventing conflation between legacy HMAC hashes and compromised VOPRF epochs.

- **Partner Authorization on PEP Consent Check (Medium 6):**
  - Hardened `check_consent_policy_enforcement_point` in `app/routes/consent.py` and `prototype_voprf/registry/service.py`: verified that calling partners have an active `PartnerAssociation` with the queried farmer entity.
  - Unassociated partners querying consent state receive HTTP 403 Forbidden. Added regression test `test_medium_6_pep_authorization_blocks_cross_partner_consent_read`.

- **Telemetry Reconciliation During Migration (Medium 9):**
  - Updated Alembic migration `0004` to quarantine `partner_association` records tied to quarantined entities.
  - Updated dashboard and dev telemetry queries (`/v1/telemetry/dpi-metrics`) to join active `FarmerEntity` records, ensuring overlap counts and rates reconcile cleanly without inflating metrics.

### Quality & Testing
- **Per-Test Database Isolation (Medium 7):**
  - Refactored `tests/conftest.py` from `scope="session"` to `scope="function"`, dropping and re-seeding the test database per test.
  - Removed duplicate SQLite engines in `tests/test_voprf_integration.py`.
  - Resolved all suite-level SQLite lock contention and state leakage: entire suite runs with **81 passed, 0 failed, 0 errored**.
- **Pre-Existing Test Fixes (Medium 8):**
  - Updated `tests/test_api_branches.py` to make each test function self-contained.
  - Fixed dev console title verification in `tests/test_dev_endpoints.py` and aligned unsuppressed metrics to count both consent and partner link removals.

### Documentation & Specification Accuracy (Medium 5)
- Clarified that `point_mul` is a fixed-iteration Montgomery ladder (fixed 256 iterations) that removes scalar-dependent loop variance, but full constant-time execution against cache/microarchitectural side channels requires $k$ residing in hardware (CloudHSM / Vault).
- Clarified that `hash_to_group` implements secp256k1 try-and-increment (with unknown discrete logarithm relative to $G$ and variable iteration count, observed 0-8, mean ~1.0); noted that RFC 9380 formally specifies Simplified SWU.

---

## [1.3.0] - 2026-10-27 (Critical Security Remediation & Cryptographic Hardening)

### Security - Critical Fixes
- **Remediated Fatal Discrete-Log Defect in `hash_to_group` (secp256k1 Try-and-Increment Hash-to-Curve):**
  - **Vulnerability:** The previous `hash_to_group(x)` implementation computed a scalar $s(x) = \text{SHA-512}(\dots) \pmod{N-1} + 1$ and multiplied generator $G$ by it: $H(x) = s(x) \cdot G$. Because the discrete logarithm $s(x)$ relative to $G$ was computable by anyone from $x$ alone, an attacker possessing the Evaluator public key $K = k \cdot G$ (served publicly via `GET /v1/evaluator/public-key`) could bypass the HSM entirely:
    $$N = r^{-1} \cdot Z = r^{-1} \cdot k \cdot (r \cdot H(x)) = k \cdot s(x) \cdot G = s(x) \cdot K$$
    This allowed computing $\text{Finalize}(x, s(x) \cdot K)$ entirely offline with no HSM call, no rate limits, and no network interaction, enabling offline rainbow table precomputation across the entire ~200M Kenyan mobile phone space.
  - **Fix:** Implemented a try-and-increment hash-to-curve for secp256k1 with unknown discrete logarithm relative to $G$. Hashes candidate x-coordinates with domain separation `b"oan-secp256k1-try-and-increment-v1"`, tests curve equation $y^2 \equiv x^3 + 7 \pmod p$ via Euler's criterion, computes square root using $y = v^{(p+1)/4} \pmod p$ ($p \equiv 3 \pmod 4$), and selects canonical sign via candidate hash parity. (Note: RFC 9380 formally specifies Simplified SWU for secp256k1; try-and-increment achieves the required unknown-DL property with variable iteration count, mean ~1.0).
  - **Domain Separation & Input Encoding:** Maintained length-prefixed domain separation: $x = \text{LP}(\text{"oan-phone-dedup-v1"}) \mathbin{\Vert} \text{LP}(\text{pilot\_id}) \mathbin{\Vert} \text{LP}(\text{normalized\_phone})$. Confirmed Partner ID remains strictly excluded from $x$ to preserve cross-provider deduplication integrity.
  - **Strict Curve Membership & Subgroup Validation:** Added `is_valid_curve_point()` to validate $0 \le x, y < p$, $y \neq 0$, and $(y^2 - (x^3 + 7)) \equiv 0 \pmod p$. Enforced validation in `GroupElement.from_bytes()` and at HTTP ingress in `app/routes/evaluator.py`, rejecting point-at-infinity and off-curve blinded elements with HTTP 400.

- **Task 2 Regression Prevention:**
  - Added regression test `test_hash_to_group_has_no_known_dlog` across integration and prototype test suites (`tests/test_voprf_integration.py` and `prototype_voprf/tests/test_prototype.py`).
  - Verifies that attempting the shortcut $s(x) \cdot K$ fails to reproduce the honest unblinded point $N$ and finalized token $T$.

### Migration Decision (Task 3 - Decision Requiring Sign-off)
- **Implemented Migration Path (a): Fresh Key Epoch Rotation & Pilot Data Quarantine:**
  - **Key Epoch Transition:** Deprecated key epoch `v1` / `ke-pilot-v1`. Created fresh Evaluator key scalar under key epoch `ke-pilot-v2` (subsequently rotated to `ke-pilot-v3` in release 1.4.0).
  - **Tainted Data Quarantine:** Because all tokens derived under `v1` used the flawed scalar-multiplication mapping and are vulnerable to offline dictionary matching, existing records cannot be safely retained.
  - **Alembic Migration `0004_deprecate_compromised_v1_epoch.py`:**
    - Added `status` column to `token_alias` table (default: `'active'`).
    - Flagged all existing `token_alias` rows with `key_id IN ('v1', 'ke-pilot-v1')` as `'compromised_v1_legacy'`.
    - Quarantined associated `farmer_entity` records tied exclusively to legacy aliases as `'quarantined_v1_epoch'`.
  - **Ingress Rejection:** Registration and evaluation endpoints reject deprecated key identifiers (`v1`, `ke-pilot-v1`) with HTTP 400.
  - **Pilot Farmer Re-registration:** Pilot partners must re-register farmers using the updated client SDK under the active key epoch.

### Hardening
- **Fixed-Iteration Montgomery Ladder (Task 4):**
  - Replaced branching double-and-add algorithm in `point_mul(k, p)` with a fixed-iteration Montgomery ladder executing exactly 256 iterations.
  - Eliminates scalar-dependent loop termination. Strict physical timing resistance relies on secret key $k$ residing in hardware (CloudHSM / Vault).
- **PEP Authentication on Consent Check (Task 5):**
  - Added `partner: Partner = Depends(authenticate_partner)` to `GET /v1/consent/check` in `app/routes/consent.py` and `prototype_voprf/registry/service.py`.
  - Unauthenticated requests are rejected with HTTP 401. Added regression test `test_consent_check_unauthenticated_rejected`.

---

## [1.2.0] - 2026-10-15 (Audit Round 2 Hardening)
