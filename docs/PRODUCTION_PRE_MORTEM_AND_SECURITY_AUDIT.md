# Production Pre-Mortem & Comprehensive Security Audit
**National Farmer Hash Registry — Republic of Kenya**
*Architectural Feasibility & Failure Analysis for 50,000 (Pilot 1) and 200,000 (Pilot 2) Scale (250,000 Cumulative)*

- **Document Version:** 1.1.0 (Production Review & Scale Audit)
- **Base Branch:** `fix/review-2026-10-15` (`b426f50`)
- **Target Architecture:** 2-of-3 Split-Key Evaluator (RFC 9497 VOPRF + RFC 9380 Hash-to-Curve)
- **Target Population:** Pilot 1: 50,000 Farmers | Pilot 2: 200,000 Farmers | Total: 250,000 Farmers
- **Date:** 3 November 2026
- **Audience:** Cloud Architecture Review Board, Technical Steering Committee, SAFIC Engineering, Data Protection Officer

---

## Executive Summary & Direct Finding

> [!CAUTION]
> **Production Readiness Verdict: NOT READY FOR DIRECT PRODUCTION DEPLOYMENT**  
> While the mathematical foundation (RFC 9380 SSWU and 2-of-3 Shamir secret sharing) is sound, the **operational code cannot be deployed as-is from this repository**. 
> At 250,000 farmers, the system will encounter fatal database race conditions, hard-coded lifetime quota lockouts, massive audit log write amplification, and mobile data leakage. Deploying without the remediations below will lead to widespread registration failures during peak agricultural onboarding windows.

---

## 1. Operational Failure: What Breaks at 250,000 Scale

Testing at 3,000 records ran sequentially on SQLite. Scaling to **50,000 in Pilot 1** and **200,000 in Pilot 2** (250,000 total) creates operational bottlenecks that do not manifest in small pilots:

### 1.1 The In-Memory Lifetime Quota Hard-Lock
- **Code Reference:** [`app/routes/evaluator.py`](file:///c:/Users/nanda/OneDrive/Desktop/DELOITTE/Agri%20Africa/OAN%20KENYA/app/routes/evaluator.py#L81-L136)
- **The Defect:**
  ```python
  PARTNER_QUOTAS = {}
  ...
  current_count = PARTNER_QUOTAS.get(partner.partner_id, 0)
  if current_count + len(req.blinded_elements) > 10000:
      raise HTTPException(
          status_code=status.HTTP_429_TOO_MANY_REQUESTS,
          detail="Partner evaluation quota exceeded. Anomaly tripwire engaged."
      )
  PARTNER_QUOTAS[partner.partner_id] = current_count + len(req.blinded_elements)
  ```
- **Why It Fails at Scale:** `PARTNER_QUOTAS` is an unexpiring in-memory Python dictionary without timestamps. Once any partner evaluates 10,000 farmers in aggregate, they are permanently blocked with `HTTP 429`. In a 250,000-farmer deployment, major partners (e.g. DigiFarm, One Acre Fund) will exceed 10,000 within days and grind to a halt. Conversely, restarting the server resets the count to 0, completely defeating anomaly detection.
- **Remediation:** Replace with a PostgreSQL/Redis rolling 24-hour rate limiter using an atomic sliding-window schema.

### 1.2 Unhandled Unique Constraint Race Condition Under Concurrency
- **Code Reference:** [`app/routes/farmers.py`](file:///c:/Users/nanda/OneDrive/Desktop/DELOITTE/Agri%20Africa/OAN%20KENYA/app/routes/farmers.py#L248-L270)
- **The Defect:**
  ```python
  alias = db.query(TokenAlias).filter(...).first()
  if not alias:
      entity = FarmerEntity(...)
      db.add(entity)
      db.flush()
      alias = TokenAlias(entity_id=entity.entity_id, ..., digest_d=digest_d)
      db.add(alias)
      db.commit()
  ```
- **Why It Fails at Scale:** During concentrated cooperative onboarding drives, multiple field agents register overlapping farmers simultaneously. Two requests for the same farmer query `TokenAlias` at the exact same millisecond. Both see no alias and attempt to insert the same `digest_d`. The database raises `IntegrityError: duplicate key value violates unique constraint 'uq_pilot_key_digest'`. Because there is **no exception handler for `IntegrityError`**, the request crashes with an unhandled `HTTP 500`, leaving transactions uncommitted and registrations dropped.
- **Remediation:** Implement an explicit `try...except IntegrityError` with database savepoints (`begin_nested()`). On collision, rollback the inner savepoint, fetch the winner record, and link the partner as a contributor.

### 1.3 Audit Log Explosion (12+ Million Rows at 250k Scale)
- **Code Reference:** [`app/audit.py`](file:///c:/Users/nanda/OneDrive/Desktop/DELOITTE/Agri%20Africa/OAN%20KENYA/app/audit.py#L57-L77)
- **The Defect:** Every Policy Enforcement Point (PEP) consent check (`/v1/consent/check`) enqueues an `AuditLog` row via a process-local queue.
- **Why It Fails at Scale:** At 250,000 active farmers receiving weekly agronomic advisories or weather alerts, the system executes ~1,000,000 consent checks per month. That equals **12,000,000 audit log rows per year**. In an unpartitioned PostgreSQL table, index bloat on `audit_log` degrades write performance and causes database lock contention. Furthermore, in multi-worker containers, in-memory queues lose un-flushed audit entries on container reboots.
- **Remediation:** Implement range partitioning on `audit_log` by `created_at` (monthly partitions) and write audit events directly to an append-only WAL stream.

### 1.4 Cryptographic Throughput Bottleneck (Pure Python Montgomery Ladder)
- **Code Reference:** [`app/crypto/voprf.py`](file:///c:/Users/nanda/OneDrive/Desktop/DELOITTE/Agri%20Africa/OAN%20KENYA/app/crypto/voprf.py#L62-L87)
- **Why It Fails at Scale:** `point_mul` executes a 256-step Montgomery ladder in pure Python. A single point multiplication takes ~2–4 ms on modern x86/ARM server vCPUs. For a batch of 500 blinded elements, a single evaluation request consumes 1.0–2.0 seconds of dedicated 100% CPU time. Under peak loads of 100 requests/sec across Kenya, pure Python saturates all CPU cores, causing request timeouts.
- **Remediation:** In production, bind to optimized C primitives (e.g. `libsecp256k1` via CFFI/ctypes) while keeping pure Python as a clean test fallback.

---

## 2. Attack on the 2-of-3 Split-Key Evaluator Design

```
                       [ Field Client SDK ]
                                |
                    Blinds Phone -> Point B
                                |
        +-----------------------+-----------------------+
        | (Parallel HTTP)       | (Parallel HTTP)       | (Parallel HTTP)
        v                       v                       v
  [ Evaluator 1 ]         [ Evaluator 2 ]         [ Evaluator 3 ]
    Custody: SAFIC          Custody: Operator       Custody: Auditor
    Share: s1               Share: s2               Share: s3
        |                       |                       |
        v                       v                       v
   (Z1, Proof1)            (Z2, Proof2)            (Z3, Proof3)
        \                       /                       |
         +----------+----------+                        | (Ignored if 2 verified)
                    |
                    v
    Client verifies DLEQ proofs, combines via Lagrange:
          Z = λ1 * Z1 + λ2 * Z2  (= k * B)
                    |
          Unblind -> Token T -> Storage Digest D
```

### 2.1 The Mid-Flight Epoch Split-Brain Attack
- **Attack Scenario:** When rotating from `ke-pilot-v3` to `ke-pilot-v4`, the three independent institutions update at different times. If Node 1 upgrades to `v4` at 10:00:00 while Nodes 2 and 3 upgrade at 10:00:15, a client making parallel calls receives:
  - Node 1: $Z_1^{(v4)}$
  - Node 2: $Z_2^{(v3)}$
- **Consequence:** If the client interpolates these two points:
  $$Z = \lambda_1 Z_1^{(v4)} + \lambda_2 Z_2^{(v3)} \neq k B$$
  The mathematical recombination silently produces a corrupted point. The resulting token $T$ and digest $D$ are garbage, permanently isolating that farmer from future deduplication.
- **Defense:** The client SDK must group responses strictly by `key_id` and abort if fewer than two verified responses match the exact same epoch.

### 2.2 Response Index Spoofing & ZeroDivision Crash
- **Attack Scenario:** If an attacker or misconfigured node returns `party_index: 2` alongside Node 2:
  $$\lambda_i = \prod_{j \neq i} \frac{j}{j - i} \pmod{N}$$
  The denominator evaluates to $(2 - 2) \equiv 0$, causing a `ZeroDivisionError` that crashes the field client.
- **Defense:** Hardcode the party-to-index mapping (`{"safic": 1, "operator": 2, "independent": 3}`) in client configuration and ignore the remote `party_index` parameter.

---

## 3. Human & Organisational Failure (Three Custodians)

| Scenario | Impact | Failure Mechanism | Prevention |
| :--- | :--- | :--- | :--- |
| **Silent Attrition** | Critical | One party's server crashes or certificate expires. The system silently drops to 2-of-2 with zero redundancy. A subsequent routine reboot of another party halts the entire national registry. | Deploy a public, automated 24/7 `/healthz` heartbeat probe that alerts all three parties immediately when availability drops below 3/3. |
| **Hostage Share on Rotation** | High | An uncooperative or unresponsive third party refuses to attend the key ceremony, blocking key rotation. | Establish legally binding Service Level Agreements (SLAs) and explicit operational protocols for decommissioning non-responsive custodians. |
| **Cloud Snapshot Share Leak** | Critical | An IT administrator at one institution creates unencrypted virtual machine backups to an S3 bucket or blob storage, leaking their share. | Enforce share injection only via runtime secret managers (AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault) with memory-only residence. |

---

## 4. Architectural Blind Spots (Omissions in Current Plan)

1. **Dual-Epoch Read Path Missing:**
   - At 250,000 farmers, you cannot re-derive tokens in the background because the registry does not store cleartext phone numbers.
   - **Remediation:** Implement a dual-epoch lookup: search by `digest_v4`; if absent, fall back to `digest_v3`. Re-derive $v4$ dynamically on the farmer's next interaction.
2. **Fake Cryptographic Shredding on Field Tablets:**
   - In [`sdk/python/voprf_client.py`](file:///c:/Users/nanda/OneDrive/Desktop/DELOITTE/Agri%20Africa/OAN%20KENYA/sdk/python/voprf_client.py#L91-L100), `shred_record()` performs an SQLite `UPDATE` followed by `DELETE`.
   - In SQLite, deleted records remain on the database freelist in plaintext until `VACUUM` is run. The claim of "local encrypted queue" is misleading; the SQLite file is completely unencrypted.
   - **Remediation:** Use SQLCipher for local storage or blind the phone number in RAM immediately upon entry so cleartext is never written to disk.
3. **Kenyan SIM Card Churn / Recycling:**
   - Mobile network operators in Kenya (Safaricom, Airtel) recycle mobile numbers after 90–120 days of inactivity.
   - Without an identity re-verification handshake, a recycled number will map to the prior farmer's `entity_id`, contaminating credit histories, subsidy allotments, and consent scopes.
   - **Remediation:** Integrate an identity re-verification policy based on registration timestamps or national ID cross-validation.

---

## 5. Subtle Code Defects in Existing Repository

1. **Database Scheme Misnomer:**
   - In [`app/routes/farmers.py`](file:///c:/Users/nanda/OneDrive/Desktop/DELOITTE/Agri%20Africa/OAN%20KENYA/app/routes/farmers.py#L265), the scheme is inserted as `"voprf_ristretto255"`, despite the entire cryptographic stack running on **`secp256k1`**.
2. **Hard-coded Legacy Salt Inconsistencies:**
   - Multiple modules duplicate salt strings without unified domain separation tags.
3. **Mobile Client Time-Drift Replay Failures:**
   - In [`app/auth.py`](file:///c:/Users/nanda/OneDrive/Desktop/DELOITTE/Agri%20Africa/OAN%20KENYA/app/auth.py), nonces carry a strict 5-minute validity window. Field tablets without active NTP synchronization will experience total registration failure due to clock drift.

---

## 6. Comprehensive Risk Ranking Matrix

| Rank | Failure Mode | Category | Likelihood | Impact | Remediation |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **1** | **Database Unique Constraint Race Condition** | Concurrency | **High** | **Critical** | Add `try...except IntegrityError` handler in `farmers.py` |
| **2** | **In-Memory Lifetime Quota Lock (10k Cap)** | Logic / Rate-Limit | **Certain** | **Critical** | Replace in-memory dict with PostgreSQL rolling window |
| **3** | **Unencrypted Offline Queue on Mobile Tablets** | Privacy / Legal | **High** | **Critical** | Implement SQLCipher or in-memory blinding |
| **4** | **Mid-Flight Key Epoch Split-Brain** | Distributed Crypto | **High** | **High** | Enforce identical `key_id` check in Client SDK aggregation |
| **5** | **Pure Python CPU Saturation at 250k Scale** | Performance | **High** | **High** | Bind to optimized C primitives (`libsecp256k1`) |
| **6** | **Silent Third-Party Node Degradation** | Operations | **High** | **High** | Deploy automated 24/7 `/healthz` multi-party monitoring |
| **7** | **Audit Log Table Bloat (12M+ rows)** | Data Storage | **High** | **High** | Implement monthly PostgreSQL table partitioning |
| **8** | **Kenyan SIM Recycling Identity Collision** | Architecture | **Medium** | **High** | Implement SIM re-verification timestamp protocol |

---

## 7. Recommended Implementation Sequence

```mermaid
flowchart TD
    subgraph Phase 1: Concurrency & Storage Hardening
        A1[Fix DB Unique Constraint Race Condition] --> A2[Replace In-Memory Quotas with PostgreSQL Rolling Table]
        A2 --> A3[Correct voprf_secp256k1 Scheme Misnomer]
        A3 --> A4[Partition Audit Log Table for 250k Scale]
    end

    subgraph Phase 2: Standards-Compliant Cryptography
        B1[Implement RFC 9380 SSWU Hash-to-Curve] --> B2[Verify Appendix J.8.1 Test Vectors]
        B2 --> B3[Purge Legacy Try-and-Increment Engine]
    end

    subgraph Phase 3: Split-Key Evaluator Deployment
        C1[Implement 2-of-3 Shamir Deal Ceremony Script] --> C2[Build Isolated Evaluator Service Config]
        C2 --> C3[Harden Client Aggregation with Key Epoch Pinning]
    end

    subgraph Phase 4: Production Scale & Field Security
        D1[Encrypt Offline Storage on Mobile SDK] --> D2[Deploy 24/7 Multi-Party Health Monitor]
        D2 --> D3[Document Dual-Epoch Read & Migration Path]
    end

    Phase 1 --> Phase 2
    Phase 2 --> Phase 3
    Phase 3 --> Phase 4
```

---
*Report generated for technical audit and executive review prior to production codebase commit.*
