# OAN Kenya Farmer Identity & Deduplication Architecture

## 1. System Overview & RFC 9497 Split-Key VOPRF

The OAN Kenya Farmer Registry implements an air-gapped, zero-knowledge deduplication system based on **RFC 9497 Oblivious Pseudorandom Functions (VOPRF)** over elliptic curve `secp256k1` (`secp256k1_XMD:SHA-256_SSWU_RO_`).

To eliminate single-point-of-failure key exposure, the Evaluator secret scalar $k$ is distributed using a **Shamir 2-of-3 threshold secret sharing scheme** across three independent administrative parties:
1. **Party 1 (Safic)**: Agricultural PMO / Safic cloud host.
2. **Party 2 (Operator)**: Telecom / Mobile Network Operator infrastructure.
3. **Party 3 (Independent)**: Independent institutional trustee / data protection audit authority.

Neither party ever holds or learns the master secret $k$. Any two parties can collaboratively evaluate a blinded farmer query without ever communicating with each other or discovering the cleartext phone number.

---

## 2. Threshold Client Flow (RFC 9497 Shamir 2-of-3)

```
Farmer Mobile / Partner Cloud SDK                    Evaluator Party 1 (Safic)       Evaluator Party 2 (Operator)
              │                                                │                               │
 1. Normalise │ phone -> +254...                               │                               │
 2. Blind     │ P = H_group(x), B = r * P                      │                               │
              ├──────────────── Blinded Element B ────────────>│                               │
              ├──────────────── Blinded Element B ────────────────────────────────────────────>│
              │                                                │                               │
              │                                                │ Z_1 = s_1 * B                 │ Z_2 = s_2 * B
              │                                                │ pi_1 = DLEQ(G, K_1, B, Z_1)   │ pi_2 = DLEQ(G, K_2, B, Z_2)
              │<─── (Z_1, pi_1) ───────────────────────────────┤                               │
              │<─── (Z_2, pi_2) ───────────────────────────────────────────────────────────────┤
              │
 3. Verify    │ verify_dleq(G, K_1, B, Z_1, pi_1) == TRUE
              │ verify_dleq(G, K_2, B, Z_2, pi_2) == TRUE
              │
 4. Key Check │ K_rec = lambda_1 * K_1 + lambda_2 * K_2 == K_aggregate
              │
 5. Combine   │ Z = lambda_1 * Z_1 + lambda_2 * Z_2  (= k * B)
 6. Unblind   │ N = r^(-1) * Z                       (= k * P)
 7. Finalize  │ Token T = HMAC-SHA512(N, "Finalize" || x)
              │
              ▼
    National Registry (Postgres)
              │
 8. Digest    │ Storage Digest D = SHA-256("OAN_KENYA_STORAGE_V1:" || T)
 9. Upsert    │ INSERT INTO token_alias (digest_d) ... RETURNING entity_id
```

### Mathematical Invariants
- Polynomial: $f(z) = k + a \cdot z \pmod n$
- Party Shares: $s_1 = f(1), s_2 = f(2), s_3 = f(3) \pmod n$
- Party Public Keys: $K_i = s_i \cdot G$
- Aggregate Public Key: $K = k \cdot G$
- Lagrange coefficients at zero for pair $\{i, j\}$:
  $$\lambda_i = \frac{j}{j - i} \pmod n, \quad \lambda_j = \frac{i}{i - j} \pmod n$$
- Linear combination reconstructs evaluation without uncovering $s_i$:
  $$Z = \lambda_i Z_i + \lambda_j Z_j = (\lambda_i s_i + \lambda_j s_j) B = k \cdot B$$
  $$N = r^{-1} \cdot Z = k \cdot P = k \cdot H(x)$$

---

## 3. Client SDK API (`sdk/python/voprf_client.py`)

Partner backends and mobile clients configure `OANFarmerVOPRFClient` with the published peer public keys:

```python
client = OANFarmerVOPRFClient(
    pilot_id="kenya-pilot",
    key_id="ke-pilot-v4",
    evaluator_public_key=aggregate_K,
    peer_public_keys={1: K1, 2: K2, 3: K3}
)

# 1. Blind registration
x, B, r = client.prepare_blinded_registration("+254712345678")

# 2. Query any 2 of the 3 evaluators
# Party 1 returns (Z1_bytes, proof1_bytes)
# Party 2 returns (Z2_bytes, proof2_bytes)
responses = {
    1: (Z1_bytes, proof1_bytes),
    2: (Z2_bytes, proof2_bytes)
}

# 3. Process threshold evaluation response
token_result = client.process_threshold_evaluation_response(x, B, r, responses)
token_bytes = token_result.token_bytes
```

### Fail-Closed Protections
1. **Quorum Enforcement:** Rejects if fewer than 2 distinct parties respond.
2. **DLEQ Proof Verification:** Rejects if any party's evaluation fails proof of discrete logarithm equivalence against that party's published key $K_i$.
3. **Key Consistency Verification:** Reconstructs the aggregate public key $K_{rec} = \sum \lambda_i K_i$ and asserts equality against the client's pinned `evaluator_public_key`.
4. **Duplicate Protection:** Rejects duplicate party indices.
