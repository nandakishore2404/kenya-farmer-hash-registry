# Reference Samples & Test Inputs

This folder contains pre-computed reference inputs and sample batch files for testing the **Kenya Farmer Hash Registry** locally.

---

## 1. `sample_registration_batch.csv`

A 20-row realistic CSV batch for testing `POST /v1/farmers:upload`.

### Expected Batch Upload Result:
- **Rows Received:** 20
- **Rows Accepted:** 17
- **Rows Rejected:** 3
- **Unique Farmer Codes Added:** 16 (Rows 3 & 4 share the same phone hash)

### Row-by-Row Expected Outcome:

| Row | Normalised Phone | Gender | Age Band | County | Onboarded At | Expected Outcome | Rationale |
|:---:|:---|:---:|:---:|:---:|:---|:---|:---|
| **1** | `+254712000001` | F | 25-34 | 047 | 2026-10-15T10:00:00Z | **Accepted** | Valid farmer in Nairobi. |
| **2** | `+254712000002` | M | 35-44 | 032 | 2026-10-15T10:05:00Z | **Accepted** | Valid farmer in Nakuru. |
| **3** | `+254712000003` | F | 18-24 | 019 | 2026-10-15T10:10:00Z | **Accepted** | Household user A in Nyeri. |
| **4** | `+254712000003` | M | 45-54 | 019 | 2026-10-15T10:11:00Z | **Accepted** | Household user B (same handset). Resend within file is treated idempotently without rollback. |
| **5** | `+254712000004` | F | 55-64 | 042 | 2026-10-15T10:15:00Z | **Accepted** | Valid farmer in Kisumu. |
| **6** | `+254712000005` | M | 25-34 | 999 | 2026-10-15T10:20:00Z | **Rejected** | County code `999` is invalid (pilot counties: 047, 032, 019, 042). |
| **7** | `+254712000006` | F | 35-44 | 047 | 2026-10-15T10:25:00Z | **Accepted** | Valid farmer in Nairobi. |
| **8** | `+254712000007` | X | 25-34 | 032 | 2026-10-15T10:30:00Z | **Rejected** | Gender `X` is invalid (must be `F` or `M`). |
| **9** | `+254712000008` | M | 18-24 | 019 | 2026-10-15T10:35:00Z | **Accepted** | Valid farmer in Nyeri. |
| **10** | `+254712000009` | F | 25-34 | 047 | 2026-11-01T10:00:00Z | **Rejected** | Date is in the future (> 5 minutes past server time). |
| **11** | `+254712000010` | M | 45-54 | 042 | 2026-10-15T10:40:00Z | **Accepted** | Valid farmer in Kisumu. |
| **12** | `+254712000011` | F | 35-44 | 032 | 2026-10-15T10:45:00Z | **Accepted** | Second-SIM owner (Primary SIM: 0712000011). |
| **13** | `+254712000012` | F | 35-44 | 032 | 2026-10-15T10:46:00Z | **Accepted** | Second-SIM owner (Secondary SIM: 0712000012). Yields distinct hash. |
| **14** | `+254712000013` | M | 55-64 | 019 | 2026-10-15T10:50:00Z | **Accepted** | Valid farmer in Nyeri. |
| **15** | `+254712000014` | F | 25-34 | 047 | 2026-10-15T10:55:00Z | **Accepted** | Valid farmer in Nairobi. |
| **16** | `+254712000015` | M | 35-44 | 042 | 2026-10-15T11:00:00Z | **Accepted** | Valid farmer in Kisumu. |
| **17** | `+254712000016` | F | 18-24 | 032 | 2026-10-15T11:05:00Z | **Accepted** | Valid farmer in Nakuru. |
| **18** | `+254712000017` | M | 45-54 | 019 | 2026-10-15T11:10:00Z | **Accepted** | Valid farmer in Nyeri. |
| **19** | `+254712000018` | F | 65+ | 047 | 2026-10-15T11:15:00Z | **Accepted** | Valid farmer in Nairobi. |
| **20** | `+254712000019` | M | 25-34 | 042 | 2026-10-15T11:20:00Z | **Accepted** | Valid farmer in Kisumu. |

---

## 2. `sample_hashes.json`

Contains pre-computed phone hashes using `PARTNER_KEY="partner_shared_pilot_secret"`. Useful for quick `curl` testing without running client SDK code first.

---

## 3. CLI Hash Generator

To compute hashes directly on the command line:

```bash
python -m sdk.python.hasher --phone "0712 345 678" --key "partner_shared_pilot_secret"
```

Output:
```
Normalised: +254712345678
Hash:       68ef61470b4d31e36b10fd399f17078a0b41198beddf846ae4defc69385e3fe6
```
