# Farmer Phone Hashing SDK

This SDK provides client-side phone number normalisation and keyed HMAC hashing for delivery partners participating in the Kenya Agricultural Advisory Registry.

## Plain-Language Privacy Notice: Why a Keyed Hash?

A standard unkeyed cryptographic hash (such as plain `SHA-256("0712345678")`) provides **zero real privacy protection** for phone numbers.

### The Problem: Precomputation & Rainbow Tables
In Kenya, all mobile numbers follow a strict format starting with `+254 7...` or `+254 1...` with exactly 8 subsequent digits. This means the entire universe of possible Kenyan mobile numbers is approximately **200 million numbers** (2 prefixes $\times 10^8$). 

A modern laptop or consumer GPU can compute 200 million SHA-256 hashes in **less than one second**. If unkeyed hashes were sent to the registry, any party who intercepted or accessed the database could simply precalculate hashes for all 200M numbers and reverse every farmer's phone number instantly.

### The Solution: Keyed Hash (`HMAC-SHA256`)
To eliminate dictionary and rainbow-table inversion:
1. Partners share a high-entropy secret (`PARTNER_KEY`) among authorized field delivery organizations.
2. The hash is computed as:
   $$\text{HMAC-SHA256}(\text{PARTNER\_KEY}, \text{"ke-farmer:v1:"} + \text{normalised\_phone})$$
3. The central registry server **does not possess the PARTNER_KEY**.
4. Upon receiving the partner hash, the central registry re-keys it using its own secret (`SERVER_KEY`) before writing to the database.

This two-tier cryptographic separation guarantees:
- **No Phone Numbers Transmitted or Stored:** The central registry server never sees or stores cleartext phone numbers or names.
- **Irreversibility:** Neither the central registry nor an external eavesdropper can brute-force the partner hash without knowing `PARTNER_KEY`.
- **Cross-Partner De-duplication:** Because all legitimate delivery partners use the same agreed `PARTNER_KEY` for the pilot, the exact same farmer produces the identical partner hash across partners, enabling exact 1-to-1 de-duplication without data leakage.

---

## Phone Normalisation Rules

All phone numbers are cleaned and converted into standard E.164 format:
- Spaces, dashes (`-`), dots (`.`), and parentheses (`()`) are stripped.
- `07XXXXXXXX` or `01XXXXXXXX` (10 digits) $\rightarrow$ `+2547XXXXXXXX` / `+2541XXXXXXXX`
- `2547XXXXXXXX` or `2541XXXXXXXX` (12 digits) $\rightarrow$ `+2547XXXXXXXX` / `+2541XXXXXXXX`
- `7XXXXXXXX` or `1XXXXXXXX` (9 digits) $\rightarrow$ `+2547XXXXXXXX` / `+2541XXXXXXXX`
- Numbers must match `^\+254(7|1)\d{8}$` or `InvalidPhone` error is thrown.

---

## Usage Examples

### Python
```python
from sdk.python.hasher import normalise_phone, hash_phone

PARTNER_KEY = "partner_shared_pilot_secret"
phone = "0712-345-678"

# 1. Normalise
norm = normalise_phone(phone) # -> "+254712345678"

# 2. Hash
farmer_hash = hash_phone(phone, PARTNER_KEY)
print(farmer_hash) # 64-char hex string
```

### JavaScript / Node.js
```javascript
const { normalisePhone, hashPhone } = require('./hasher');

const PARTNER_KEY = 'partner_shared_pilot_secret';
const phone = '0712-345-678';

// 1. Normalise
const norm = normalisePhone(phone); // -> "+254712345678"

// 2. Hash
const farmerHash = hashPhone(phone, PARTNER_KEY);
console.log(farmerHash); // 64-char hex string
```
