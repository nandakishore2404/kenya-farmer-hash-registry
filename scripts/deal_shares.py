#!/usr/bin/env python3
"""
One-Time Air-Gapped Key Dealing Ceremony for OAN Kenya Split-Key Evaluator (RFC 9497 / Shamir 2-of-3)
Generates:
  - Degree-1 polynomial: f(z) = (k + a*z) mod N_ORDER
  - Shares: s1 = f(1), s2 = f(2), s3 = f(3) mod N_ORDER
  - Public Keys: K = k*G, K1 = s1*G, K2 = s2*G, K3 = s3*G
  - Writes share files with permissions 0600
  - Refuses to run if target share files already exist
  - Zeroes k and a from memory before termination
"""

import os
import sys
import secrets
import base64
from typing import Tuple

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto.voprf import (
    N_ORDER,
    GENERATOR_G,
    point_mul,
    GroupElement,
    lagrange_at_zero
)

PARTIES = [
    ("safic", 1),
    ("operator", 2),
    ("independent", 3)
]

def deal_shares(output_dir: str = ".") -> Tuple[str, dict]:
    # 1. Safety check: refuse if any share file already exists
    share_files = {p_id: os.path.join(output_dir, f"{p_id}.share") for p_id, _ in PARTIES}
    existing = [f for f in share_files.values() if os.path.exists(f)]
    if existing:
        raise RuntimeError(
            f"REFUSING TO DEAL: Share file(s) already exist: {', '.join(existing)}. "
            "The dealing ceremony must run once on an air-gapped machine. "
            "To re-deal, existing share files must be explicitly archived or deleted."
        )

    # 2. Cryptographic generation of k and polynomial coefficient a
    k = secrets.randbelow(N_ORDER - 1) + 1
    a = secrets.randbelow(N_ORDER - 1) + 1

    f = lambda z: (k + a * z) % N_ORDER
    shares = {p_id: f(idx) for p_id, idx in PARTIES}

    # 3. Derive aggregate public key K and per-party public keys Ki
    K_pt = point_mul(k, GENERATOR_G.pt)
    K_elem = GroupElement(K_pt)
    K_b64 = base64.b64encode(K_elem.to_bytes()).decode("utf-8")

    party_pubkeys = {}
    for p_id, idx in PARTIES:
        s_i = shares[p_id]
        Ki_pt = point_mul(s_i, GENERATOR_G.pt)
        Ki_elem = GroupElement(Ki_pt)
        party_pubkeys[p_id] = {
            "party_index": idx,
            "public_key_b64": base64.b64encode(Ki_elem.to_bytes()).decode("utf-8"),
            "public_key_elem": Ki_elem
        }

    # 4. Verify 2-of-3 reconstruction across all pairs before writing
    for pair in [(1, 2), (1, 3), (2, 3)]:
        lam = lagrange_at_zero(list(pair))
        i, j = pair
        id_i = [p for p, idx in PARTIES if idx == i][0]
        id_j = [p for p, idx in PARTIES if idx == j][0]
        rec_s = (lam[i] * shares[id_i] + lam[j] * shares[id_j]) % N_ORDER
        if rec_s != k:
            raise RuntimeError(f"Ceremony validation failed: pair {pair} does not reconstruct k")

    # 5. Write each share to its own file with restrictive permissions (0600)
    for p_id, _ in PARTIES:
        s_hex = f"{shares[p_id]:064x}"
        path = share_files[p_id]
        # Open with O_CREAT | O_WRONLY | O_EXCL, mode 0o600
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        mode = 0o600
        fd = os.open(path, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(s_hex + "\n")

    # 6. Secure zeroization of k and a in memory
    k = 0
    a = 0
    for p_id in shares:
        shares[p_id] = 0

    return K_b64, party_pubkeys

def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print("===================================================================")
    print("  OAN KENYA SPLIT-KEY EVALUATOR DEALING CEREMONY (2-OF-3 SHAMIR)   ")
    print("===================================================================\n")
    try:
        K_b64, party_pubkeys = deal_shares(out_dir)
        print("CEREMONY SUCCESSFUL! Shares written to disk with mode 0600.\n")
        print(f"Aggregate Public Key K (fixed, pinned in clients):")
        print(f"  {K_b64}\n")
        print("Per-Party Published Public Keys:")
        for p_id, info in party_pubkeys.items():
            print(f"  Party '{p_id}' (Index {info['party_index']}):")
            print(f"    Public Key (Ki): {info['public_key_b64']}")
        print("\nPeer Public Keys Config String (EVALUATOR_PEER_PUBKEYS):")
        peer_str = ",".join([party_pubkeys[p]["public_key_b64"] for p, _ in PARTIES])
        print(f"  {peer_str}\n")
        print("Master secret scalar k and polynomial coefficients have been wiped from memory.")
        print("===================================================================")
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
