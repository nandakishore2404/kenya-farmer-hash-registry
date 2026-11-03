#!/usr/bin/env python3
"""
Share Verification Script for OAN Kenya Split-Key Evaluator
Enables an institution (SAFIC, Operator, Independent) to verify that their
held secret share matches their published public key Ki without revealing the share.
"""

import os
import sys
import base64

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto.voprf import (
    N_ORDER,
    GENERATOR_G,
    point_mul,
    GroupElement
)

def verify_share(share_val_or_path: str, published_ki_b64: str) -> bool:
    clean_input = share_val_or_path.strip()
    if os.path.isfile(clean_input):
        with open(clean_input, "r", encoding="utf-8") as f:
            clean_input = f.read().strip()

    hex_share = clean_input[2:] if clean_input.startswith(("0x", "0X")) else clean_input
    if len(hex_share) != 64:
        raise ValueError("Share must be exactly 64 hexadecimal characters")

    s_i = int(hex_share, 16) % N_ORDER
    if s_i == 0:
        raise ValueError("Share cannot be zero mod curve order")

    derived_pt = point_mul(s_i, GENERATOR_G.pt)
    derived_elem = GroupElement(derived_pt)
    derived_b64 = base64.b64encode(derived_elem.to_bytes()).decode("utf-8")

    expected_bytes = base64.b64decode(published_ki_b64.strip())
    expected_elem = GroupElement.from_bytes(expected_bytes)

    return derived_elem == expected_elem

def main():
    if len(sys.argv) < 3:
        print("Usage: python verify_share.py <share_file_or_hex> <published_ki_b64>")
        sys.exit(1)

    share_arg = sys.argv[1]
    pubkey_arg = sys.argv[2]

    try:
        is_valid = verify_share(share_arg, pubkey_arg)
        if is_valid:
            print("VERIFICATION RESULT: PASS - Share scalar mathematically matches published Ki!")
            sys.exit(0)
        else:
            print("VERIFICATION RESULT: FAIL - Share scalar does NOT match published Ki!", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"VERIFICATION ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
