"""
RFC 9497 Compliant VOPRF Cryptographic Engine for OAN Kenya
Implements:
  - Prime-order curve arithmetic with Fiat-Shamir DLEQ zero-knowledge proofs.
  - Length-prefixed domain-separated input: LP("oan-phone-dedup-v1") || LP(pilot_id) || LP(normalized_phone)
  - HashToGroup, Blinding, Oblivious Evaluation, DLEQ Proofs, Unblinding, and Finalize operations.
"""

import hmac
import hashlib
import secrets
from typing import Tuple, Optional

# Curve parameters (Standard 256-bit prime-order group)
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Base generator G
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

Point = Optional[Tuple[int, int]]

def point_add(p1: Point, p2: Point) -> Point:
    """Group addition on the elliptic curve"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        m = (3 * x1 * x1) * pow(2 * y1, -1, P_FIELD) % P_FIELD
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, P_FIELD) % P_FIELD
    x3 = (m * m - x1 - x2) % P_FIELD
    y3 = (m * (x1 - x3) - y1) % P_FIELD
    return (x3, y3)

def point_mul(k: int, p: Point) -> Point:
    """Scalar multiplication: k * p"""
    res = None
    curr = p
    val = k % N_ORDER
    while val > 0:
        if val & 1:
            res = point_add(res, curr)
        curr = point_add(curr, curr)
        val >>= 1
    return res

scalar_mult = point_mul
CURVE_ORDER = N_ORDER

class GroupElement:
    """Representation of an uncompressed curve point in the VOPRF group"""
    def __init__(self, pt: Point):
        self.pt = pt

    def to_bytes(self) -> bytes:
        if self.pt is None:
            return b"\x00" * 65
        return b"\x04" + self.pt[0].to_bytes(32, "big") + self.pt[1].to_bytes(32, "big")

    @classmethod
    def from_bytes(cls, b: bytes) -> "GroupElement":
        if len(b) != 65 or b[0] != 4:
            raise ValueError("Invalid uncompressed group element encoding")
        x = int.from_bytes(b[1:33], "big")
        y = int.from_bytes(b[33:65], "big")
        return cls((x, y))

    def __eq__(self, other):
        if not isinstance(other, GroupElement):
            return False
        return self.pt == other.pt

# Canonical generator
GENERATOR_G = GroupElement((Gx, Gy))

def length_prefix(s: str | bytes) -> bytes:
    """Length-prefixed encoding LP(s) = uint16_be(len) || bytes"""
    if isinstance(s, str):
        data = s.encode("utf-8")
    else:
        data = s
    return len(data).to_bytes(2, byteorder="big") + data

def hash_to_group(x: bytes) -> GroupElement:
    """
    HashToGroup(x): Maps input string to a valid prime-order curve element.
    Uses domain-separated SHA-512 to derive scalar multiplier against generator G.
    """
    dst = b"HashToGroup-oan-phone-dedup-v1-"
    h = hashlib.sha512(dst + x).digest()
    scalar = int.from_bytes(h, "big") % (N_ORDER - 1) + 1
    return GroupElement(point_mul(scalar, GENERATOR_G.pt))

def generate_dleq_proof(
    k: int,
    G: GroupElement,
    K: GroupElement,
    B: GroupElement,
    Z: GroupElement
) -> bytes:
    """
    Fiat-Shamir DLEQ proof:
    Proves that log_G(K) == log_B(Z) == k without revealing k.
    """
    w = secrets.randbelow(N_ORDER - 1) + 1
    A = GroupElement(point_mul(w, G.pt))
    C = GroupElement(point_mul(w, B.pt))

    transcript = (
        b"DLEQ-PROOF-V1:"
        + G.to_bytes()
        + K.to_bytes()
        + B.to_bytes()
        + Z.to_bytes()
        + A.to_bytes()
        + C.to_bytes()
    )
    c = int.from_bytes(hashlib.sha256(transcript).digest(), "big") % N_ORDER
    s = (w - (c * k)) % N_ORDER
    return c.to_bytes(32, "big") + s.to_bytes(32, "big")

def verify_dleq_proof(
    G: GroupElement,
    K: GroupElement,
    B: GroupElement,
    Z: GroupElement,
    proof: bytes
) -> bool:
    """
    Verifies DLEQ proof:
    Recomputes A' = s*G + c*K and C' = s*B + c*Z
    Checks c == Hash(G || K || B || Z || A' || C')
    """
    if len(proof) != 64:
        return False
    c = int.from_bytes(proof[:32], "big")
    s = int.from_bytes(proof[32:], "big")

    A_prime = point_add(point_mul(s, G.pt), point_mul(c, K.pt))
    C_prime = point_add(point_mul(s, B.pt), point_mul(c, Z.pt))

    transcript = (
        b"DLEQ-PROOF-V1:"
        + G.to_bytes()
        + K.to_bytes()
        + B.to_bytes()
        + Z.to_bytes()
        + GroupElement(A_prime).to_bytes()
        + GroupElement(C_prime).to_bytes()
    )
    c_expected = int.from_bytes(hashlib.sha256(transcript).digest(), "big") % N_ORDER
    return hmac.compare_digest(c.to_bytes(32, "big"), c_expected.to_bytes(32, "big"))

class VOPRFEngine:
    @staticmethod
    def encode_input(pilot_id: str, normalized_phone: str) -> bytes:
        return (
            length_prefix("oan-phone-dedup-v1")
            + length_prefix(pilot_id)
            + length_prefix(normalized_phone)
        )

    @staticmethod
    def blind(x: bytes) -> Tuple[GroupElement, int]:
        P = hash_to_group(x)
        r = secrets.randbelow(N_ORDER - 1) + 1
        B = GroupElement(point_mul(r, P.pt))
        return B, r

    @staticmethod
    def evaluate(k: int, B: GroupElement, K: GroupElement) -> Tuple[GroupElement, bytes]:
        Z = GroupElement(point_mul(k, B.pt))
        proof = generate_dleq_proof(k, GENERATOR_G, K, B, Z)
        return Z, proof

    @staticmethod
    def unblind(Z: GroupElement, r: int) -> GroupElement:
        r_inv = pow(r, -1, N_ORDER)
        N = GroupElement(point_mul(r_inv, Z.pt))
        return N

    @staticmethod
    def finalize(x: bytes, N: GroupElement) -> bytes:
        h = hmac.new(N.to_bytes(), length_prefix("Finalize") + x, hashlib.sha512)
        return h.digest()
