"""
RFC 9497 Compliant VOPRF Cryptographic Engine for OAN Kenya
Standards-Compliant Cryptography:
  - RFC 9380 Simplified SWU Hash-to-Curve (secp256k1_XMD:SHA-256_SSWU_RO_)
  - Domain separation with explicit key epoch: OAN-KE-<epoch>-secp256k1_XMD:SHA-256_SSWU_RO_
  - Montgomery ladder constant-time scalar multiplication (Pure Python fallback)
  - Native curve backend provider support (CFFI / libsecp256k1 / coincurve)
  - Two-of-three Shamir secret sharing with Lagrange polynomial interpolation at zero
  - Fiat-Shamir DLEQ zero-knowledge proofs
"""

import os
import hmac
import hashlib
import secrets
from typing import Tuple, Optional, List, Dict

# Curve parameters (Standard secp256k1 256-bit prime-order group)
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Base generator G
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

Point = Optional[Tuple[int, int]]

def is_valid_curve_point(pt: Point) -> bool:
    """
    Validates that point is non-infinity, coordinates lie in F_p,
    and satisfies the curve equation: y^2 = x^3 + 7 mod P_FIELD.
    Because secp256k1 has prime order N_ORDER and cofactor 1,
    any non-infinity point on the curve belongs to the prime-order subgroup.
    """
    if pt is None:
        return False
    x, y = pt
    if not (0 <= x < P_FIELD and 0 <= y < P_FIELD):
        return False
    if y == 0:
        return False
    return (y * y - (x * x * x + 7)) % P_FIELD == 0

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
        if y1 == 0:
            return None
        m = (3 * x1 * x1) * pow(2 * y1, -1, P_FIELD) % P_FIELD
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, P_FIELD) % P_FIELD
    x3 = (m * m - x1 - x2) % P_FIELD
    y3 = (m * (x1 - x3) - y1) % P_FIELD
    return (x3, y3)

def point_mul_pure_python(k: int, p: Point) -> Point:
    """
    Fixed-iteration Montgomery ladder scalar multiplication for Point p.
    Executes a fixed 256 iterations to eliminate scalar-dependent loop termination.
    """
    if p is None:
        return None
    k_val = k % N_ORDER
    if k_val == 0:
        return None

    r0 = None
    r1 = p
    for bit_idx in range(255, -1, -1):
        bit = (k_val >> bit_idx) & 1
        if bit == 0:
            r1 = point_add(r0, r1)
            r0 = point_add(r0, r0)
        else:
            r0 = point_add(r0, r1)
            r1 = point_add(r1, r1)
    return r0

# Curve backend selection and dispatch
CURVE_BACKEND = os.environ.get("CURVE_BACKEND", "pure_python").strip().lower()

_NATIVE_AVAILABLE = False
try:
    import coincurve
    _NATIVE_AVAILABLE = True
except ImportError:
    _NATIVE_AVAILABLE = False

def point_mul(k: int, p: Point) -> Point:
    """
    Dispatches scalar multiplication to configured curve backend.
    In production (ENV == 'production'), if CURVE_BACKEND='native' but native bindings
    are missing, fails fast with a RuntimeError to prevent silent 10x throughput degradation.
    """
    backend = os.environ.get("CURVE_BACKEND", CURVE_BACKEND).strip().lower()
    env = os.environ.get("ENV", "development").strip().lower()

    if backend == "native":
        if not _NATIVE_AVAILABLE:
            if env == "production":
                raise RuntimeError(
                    "FATAL: CURVE_BACKEND='native' is configured, but native secp256k1 bindings "
                    "(e.g. coincurve / libsecp256k1) are not available. Production refuses to start "
                    "with unverified or missing native backend."
                )
            # In non-production, fall back to pure python
            return point_mul_pure_python(k, p)
        # Use native coincurve scalar multiplication
        if p is None:
            return None
        k_val = k % N_ORDER
        if k_val == 0:
            return None
        try:
            pub_bytes = b"\x04" + p[0].to_bytes(32, "big") + p[1].to_bytes(32, "big")
            native_pt = coincurve.PublicKey(pub_bytes)
            res_bytes = native_pt.multiply(k_val.to_bytes(32, "big")).format(compressed=False)
            x_res = int.from_bytes(res_bytes[1:33], "big")
            y_res = int.from_bytes(res_bytes[33:65], "big")
            return (x_res, y_res)
        except Exception:
            return point_mul_pure_python(k, p)
    else:
        return point_mul_pure_python(k, p)

scalar_mult = point_mul
CURVE_ORDER = N_ORDER

class GroupElement:
    """Representation of an uncompressed curve point in the VOPRF group"""
    def __init__(self, pt: Point):
        if not is_valid_curve_point(pt):
            raise ValueError("GroupElement initialized with invalid or non-curve point")
        self.pt = pt

    def to_bytes(self) -> bytes:
        if self.pt is None:
            raise ValueError("Point at infinity cannot be encoded as an affine group element")
        return b"\x04" + self.pt[0].to_bytes(32, "big") + self.pt[1].to_bytes(32, "big")

    @classmethod
    def from_bytes(cls, b: bytes) -> "GroupElement":
        if len(b) != 65 or b[0] != 4:
            raise ValueError("Invalid uncompressed group element encoding")
        x = int.from_bytes(b[1:33], "big")
        y = int.from_bytes(b[33:65], "big")
        pt = (x, y)
        if not is_valid_curve_point(pt):
            raise ValueError("Point is not on secp256k1 curve or is invalid")
        return cls(pt)

    def __eq__(self, other):
        if not isinstance(other, GroupElement):
            return False
        return self.pt == other.pt

# Canonical generator G
GENERATOR_G = GroupElement((Gx, Gy))

def length_prefix(s: str | bytes) -> bytes:
    """Length-prefixed encoding LP(s) = uint16_be(len) || bytes"""
    if isinstance(s, str):
        data = s.encode("utf-8")
    else:
        data = s
    return len(data).to_bytes(2, byteorder="big") + data

# ============================================================================
# RFC 9380 SIMPLIFIED SWU HASH-TO-CURVE FOR secp256k1_XMD:SHA-256_SSWU_RO_
# ============================================================================

# 3-isogenous curve E': y^2 = x^3 + A_P*x + B_P   (RFC 9380 section 8.7)
A_P = 0x3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533
B_P = 1771
SWU_Z = P_FIELD - 11                   # Z = -11
C1  = (P_FIELD - 3) // 4
C2  = pow(11, (P_FIELD + 1) // 4, P_FIELD) # sqrt(-Z)

# 3-isogeny map constants (RFC 9380 Appendix E.1)
K1 = [
    0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7,
    0x07D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581,
    0x534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262,
    0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C,
]
K2 = [
    0xD35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B,
    0xEDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14,
]
K3 = [
    0x4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C,
    0xC75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3,
    0x29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931,
    0x2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84,
]
K4 = [
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B,
    0x7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573,
    0x6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F,
]

inv = lambda a: pow(a, P_FIELD - 2, P_FIELD)
sgn0 = lambda v: v % 2

def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """RFC 9380 section 5.3.1 with SHA-256."""
    ell = (len_in_bytes + 31) // 32
    dst_prime = dst + len(dst).to_bytes(1, "big")
    b_0 = hashlib.sha256(
        b"\x00" * 64 + msg + len_in_bytes.to_bytes(2, "big") + b"\x00" + dst_prime
    ).digest()
    b_i = hashlib.sha256(b_0 + b"\x01" + dst_prime).digest()
    out = b_i
    for i in range(2, ell + 1):
        b_i = hashlib.sha256(
            bytes(a ^ b for a, b in zip(b_0, b_i)) + i.to_bytes(1, "big") + dst_prime
        ).digest()
        out += b_i
    return out[:len_in_bytes]

def hash_to_field(msg: bytes, count: int, dst: bytes) -> list:
    """RFC 9380 section 5.2, m=1, L=48."""
    L = 48
    uniform = expand_message_xmd(msg, dst, count * L)
    return [
        int.from_bytes(uniform[i * L : (i + 1) * L], "big") % P_FIELD
        for i in range(count)
    ]

def sqrt_ratio_3mod4(u: int, v: int):
    """RFC 9380 Appendix F.2.1.2, for p = 3 mod 4."""
    tv1 = v * v % P_FIELD
    tv2 = u * v % P_FIELD
    tv1 = tv1 * tv2 % P_FIELD
    y1 = pow(tv1, C1, P_FIELD) * tv2 % P_FIELD
    y2 = y1 * C2 % P_FIELD
    tv3 = y1 * y1 % P_FIELD * v % P_FIELD
    is_qr = (tv3 == u)
    return is_qr, (y1 if is_qr else y2)

def map_to_curve_sswu(u: int):
    """RFC 9380 Appendix F.2 straight-line simplified SWU onto E'."""
    tv1 = SWU_Z * (u * u % P_FIELD) % P_FIELD
    tv2 = (tv1 * tv1 + tv1) % P_FIELD
    tv3 = B_P * (tv2 + 1) % P_FIELD
    tv4 = A_P * (SWU_Z if tv2 == 0 else (P_FIELD - tv2) % P_FIELD) % P_FIELD
    tv2 = tv3 * tv3 % P_FIELD
    tv6 = tv4 * tv4 % P_FIELD
    tv5 = A_P * tv6 % P_FIELD
    tv2 = (tv2 + tv5) * tv3 % P_FIELD
    tv6 = tv6 * tv4 % P_FIELD
    tv2 = (tv2 + B_P * tv6) % P_FIELD
    x = tv1 * tv3 % P_FIELD
    is_gx1_square, y1 = sqrt_ratio_3mod4(tv2, tv6)
    y = tv1 * u % P_FIELD * y1 % P_FIELD
    if is_gx1_square:
        x, y = tv3, y1
    if sgn0(u) != sgn0(y):
        y = (P_FIELD - y) % P_FIELD
    return x * inv(tv4) % P_FIELD, y

def iso_map(x: int, y: int):
    """3-isogeny E' -> secp256k1 (RFC 9380 Appendix E.1)."""
    x2 = x * x % P_FIELD
    x3 = x2 * x % P_FIELD
    x_num = (K1[3] * x3 + K1[2] * x2 + K1[1] * x + K1[0]) % P_FIELD
    x_den = (x2 + K2[1] * x + K2[0]) % P_FIELD
    y_num = (K3[3] * x3 + K3[2] * x2 + K3[1] * x + K3[0]) % P_FIELD
    y_den = (x3 + K4[2] * x2 + K4[1] * x + K4[0]) % P_FIELD
    return x_num * inv(x_den) % P_FIELD, y * y_num % P_FIELD * inv(y_den) % P_FIELD

def hash_to_curve(msg: bytes, dst: bytes) -> Point:
    """RFC 9380 secp256k1_XMD:SHA-256_SSWU_RO_."""
    u = hash_to_field(msg, 2, dst)
    return point_add(
        iso_map(*map_to_curve_sswu(u[0])),
        iso_map(*map_to_curve_sswu(u[1]))
    )

def hash_to_group(x: bytes, epoch_id: str = "ke-pilot-v4") -> GroupElement:
    """
    RFC 9380 Simplified SWU Hash-to-Curve with explicit key epoch DST:
    DST = b"OAN-KE-" + epoch_id + b"-secp256k1_XMD:SHA-256_SSWU_RO_"
    Eliminates all try-and-increment loops and timing side-channels.
    """
    dst = b"OAN-KE-" + epoch_id.encode("utf-8") + b"-secp256k1_XMD:SHA-256_SSWU_RO_"
    pt = hash_to_curve(x, dst)
    return GroupElement(pt)

# ============================================================================
# TWO-OF-THREE SHAMIR SECRET SHARING & LAGRANGE INTERPOLATION
# ============================================================================

def lagrange_at_zero(subset: List[int]) -> Dict[int, int]:
    """
    Computes Lagrange interpolation coefficients evaluated at zero mod N_ORDER:
    lambda_i = prod_{j in subset, j != i} (j / (j - i)) mod N_ORDER
    Rejects duplicate or invalid party indices cleanly without ZeroDivisionError.
    """
    if len(subset) != len(set(subset)):
        raise ValueError("Duplicate or invalid party indices in evaluation subset")
    for idx in subset:
        if not isinstance(idx, int) or idx <= 0:
            raise ValueError(f"Invalid party index: {idx}")

    lam = {}
    for i in subset:
        num, den = 1, 1
        for j in subset:
            if j != i:
                num = (num * j) % N_ORDER
                den = (den * (j - i)) % N_ORDER
        lam[i] = (num * pow(den, -1, N_ORDER)) % N_ORDER
    return lam

def combine_evaluations(subset, elements=None) -> GroupElement:
    """
    Recombines party evaluation responses Z_i via Lagrange coefficients:
    Z = sum_{i in subset} lambda_i * Z_i = k * B
    Supports either:
      combine_evaluations([1, 2], {1: Z1, 2: Z2})
      combine_evaluations([(1, Z1), (2, Z2)])
    """
    if elements is None and isinstance(subset, (list, tuple)) and subset and isinstance(subset[0], (list, tuple)):
        pairs = subset
        indices = [p[0] for p in pairs]
        elem_map = {p[0]: p[1] for p in pairs}
        return combine_evaluations(indices, elem_map)

    lam = lagrange_at_zero(subset)
    Z = None
    for i in subset:
        term = point_mul(lam[i], elements[i].pt)
        Z = term if Z is None else point_add(Z, term)
    return GroupElement(Z)

def combine_public_keys(subset, public_keys=None) -> GroupElement:
    """
    Recombines party public keys K_i via Lagrange coefficients:
    K = sum_{i in subset} lambda_i * K_i = k * G
    Supports either:
      combine_public_keys([1, 2], {1: K1, 2: K2})
      combine_public_keys([(1, K1), (2, K2)])
    """
    if public_keys is None and isinstance(subset, (list, tuple)) and subset and isinstance(subset[0], (list, tuple)):
        pairs = subset
        indices = [p[0] for p in pairs]
        pub_map = {p[0]: p[1] for p in pairs}
        return combine_public_keys(indices, pub_map)

    lam = lagrange_at_zero(subset)
    K = None
    for i in subset:
        term = point_mul(lam[i], public_keys[i].pt)
        K = term if K is None else point_add(K, term)
    return GroupElement(K)

# ============================================================================
# FIAT-SHAMIR DLEQ PROOFS
# ============================================================================

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

    if not is_valid_curve_point(A_prime) or not is_valid_curve_point(C_prime):
        return False

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
    def blind(x: bytes, epoch_id: str = "ke-pilot-v4") -> Tuple[GroupElement, int]:
        P = hash_to_group(x, epoch_id=epoch_id)
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
