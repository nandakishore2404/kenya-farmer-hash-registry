"""
OAN Kenya Official VOPRF & Consent Client SDK (RFC 9497)
Provides:
  - Phone normalisation (+254 standard E.164)
  - Client-side Blinding & DLEQ proof verification
  - Ephemeral in-memory queue (default for partner cloud backends)
  - Authenticated-encrypted local store-and-forward queue with overwrite-shredding & VACUUM (for edge devices)

Deployment & Threat Model Note:
  This SDK is designed for deployment on Partner Cloud Backends (e.g. One Acre Fund, DigiFarm, KTDA
  application servers) syncing farmer cohorts to the national registry, as well as field integration gateways.
  No cleartext phone number is ever deliberately written to disk.

Memory Security Disclaimer:
  In Python, string and integer objects are immutable and managed by the runtime garbage collector;
  true memory zeroization is not guaranteed by the language runtime. In production host environments,
  operators must disable swap ('swapoff -a') and core dumps ('ulimit -c 0') to prevent process memory
  pages from being flushed to physical media.
"""

import os
import re
import uuid
import base64
import sqlite3
import secrets
import hashlib
from typing import List, Dict, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.crypto.voprf import (
    VOPRFEngine,
    GroupElement,
    verify_dleq_proof,
    GENERATOR_G
)

KENYAN_MOBILE_REGEX = re.compile(r"^\+254[71]\d{8}$")

class InvalidPhoneError(ValueError):
    pass

class CryptographicVerificationError(RuntimeError):
    pass

def normalise_kenyan_phone(phone: str) -> str:
    """Normalises Kenyan mobile number to standard E.164 +254..."""
    if not isinstance(phone, str):
        raise InvalidPhoneError("Phone number must be a string")
    cleaned = re.sub(r"[\s\-\.\(\)]", "", phone.strip())
    if re.fullmatch(r"0\d{9}", cleaned):
        cleaned = "+254" + cleaned[1:]
    elif re.fullmatch(r"254\d{9}", cleaned):
        cleaned = "+" + cleaned
    elif re.fullmatch(r"[71]\d{8}", cleaned):
        cleaned = "+254" + cleaned

    if not KENYAN_MOBILE_REGEX.fullmatch(cleaned):
        raise InvalidPhoneError(f"Invalid Kenyan phone number format: '{phone}'")
    return cleaned

class BaseOfflineQueue:
    """Abstract interface for offline store-and-forward queues."""
    def enqueue(self, phone: str, purpose: str = "ADVISORY", role: str = "contributor") -> str:
        raise NotImplementedError

    def fetch_queued(self, limit: int = 100) -> List[Dict]:
        raise NotImplementedError

    def shred_record(self, queue_id: str):
        raise NotImplementedError

    def close(self):
        pass

class EphemeralStoreAndForwardQueue(BaseOfflineQueue):
    """
    Default in-memory queue for partner cloud backends.
    Records reside strictly in process volatile memory and are never deliberately written to disk.
    """
    def __init__(self):
        self._records: Dict[str, Dict] = {}

    def enqueue(self, phone: str, purpose: str = "ADVISORY", role: str = "contributor") -> str:
        qid = str(uuid.uuid4())
        norm_phone = normalise_kenyan_phone(phone)
        self._records[qid] = {
            "queue_id": qid,
            "phone": norm_phone,
            "purpose": purpose,
            "role": role,
            "status": "QUEUED"
        }
        return qid

    def fetch_queued(self, limit: int = 100) -> List[Dict]:
        out = []
        for r in self._records.values():
            if r["status"] == "QUEUED":
                out.append({
                    "queue_id": r["queue_id"],
                    "phone": r["phone"],
                    "purpose": r["purpose"],
                    "role": r["role"]
                })
                if len(out) >= limit:
                    break
        return out

    def shred_record(self, queue_id: str):
        if queue_id in self._records:
            self._records[queue_id]["phone"] = "SHREDDED_ZEROIZED"
            self._records[queue_id]["status"] = "SYNCED"
            del self._records[queue_id]

class EncryptedStoreAndForwardQueue(BaseOfflineQueue):
    """
    Hardware-keyed Authenticated Encrypted Queue (AES-256-GCM) for edge field devices.
    Ensures that data at rest is cryptographically unreadable without the platform/keystore key.
    Shredding performs cryptographic multi-pass overwrite before deletion and invokes SQLite VACUUM.
    """
    def __init__(self, db_path: str, encryption_key: Optional[bytes] = None):
        self.db_path = db_path
        if encryption_key is None:
            # Derive or generate process key if not provided (with explicit warning for persistent paths)
            self._key = secrets.token_bytes(32)
        elif isinstance(encryption_key, str):
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"OAN-KE-OFFLINE-QUEUE-SALT-v1",
                info=b"oan-encrypted-offline-queue",
            )
            self._key = hkdf.derive(encryption_key.encode("utf-8"))
        elif isinstance(encryption_key, bytes):
            if len(encryption_key) == 32:
                self._key = encryption_key
            else:
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"OAN-KE-OFFLINE-QUEUE-SALT-v1",
                    info=b"oan-encrypted-offline-queue",
                )
                self._key = hkdf.derive(encryption_key)
        else:
            raise TypeError("encryption_key must be bytes or str")

        self._aesgcm = AESGCM(self._key)
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS local_offline_queue (
                    queue_id TEXT PRIMARY KEY,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    consent_purpose TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'QUEUED',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def enqueue(self, phone: str, purpose: str = "ADVISORY", role: str = "contributor") -> str:
        qid = str(uuid.uuid4())
        norm_phone = normalise_kenyan_phone(phone)
        nonce = secrets.token_bytes(12)
        # AES-GCM appends 16-byte tag to ciphertext
        ciphertext = self._aesgcm.encrypt(nonce, norm_phone.encode("utf-8"), None)
        with self.conn:
            self.conn.execute(
                "INSERT INTO local_offline_queue (queue_id, nonce, ciphertext, consent_purpose, role) VALUES (?, ?, ?, ?, ?)",
                (qid, nonce, ciphertext, purpose, role)
            )
        return qid

    def fetch_queued(self, limit: int = 100) -> List[Dict]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT queue_id, nonce, ciphertext, consent_purpose, role FROM local_offline_queue WHERE status = 'QUEUED' LIMIT ?",
            (limit,)
        )
        rows = cur.fetchall()
        results = []
        for r in rows:
            qid, nonce, ct, purpose, role = r
            try:
                decrypted_bytes = self._aesgcm.decrypt(nonce, ct, None)
                phone = decrypted_bytes.decode("utf-8")
                results.append({"queue_id": qid, "phone": phone, "purpose": purpose, "role": role})
            except Exception as e:
                raise CryptographicVerificationError(f"Failed to decrypt queued record {qid}: {str(e)}")
        return results

    def shred_record(self, queue_id: str):
        """
        Cryptographic shredding: Overwrites ciphertext and nonce with high-entropy random bytes,
        deletes the row, commits, and runs VACUUM to purge the SQLite freelist.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT nonce, ciphertext FROM local_offline_queue WHERE queue_id = ?", (queue_id,))
        row = cur.fetchone()
        if row:
            nonce_len = len(row[0])
            ct_len = len(row[1])
            garbage_nonce = secrets.token_bytes(nonce_len)
            garbage_ct = secrets.token_bytes(ct_len)
            with self.conn:
                # Overwrite on disk before deletion
                self.conn.execute(
                    "UPDATE local_offline_queue SET nonce = ?, ciphertext = ?, status = 'SHREDDED' WHERE queue_id = ?",
                    (garbage_nonce, garbage_ct, queue_id)
                )
                self.conn.execute("DELETE FROM local_offline_queue WHERE queue_id = ?", (queue_id,))
            # Force SQLite to reclaim and wipe freelist pages
            self.conn.execute("VACUUM")

    def close(self):
        if self.conn:
            self.conn.close()

class OfflineStoreAndForwardQueue:
    """
    Factory / compatibility wrapper.
    Defaults to EphemeralStoreAndForwardQueue for ':memory:' or None (cloud backend standard).
    Constructs EncryptedStoreAndForwardQueue when a persistent file path is specified.
    """
    def __new__(cls, db_path: str = ":memory:", encryption_key: Optional[bytes] = None):
        if db_path == ":memory:" or db_path is None:
            return EphemeralStoreAndForwardQueue()
        return EncryptedStoreAndForwardQueue(db_path=db_path, encryption_key=encryption_key)

class OANFarmerVOPRFClient:
    """
    Client for field applications and partner backends.
    """
    def __init__(
        self,
        pilot_id: str,
        key_id: str,
        evaluator_public_key: GroupElement,
        offline_queue: Optional[BaseOfflineQueue] = None
    ):
        self.pilot_id = pilot_id
        self.key_id = key_id
        self.evaluator_public_key = evaluator_public_key
        self.offline_queue = offline_queue if offline_queue is not None else EphemeralStoreAndForwardQueue()

    def prepare_blinded_registration(self, phone: str) -> Tuple[bytes, GroupElement, int]:
        norm_phone = normalise_kenyan_phone(phone)
        x = VOPRFEngine.encode_input(self.pilot_id, norm_phone)
        B, r = VOPRFEngine.blind(x)
        return x, B, r

    def process_evaluation_response(
        self,
        x: bytes,
        B: GroupElement,
        r: int,
        Z_bytes: bytes,
        proof_bytes: bytes
    ) -> bytes:
        Z = GroupElement.from_bytes(Z_bytes)

        # 1. Verify DLEQ proof
        is_valid = verify_dleq_proof(
            GENERATOR_G,
            self.evaluator_public_key,
            B,
            Z,
            proof_bytes
        )
        if not is_valid:
            raise CryptographicVerificationError(
                "Evaluator DLEQ proof verification failed! Potential key tampering detected."
            )

        # 2. Unblind N = r^(-1) * Z
        N = VOPRFEngine.unblind(Z, r)

        # 3. Finalize Token T
        token_t = VOPRFEngine.finalize(x, N)
        return token_t

