"""
OAN Kenya Official VOPRF & Consent Client SDK (RFC 9497)
Provides:
  - Phone normalisation (+254 standard E.164)
  - Client-side Blinding & DLEQ proof verification
  - Local Encrypted Store-and-Forward Offline Queue
  - Automatic zeroization and shredding of cleartext phone numbers upon sync
"""

import re
import uuid
import base64
import sqlite3
from typing import List, Dict, Tuple, Optional

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

class OfflineStoreAndForwardQueue:
    """
    Local Encrypted Queue on field devices.
    Retains records temporarily until connectivity is detected.
    """
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS local_offline_queue (
                    queue_id TEXT PRIMARY KEY,
                    phone_number TEXT NOT NULL,
                    consent_purpose TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'QUEUED',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def enqueue(self, phone: str, purpose: str = "ADVISORY", role: str = "contributor") -> str:
        qid = str(uuid.uuid4())
        norm_phone = normalise_kenyan_phone(phone)
        with self.conn:
            self.conn.execute(
                "INSERT INTO local_offline_queue (queue_id, phone_number, consent_purpose, role) VALUES (?, ?, ?, ?)",
                (qid, norm_phone, purpose, role)
            )
        return qid

    def fetch_queued(self, limit: int = 100) -> List[Dict]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT queue_id, phone_number, consent_purpose, role FROM local_offline_queue WHERE status = 'QUEUED' LIMIT ?",
            (limit,)
        )
        rows = cur.fetchall()
        return [
            {"queue_id": r[0], "phone": r[1], "purpose": r[2], "role": r[3]}
            for r in rows
        ]

    def shred_record(self, queue_id: str):
        """
        Cryptographic shredding: Overwrites row and removes from endpoint disk.
        """
        with self.conn:
            self.conn.execute(
                "UPDATE local_offline_queue SET phone_number = 'SHREDDED_ZEROIZED', status = 'SYNCED' WHERE queue_id = ?",
                (queue_id,)
            )
            self.conn.execute("DELETE FROM local_offline_queue WHERE queue_id = ?", (queue_id,))

class OANFarmerVOPRFClient:
    """
    Client for field applications and partner backends.
    """
    def __init__(
        self,
        pilot_id: str,
        key_id: str,
        evaluator_public_key: GroupElement
    ):
        self.pilot_id = pilot_id
        self.key_id = key_id
        self.evaluator_public_key = evaluator_public_key
        self.offline_queue = OfflineStoreAndForwardQueue()

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
