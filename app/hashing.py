import hmac
import hashlib
from app.config import settings

def rekey_hash(incoming_hash: str) -> str:
    """
    On receipt, the server re-keys the partner hash:
    hash_key = hex(HMAC-SHA256(SERVER_KEY, incoming_hash))
    Store only hash_key. The incoming partner hash is never stored.
    """
    key = settings.SERVER_KEY.encode("utf-8")
    msg = incoming_hash.strip().lower().encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def hash_api_key(api_key: str) -> str:
    """
    Computes SHA256 of the partner API key for database storage and lookup.
    """
    return hashlib.sha256(api_key.strip().encode("utf-8")).hexdigest()

def compute_request_signature_v2(
    api_key: str,
    method: str,
    path: str,
    query: str,
    timestamp: str,
    nonce: str,
    body: bytes
) -> str:
    """
    Signature v2:
    hex(HMAC-SHA256(api_key, METHOD + "\\n" + PATH + "\\n" + QUERY + "\\n" + TIMESTAMP + "\\n" + NONCE + "\\n" + hex(SHA256(body))))
    """
    body_hash = hashlib.sha256(body).hexdigest()
    canonical_str = f"{method.upper()}\n{path}\n{query}\n{timestamp}\n{nonce}\n{body_hash}"
    key = api_key.strip().encode("utf-8")
    return hmac.new(key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

def compute_request_signature(api_key: str, body: bytes) -> str:
    """
    Computes legacy HMAC-SHA256 signature of request body using partner API key.
    """
    key = api_key.strip().encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()
