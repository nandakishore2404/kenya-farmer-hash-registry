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

def compute_request_signature(api_key: str, body: bytes) -> str:
    """
    Computes HMAC-SHA256 signature of request body using partner API key.
    """
    key = api_key.strip().encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()
