import hmac
import hashlib
import re

class InvalidPhone(ValueError):
    """Raised when a phone number cannot be normalised to a valid Kenyan mobile number."""
    pass

KENYAN_MOBILE_REGEX = re.compile(r"^\+254(7|1)\d{8}$")

def normalise_phone(phone: str) -> str:
    """
    Normalise a Kenyan phone number:
    - Removes whitespace, dashes, dots, parentheses
    - '0' + 9 digits -> '+254' + 9 digits
    - '254' + 9 digits -> '+254' + 9 digits
    - 9 digits starting with 7 or 1 -> '+254' + digits
    - Validates against ^\\+254(7|1)\\d{8}$ or raises InvalidPhone
    """
    if not isinstance(phone, str):
        raise InvalidPhone("Phone number must be a string")
    
    cleaned = re.sub(r"[\s\-\.\(\)]", "", phone.strip())
    
    # Check 0 + 9 digits
    if re.fullmatch(r"0\d{9}", cleaned):
        cleaned = "+254" + cleaned[1:]
    # Check 254 + 9 digits (without leading +)
    elif re.fullmatch(r"254\d{9}", cleaned):
        cleaned = "+" + cleaned
    # Check 9 digits starting with 7 or 1
    elif re.fullmatch(r"[71]\d{8}", cleaned):
        cleaned = "+254" + cleaned

    if not KENYAN_MOBILE_REGEX.fullmatch(cleaned):
        raise InvalidPhone(f"Invalid Kenyan phone number format: '{phone}'")
    
    return cleaned

def hash_phone(phone: str, partner_key: str | bytes) -> str:
    """
    Normalises the phone number and computes the partner HMAC-SHA256 hash:
    hex(HMAC-SHA256(PARTNER_KEY, "ke-farmer:v1:" + normalised_phone))
    """
    norm = normalise_phone(phone)
    if isinstance(partner_key, str):
        partner_key = partner_key.encode("utf-8")
    
    message = f"ke-farmer:v1:{norm}".encode("utf-8")
    return hmac.new(partner_key, message, hashlib.sha256).hexdigest()

def sign_request(
    api_key: str,
    method: str,
    path: str,
    query: str = "",
    body: bytes | str = b"",
    timestamp: int | str | None = None,
    nonce: str | None = None
) -> dict:
    """
    Constructs signature v2 and returns dictionary of headers:
    X-Partner-Key, X-Timestamp, X-Nonce, X-Signature.
    """
    import time
    import secrets
    
    if timestamp is None:
        timestamp_str = str(int(time.time()))
    else:
        timestamp_str = str(timestamp)
        
    if nonce is None:
        nonce_str = secrets.token_hex(16)
    else:
        nonce_str = str(nonce)
        
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = body or b""
        
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    canonical_str = f"{method.upper()}\n{path}\n{query}\n{timestamp_str}\n{nonce_str}\n{body_hash}"
    key = api_key.strip().encode("utf-8")
    sig = hmac.new(key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
    
    return {
        "X-Partner-Key": api_key,
        "X-Timestamp": timestamp_str,
        "X-Nonce": nonce_str,
        "X-Signature": sig
    }

if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Normalise and hash a Kenyan phone number")
    parser.add_argument("--phone", required=True, help="Kenyan phone number to hash")
    parser.add_argument("--key", required=True, help="Partner secret key")
    args = parser.parse_args()

    try:
        norm = normalise_phone(args.phone)
        h = hash_phone(args.phone, args.key)
        print(f"Normalised: {norm}")
        print(f"Hash:       {h}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

