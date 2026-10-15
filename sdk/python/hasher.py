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
