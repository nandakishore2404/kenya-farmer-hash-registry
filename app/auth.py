import hmac
from typing import Optional
from fastapi import Header, HTTPException, Request, Depends, status
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import Partner
from app.hashing import hash_api_key, compute_request_signature

async def authenticate_partner(
    request: Request,
    x_partner_key: Optional[str] = Header(None, alias="X-Partner-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    db: Session = Depends(get_db)
) -> Partner:
    """
    Authenticates delivery partner requests:
    1. Looks up partner by SHA-256 hash of X-Partner-Key
    2. Validates HMAC-SHA256 signature of request body using X-Partner-Key
    3. Rejects invalid partner keys or bad signatures with 401 Unauthorized
    """
    if not x_partner_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Partner-Key header"
        )
    
    key_hash = hash_api_key(x_partner_key)
    partner = db.query(Partner).filter(Partner.api_key_hash == key_hash).first()
    if not partner:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown or invalid partner key"
        )
    
    if not x_signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Signature header"
        )

    # Read raw body for HMAC verification
    body = await request.body()
    
    # Re-enable body stream for multipart parsers or downstream dependencies
    sent = False
    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}
    
    request._receive = receive
    request._stream_consumed = False

    expected_sig = compute_request_signature(x_partner_key, body)
    
    if not hmac.compare_digest(x_signature.strip().lower(), expected_sig.strip().lower()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid request signature"
        )
    
    return partner


def authenticate_admin(
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")
) -> bool:
    """
    Authenticates administrative requests using the server ADMIN_KEY.
    """
    if not x_admin_key or not hmac.compare_digest(x_admin_key.strip(), settings.ADMIN_KEY.strip()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing admin key"
        )
    return True
