import time
from datetime import datetime, timezone, timedelta
from typing import Optional
import hmac
from fastapi import Header, HTTPException, Request, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.config import settings
from app.database import get_db
from app.models import Partner, RequestNonce
from app.hashing import hash_api_key, compute_request_signature_v2

async def authenticate_partner(
    request: Request,
    x_partner_key: Optional[str] = Header(None, alias="X-Partner-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
    x_nonce: Optional[str] = Header(None, alias="X-Nonce"),
    db: Session = Depends(get_db)
) -> Partner:
    """
    Authenticates delivery partner requests:
    1. Looks up partner by SHA-256 hash of X-Partner-Key and ensures active
    2. Enforces required signature headers (X-Timestamp, X-Nonce, X-Signature)
    3. Enforces X-Timestamp (within 300 seconds of server time)
    4. Enforces X-Nonce format (at least 16 chars)
    5. Validates HMAC-SHA256 signature v2 (method, path, query, timestamp, nonce, sha256(body))
    6. Nonce check and insert (rejecting replays, catching IntegrityError on uq_partner_nonce)
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
    
    if partner.active != 1:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Partner account is disabled"
        )
    
    if not x_signature or not x_timestamp or not x_nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing signature headers"
        )

    # Validate timestamp
    try:
        req_ts = int(x_timestamp.strip())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-Timestamp header"
        )
        
    current_ts = int(time.time())
    if abs(current_ts - req_ts) > 300:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Request timestamp expired or skewed beyond 300 seconds"
        )
        
    nonce_str = x_nonce.strip()
    if len(nonce_str) < 16:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Nonce must be at least 16 characters"
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

    # Verify signature v2 BEFORE touching or recording nonce
    path = request.url.path
    query = request.url.query
    expected_sig = compute_request_signature_v2(
        api_key=x_partner_key,
        method=request.method,
        path=path,
        query=query,
        timestamp=x_timestamp.strip(),
        nonce=nonce_str,
        body=body
    )

    if not hmac.compare_digest(x_signature.strip().lower(), expected_sig.strip().lower()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid request signature"
        )

    # Check if nonce was seen in the last 10 minutes
    ten_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
    existing_nonce = db.query(RequestNonce).filter(
        RequestNonce.partner_id == partner.partner_id,
        RequestNonce.nonce == nonce_str,
        RequestNonce.seen_at >= ten_mins_ago
    ).first()
    
    if existing_nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Replayed request: nonce already used"
        )
        
    # Record new nonce and catch potential concurrent replay via uq_partner_nonce
    new_nonce = RequestNonce(
        partner_id=partner.partner_id,
        nonce=nonce_str,
        seen_at=datetime.now(timezone.utc)
    )
    db.add(new_nonce)
    try:
        # Purge older nonces
        db.query(RequestNonce).filter(RequestNonce.seen_at < ten_mins_ago).delete()
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Replayed request: nonce already used"
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
