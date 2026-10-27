from datetime import datetime
from typing import Literal, Optional, List
from pydantic import BaseModel, Field, field_validator

GenderType = Literal["F", "M", "U"]
AgeBandType = Literal["<18", "18-24", "25-34", "35-44", "45-54", "55-64", "65+", "U"]

class FarmerRegisterRequest(BaseModel):
    hash: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$", description="Incoming partner HMAC-SHA256 hash")
    gender: GenderType
    age_band: AgeBandType
    county_code: str = Field(..., min_length=1, max_length=10)
    onboarded_at: Optional[datetime] = None

    @field_validator("onboarded_at")
    @classmethod
    def validate_onboarded_at(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return v
        from datetime import timezone, timedelta
        from app.config import settings
        
        # Ensure UTC timezone
        dt = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        
        # Reject future dates > 5 minutes
        if dt > now + timedelta(minutes=5):
            raise ValueError("onboarded_at cannot be more than 5 minutes in the future")
            
        # Reject dates earlier than PILOT_START_DATE
        pilot_start = datetime.fromisoformat(settings.PILOT_START_DATE).replace(tzinfo=timezone.utc)
        if dt < pilot_start:
            raise ValueError(f"onboarded_at cannot be earlier than pilot start date ({settings.PILOT_START_DATE})")
            
        return v

class VOPRFFarmerRegisterRequest(BaseModel):
    pilot_id: str = Field("kenya-pilot", description="Pilot identifier")
    key_id: str = Field("ke-pilot-v1", description="Evaluator Key ID")
    token_b64: str = Field(..., description="Base64-encoded 64-byte finalized VOPRF token T")
    gender: Optional[GenderType] = "U"
    age_band: Optional[AgeBandType] = "U"
    county_code: Optional[str] = "047"
    role: Optional[Literal["onboarder", "primary", "contributor"]] = "contributor"
    idempotency_key: str = Field(..., description="Unique client idempotency UUID")
    onboarded_at: Optional[datetime] = None

class VOPRFFarmerRegisterResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    entity_id: str
    is_new_entity: bool
    partner_association_status: str

class StatusAcceptedResponse(BaseModel):
    status: Literal["accepted"] = "accepted"

class UploadResponse(BaseModel):
    rows_received: int
    rows_accepted: int
    rows_rejected: int

class PartnerSummaryResponse(BaseModel):
    partner_id: str
    farmers_sent: int
    first_to_onboard: int
    already_known: int

class PartnerLinkDetail(BaseModel):
    partner_id: str
    status: str
    linked_at: datetime

class AdminLookupResponse(BaseModel):
    farmer_id: int
    created_at: datetime
    partners: List[PartnerLinkDetail]
