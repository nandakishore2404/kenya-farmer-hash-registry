from datetime import datetime
from typing import Literal, Optional, List
from pydantic import BaseModel, Field

GenderType = Literal["F", "M", "U"]
AgeBandType = Literal["<18", "18-24", "25-34", "35-44", "45-54", "55-64", "65+", "U"]

class FarmerRegisterRequest(BaseModel):
    hash: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$", description="Incoming partner HMAC-SHA256 hash")
    gender: GenderType
    age_band: AgeBandType
    county_code: str = Field(..., min_length=1, max_length=10)
    onboarded_at: Optional[datetime] = None

class StatusAcceptedResponse(BaseModel):
    status: Literal["accepted"] = "accepted"

class UploadResponse(BaseModel):
    rows_received: int
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
