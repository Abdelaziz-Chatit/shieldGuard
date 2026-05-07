from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any, Dict, List
from datetime import datetime
from enum import Enum


# ============= Auth Schemas =============

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ============= URL Analysis Schemas =============

class URLRequest(BaseModel):
    url: str = Field(..., min_length=5, max_length=2048)


class URLResponse(BaseModel):
    url: str
    score: float = Field(..., ge=0.0, le=1.0)
    is_phishing: bool
    verdict: str
    model_used: str
    cached: bool = False
    created_at: datetime


# ============= Network Analysis Schemas =============

class NetworkFeaturesRequest(BaseModel):
    features: Dict[str, float] = Field(..., description="Up to 78 CICIDS2017 feature names and values")


class NetworkResponse(BaseModel):
    score_cnn: float = Field(..., ge=0.0, le=1.0)
    score_if: float = Field(..., ge=0.0, le=1.0)
    is_malicious: bool
    verdict: str
    model_used: str
    created_at: datetime


# ============= File Analysis Schemas =============

class FileResponse(BaseModel):
    filename: str
    sha256: str
    size_bytes: int
    found_in_blacklist: bool
    blacklist_match: Optional[Dict[str, str]] = None
    score_if: Optional[float] = None
    verdict: str
    created_at: datetime


# ============= Alert Schemas =============

class AlertResponse(BaseModel):
    id: int
    type: str
    severity: str
    title: str
    description: Optional[str]
    source: Optional[str]
    score: Optional[float]
    model_used: Optional[str]
    resolved: bool
    resolved_at: Optional[datetime]
    created_at: datetime
    user_id: Optional[int]
    
    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    alerts: List[AlertResponse]
    total: int
    page: int
    limit: int


class AlertResolveRequest(BaseModel):
    notes: str = ""


# ============= Admin Schemas =============

class ModelStatusResponse(BaseModel):
    cnn_gru_loaded: bool
    char_cnn_loaded: bool
    if_loaded: bool
    errors: Dict[str, Optional[str]]


class StatsResponse(BaseModel):
    total_alerts: int
    alerts_today: int
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    total_scans: int
    scans_today: int
    threats_blocked: int
    model_status: ModelStatusResponse


class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int


class SignatureCreate(BaseModel):
    sha256: str = Field(..., regex="^[a-f0-9]{64}$")
    name: str = Field(..., max_length=255)
    severity: str
    category: str
    source: str


class SignatureResponse(BaseModel):
    sha256: str
    name: str
    severity: str
    category: str
    source: str
    added_at: datetime


class WhitelistCreate(BaseModel):
    type: str = Field(..., regex="^(url|ip|hash|process)$")
    value: str = Field(..., max_length=500)


class WhitelistResponse(BaseModel):
    id: int
    type: str
    value: str
    added_by: Optional[int]
    created_at: datetime
    
    class Config:
        from_attributes = True


class ConfigUpdate(BaseModel):
    key: str = Field(..., max_length=100)
    value: str


class BulkImportResponse(BaseModel):
    imported: int
    skipped: int
    errors: List[str]


# ============= WebSocket Schemas =============

class WSEvent(BaseModel):
    event_type: str
    severity: str
    title: str
    description: str
    source: Optional[str]
    score: Optional[float]
    timestamp: datetime


# ============= Generic Response Wrapper =============

class APIResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
