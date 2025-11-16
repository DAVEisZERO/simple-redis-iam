from pydantic import BaseModel, field_validator
import re
from typing import Optional
from datetime import datetime

### Authenticated and stored user info ###
class AuthUser(BaseModel):
    id: str
    email: str
    name: Optional[str] = None
    list: Optional[str] = None
    role: Optional[str] = None


### RESPONSE SESSION SCHEMA FOR CLIENT ###
class UserSession(BaseModel):
    provider_token: Optional[str] = None
    provider_refresh_token: Optional[str] = None
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    expires_at: Optional[int] = None
    token_type: str
    user: AuthUser

class OTPData(BaseModel):
    email: str
    code: str
    expires_at: datetime

class StoreUser(BaseModel):
    id: Optional[str] = None
    name: str
    email: str
    password: str
    role: str
    verified: Optional[bool] = False
### COMMUNICATION SCHEMAS ###

class User(BaseModel):
    id: Optional[str] = None
    name: str
    email: str
    password: str
    #letterboxd: str

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        # 1. Check Length
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        # 2. Check Complexity (Optional but common)
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one digit')
        
        return v

class InsecureUser(BaseModel): ### A01:2021 – Broken Access Control ###
    id: Optional[str] = None
    name: str
    email: str
    password: str ## A07:2021 – Identification and Authentication Failures: no validation
    role: Optional[str] = "user"  # default role is 'user'

class EmailRequest(BaseModel):
    email: str

class UrlRequest(BaseModel):
    url: str

### NOT IMPLEMENTED YET ###
class SecuritySettings(BaseModel):
    otp_configured: bool
    secret: str

class Token(BaseModel):
    access_token: str
    token_type: str





