from pydantic import BaseModel
from typing import Optional

class User(BaseModel):
    name: str
    email: str
    password: str
    #letterboxd: str

class Token(BaseModel):
    access_token: str
    token_type: str


class AuthUser(BaseModel):
    # Define fields for AuthUser based on your requirements
    id: int
    email: str
    name: Optional[str] = None
    list: Optional[str] = None
    # Add more fields as needed

class UserSession(BaseModel):
    provider_token: Optional[str] = None
    provider_refresh_token: Optional[str] = None
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    expires_at: Optional[int] = None
    token_type: str
    user: AuthUser

class SecuritySettings(BaseModel):
    otp_configured: bool
    secret: str