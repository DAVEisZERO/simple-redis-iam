from datetime import datetime

from pydantic import BaseModel

"""
################################################################################
###                                   DOCS                                   ###
################################################################################

Token Schema Module
------------------
Defines Pydantic models for authentication tokens and OTP (One-Time Password)
data structures. Provides standardized schemas for token responses and
temporary credential storage.

Classes:
    Token: OAuth2 token response schema for client authentication.
        Attributes: access_token (str), token_type (str)
        
    OTPData: One-time password data with expiration tracking.
        Attributes: email (str), code (str), expires_at (datetime)
        
    SecuritySettings: [NOT IMPLEMENTED] Security configuration for user accounts.
        Attributes: otp_configured (bool), secret (str)

################################################################################

"""

class Token(BaseModel):
    access_token: str
    token_type: str

class OTPData(BaseModel):
    email: str
    code: str
    expires_at: datetime
    
### NOT IMPLEMENTED YET ###
class SecuritySettings(BaseModel):
    otp_configured: bool
    secret: str
