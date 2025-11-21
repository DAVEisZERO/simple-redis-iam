import string
import secrets
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel

from app.config.settings import SETTINGS  
from app.schemas.token import OTPData


"""
################################################################################
###                                   DOCS                                   ###
################################################################################

OTP Service Module
------------------
Handles one-time password (OTP) generation and validation for authentication
purposes. Provides cryptographically secure OTP tokens with configurable
expiration times and timing-attack resistant validation.

Configuration:
    SETTINGS.otp_length: Length of generated OTP code in digits.
    SETTINGS.otp_expire_minutes: OTP expiration time in minutes.

Classes:
    OTPData: Pydantic model representing OTP data with email, code, and expiration.
        Attributes: email (str), code (str), expires_at (datetime)

Functions:
    generate_otp: Generates a cryptographically secure, digits-only OTP.
        Input: email (str), length (int, optional)
        Returns: OTPData object with generated code and expiration timestamp
        
    validate_otp_token: Validates an OTP token by checking expiration and code.
        Input: stored_otp (OTPData), request_otp (str)
        Returns: bool (True if valid and not expired, False otherwise)
        Security: Uses secrets.compare_digest to prevent timing attacks

################################################################################
"""

def generate_otp(email: str, length: int = SETTINGS.otp_length) -> OTPData:
    """Generates a secure, digits-only OTP."""
    digits = string.digits

    otp_data = OTPData(
        email=email, 
        code="".join(secrets.choice(digits) for _ in range(length)), 
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=SETTINGS.otp_expire_minutes)
    )

    return otp_data

def validate_otp_token(stored_otp:OTPData, request_otp: str) -> bool:

    # 2. Check if the OTP is expired
    if datetime.now(timezone.utc) > stored_otp.expires_at:
        return False
    
    # 3. Check if the OTP code is correct
    # Use secrets.compare_digest to prevent timing attacks
    if not secrets.compare_digest(stored_otp.code, request_otp):
        return False
    
    return True