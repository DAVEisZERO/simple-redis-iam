import pyotp 
import time
import string
import secrets
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone


# --- Configuration ---
OTP_LENGTH = 6
OTP_EXPIRE_MINUTES = 10  # Code is valid for 10 minutes

class OTPData(BaseModel):
    email: str
    code: str
    expires_at: datetime

def generate_otp(email: str, length: int = OTP_LENGTH) -> OTPData:
    """Generates a secure, digits-only OTP."""
    digits = string.digits

    otp_data = OTPData(
        email=email, 
        code="".join(secrets.choice(digits) for _ in range(length)), 
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
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
#print(generate_otp(email="dfsdffds@dsfsdf.de"))