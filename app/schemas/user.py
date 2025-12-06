from pydantic import BaseModel, field_validator, Field
import re
from typing import Optional
from datetime import datetime

"""
################################################################################
###                                   DOCS                                   ###
################################################################################

User Schema Module
------------------
Defines Pydantic models for user authentication, storage, and API communication.
Includes validation for passwords with complexity requirements and secure user
data structures for different contexts.

Classes:
    AuthUser: Represents authenticated and stored user information.
        Attributes: id (str), email (str), name (Optional[str]), list (Optional[str]), role (Optional[str])
        
    UserSession: Response schema for client session data including tokens.
        Attributes: provider_token, provider_refresh_token, access_token, refresh_token, 
                    expires_in, expires_at, token_type, user (AuthUser)
        
    StoreUser: User data model for storage with verification status.
        Attributes: id (Optional[str]), name (str), email (str), password (str), role (str), verified (bool)
        
    User: User communication schema with password validation.
        Attributes: id (Optional[str]), name (str), email (str), password (str)
        Validators: validate_password (minimum 8 chars, uppercase letter, digit required)
        
    InsecureUser: [INSECURE] User model without validation, vulnerable to injection and weak passwords.
        Attributes: id (Optional[str]), name (str), email (str), password (str), role (default 'user')

################################################################################

"""

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

class StoreUser(BaseModel):
    id: Optional[str] = None
    name: str
    email: str
    password: str
    role: str
    verified: Optional[bool] = False
### COMMUNICATION SCHEMAS ###

class User(BaseModel): # User schema with fields validation (A01;2021, A03:2021), role atribute removed for frontend interface/communication
    id: Optional[str] = None
    name: str = Field(pattern=r"^[A-Z][a-zA-Z\s\-\']*$")
    email: str = Field(pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
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


########################################################################################################################################
###                                                      INSECURE CODE                                                               ###
########################################################################################################################################

### 1. A01:2021 – Broken Access Control: role escalation
### 2. A07:2021 – Identification and Authentication Failures: no validation. Permits default, weak, or well-known passwords, such as "Password1" or "admin/admin".
### 3. A03:2021 – Injection: No validation or sanitization of user inputs, leading to potential injection attacks.
#######################################################################################################################
class InsecureUser(BaseModel): 
    id: Optional[str] = None
    name: str
    email: str
    password: str 
    role: Optional[str] = "user"  # default role is 'user'



