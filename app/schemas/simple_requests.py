from pydantic import BaseModel

"""
################################################################################
###                                   DOCS                                   ###
################################################################################

Simple Requests Schema Module
------------------
Defines Pydantic models for basic request payloads used across API endpoints.
Provides standardized input validation for common request types.

Classes:
    EmailRequest: Request schema for email-based operations.
        Attributes: email (str)
        
    UrlRequest: Request schema for URL-based operations.
        Attributes: url (str)

################################################################################
"""

class EmailRequest(BaseModel):
    email: str

class UrlRequest(BaseModel):
    url: str

class StatusRequest(BaseModel):
    status: str