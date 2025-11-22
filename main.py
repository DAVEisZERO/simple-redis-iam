import uvicorn

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from asgi_correlation_id import CorrelationIdMiddleware
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import auth, entrypoints, secured
from app.config.settings import SETTINGS

"""
################################################################################
###                                   DOCS                                   ###
################################################################################

Entrypoints Router Module
------------------
Handles user registration, email verification, and password reset flows with
OAuth2 token-based authentication. Implements rate limiting, comprehensive
logging, and secure OTP-based verification. Provides both secure and insecure
endpoints for demonstration purposes.

Configuration:
    limiter: SlowAPI rate limiter with per-endpoint rate limits
    LOGGER: Structured logging for authentication events and security monitoring

Functions:
    store_user: [SECURE] Registers new user with email verification requirement.
        Input: request (Request), user (User)
        Returns: StatusRequest with confirmation email status
        Security: Rate limited (2/day), password hashing, email verification required
        Logging: Tracks signup attempts, email delivery, and security events
        
    handle_email_verification: [SECURE] Validates OTP token and marks user verified.
        Input: request (Request), token (str), type (str), redirect_to (str)
        Returns: RedirectResponse with session token in URL fragment
        Security: Rate limited (3/hour), OTP validation, session token generation
        Logging: Tracks verification attempts and successful authentications
        
    forgot_password: [SECURE] Initiates password reset workflow via email.
        Input: request (Request), user (EmailRequest)
        Returns: dict with status message
        Security: Rate limited (3/hour), user existence validation, OTP generation
        Logging: Tracks password reset requests and email delivery
        
    store_user_insecure: [INSECURE] Registers user without email verification.
        Input: request (Request), user (InsecureUser)
        Returns: UserSession with immediate token
        Vulnerabilities: No rate limiting, no email verification, role escalation possible,
                        plaintext password storage, no logging, broken access control

################################################################################
"""

origins = SETTINGS.allowed_origins

limiter = Limiter(key_func=get_remote_address, default_limits=["2/minute"])
app = FastAPI(
    title="Secure IAM with FastAPI and Redis",
    description="A secure Identity and Access Management (IAM) system built with FastAPI and Redis, focusing on best security practices.",
    version="1.0.0",
    docs_url=None,
    debug=False, 
)

# Add Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware) # Add SlowAPI Middleware for rate limiting
app.add_middleware(CorrelationIdMiddleware) # Add Correlation ID Middleware to identify requests, bette monitoring
# Arrange CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"], # Only allow necessary verbs
    allow_headers=["Authorization", "Content-Type"], # Restrict headers
)

@app.middleware("http")
async def add_content_security_policy(request: Request, call_next):
    response = await call_next(request)
    
    # 1. Create the Policy String
    # This says: "Only allow scripts/images/styles from my own server ('self').
    # Block EVERYTHING else (no external analytics, no CDNs, no iframes)."
    csp_policy = (
        "default-src 'self'; "          # Load assets only from my own domain
        "img-src 'self' data:; "        # Allow images from self and base64 (data:)
        "script-src 'self'; "           # STRICT: No external JS, no inline scripts
        "style-src 'self'; "            # CSS only from here
        "frame-ancestors 'none'; "      # Replaces X-Frame-Options: DENY
        "upgrade-insecure-requests;"    # Force browser to use HTTPS for all links
    )
    
    # 2. Stamp it on the response
    response.headers["Content-Security-Policy"] = csp_policy
    
    # 3. Keep the legacy header for very old browsers (optional but safe)
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    return response


app.include_router(auth.router, prefix="/api/v1/auth")
app.include_router(entrypoints.router, prefix="/api/v1/entrypoints")   
app.include_router(secured.router, prefix="/api/v1")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, ssl_certfile='./ssl_certs/example.com+5.pem', ssl_keyfile="./ssl_certs/./example.com+5-key.pem")


########################################################################################################################################
###                                                     INSECURE CODE                                                                ###
########################################################################################################################################

###  1. A05:2021 – Security Misconfiguration: CORS & general configurations for fastAPI app --> The Fix: Whitelist only the specific domains of the frontend applications
###  2. A04:2021 – Insecure Design: No Rate Limiting the critical endpoint from external requests. Vulnerable to DoS and brute force attacks.
###  3. A05:2021 – Security Misconfiguration: No security headers!
###  4. A05:2021 – Security Misconfiguration: docs are enabled in production, potentially leaking sensitive information.
###  5. A05:2021 – Security Misconfiguration: Debug is True in production. Gives too much information to attackers.
###  6. A02:2021 – Cryptographic Failures:Run application without TLS/SSL --> no confidentiality and integrity guarantess with the client
#######################################################################################################################

app_insecure = FastAPI(
    title="Secure IAM with FastAPI and Redis",
    description="A secure Identity and Access Management (IAM) system built with FastAPI and Redis, focusing on best security practices.",
    version="1.0.0",
    docs_url="/docs",
    debug=True,
)

origins = [
    "http://localhost:8100/",
    "http://localhost:8100",
    "http://localhost",
    "http://",   
    "http://127.0.0.1:8100",
]

# Arrange CORS settings
app_insecure.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # NOT-SECURE: Allow all origins
    allow_credentials=True,
    allow_methods=["*"], # NOT-SECURE: Allow all methods
    allow_headers=["*"], # # NOT-SECURE: Allow all headers
)

# if __name__ == "__main__":
#     uvicorn.run("main:app_insecure", host="0.0.0.0", port=8000,)

