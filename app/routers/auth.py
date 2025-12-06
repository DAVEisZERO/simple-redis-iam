from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.services.redis_service import get_from_redis,store_session_redis
from app.services.oauth2_opaque_token import generate_opaque_token, verify_password
from app.logging.confg_logging import LOGGER
from app.schemas.user import AuthUser, UserSession, StoreUser

"""
################################################################################
###                                   DOCS                                   ###
################################################################################

Authentication Router Module
------------------
Handles user login and session management with OAuth2 token-based authentication.
Implements rate limiting, comprehensive logging, and password verification using
secure Argon2 hashing. Provides both secure and insecure endpoints for
demonstration purposes.

Configuration:
    limiter: SlowAPI rate limiter configured to 5 requests per minute on login
    LOGGER: Structured logging for authentication events and security monitoring
    OAUTH2_SCHEME: FastAPI OAuth2PasswordBearer for token extraction

Functions:
    login: [SECURE] Authenticates user with credentials and generates session token.
        Input: request (Request), form_data (OAuth2PasswordRequestForm)
        Returns: UserSession with opaque token and user information
        Security: Rate limited (5/min), password hashing verification, comprehensive logging
        Logging: Captures login attempts, failures, and token generation with IP tracking
        
    loginInsecure: [INSECURE] Authenticates user with plaintext password comparison.
        Input: form_data (OAuth2PasswordRequestForm)
        Returns: UserSession with token and user data
        Vulnerabilities: No rate limiting, plaintext password storage, no logging,
                        No input validation, vulnerable to DoS and brute force attacks

################################################################################

"""

# configure rate limit
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(tags=["Authentication"])

@router.post("/login/", status_code=status.HTTP_202_ACCEPTED, response_model=UserSession)
@limiter.limit("5/minute") # Rate limiting to 5 requests per minute (A04:2021)
async def login(request: Request, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = StoreUser(**get_from_redis(username=form_data.username))
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("login_requested", user=user.email, ip=client_ip)   #Loggin of important transactions (A09:2021)

    if user == None:
        LOGGER.warning("login_failed", user=user.email, ip=client_ip, detaisl="Incorrect username") #Loggin of important transactions (A09:2021)
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incorrect username or password") # too general information is given for more security (A04:2021)
    else: 
        user_psswrd = user.password
        sent_password = form_data.password

        if not verify_password(attempt=sent_password, hash=user_psswrd):
            LOGGER.warning("login_failed", user=user.email, ip=client_ip, detaisl="Incorrect password")
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Incorrect username or password")
        else:
            token = generate_opaque_token()
            store_session_redis(form_data.username, token)
            LOGGER.info("login_success", user=user.email, ip=client_ip)
            LOGGER.info("token_generated", user=user.email, ip=client_ip)
            auth_user = AuthUser(id=user.id, email=user.email, name=user.name)
            ##TODO: Multiple session tokens can be created for the same user (signup + login problem) --> not secure, too much token
    
    return UserSession(
        access_token=token,
        token_type="bearer",
        user=auth_user
    )

########################################################################################################################################
###                                                      INSECURE CODE                                                               ###
########################################################################################################################################

###  1. A02:2021 – Cryptographic Failures: check hashed password
###  2. A04:2021 – Insecure Design: security before userfriendlyness. Not a good idea to give too many details on login failures.
###  3.A04:2021 – Insecure Design: No Rate Limiting the critical endpoint from external requests. Vulnerable to DoS and brute force attacks.
###  4. A09:2021 – Security Logging and Monitoring Failures: No logging of critical actions such as login, signup, password changes, etc.
#######################################################################################################################

@router.post("/loginInsecure/", status_code=status.HTTP_202_ACCEPTED, response_model=UserSession)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user: AuthUser = get_from_redis(username=form_data.username)
    if user == None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Username does not exist.")
    else: 
        user_psswrd = user.get("password")
        sent_password = form_data.password

        if not user_psswrd == sent_password: ### raw password are stored and vverified
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Incorrect password")
        else:
            token = generate_opaque_token()
            store_session_redis(form_data.username, token)
            ##TODO: Multiple session tokens can be created for the same user (signup + login problem) --> not secure, too much token
    
    return UserSession(
        access_token=token,
        token_type="bearer",
        user=user
    )

