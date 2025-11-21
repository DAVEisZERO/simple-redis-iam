import urllib.parse

from fastapi import APIRouter, status, HTTPException, Request
from fastapi.responses import RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.services.redis_service import store_in_redis, get_from_redis, remove_from_redis, store_session_redis, find_in_redis, remove_otp_from_redis
from app.services.oauth2_opaque_token import generate_opaque_token, hash_password
from app.services.confirmation_service import validate_auth_code, reset_password_email, authentication_email
from app.schemas.user import User,InsecureUser, AuthUser, UserSession, StoreUser
from app.schemas.simple_requests import EmailRequest,StatusRequest
from app.utils.utils import create_user_id
from app.logging.confg_logging import LOGGER

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
        Vulnerabilities: No rate limiting, no email verification, role escalation possible, plaintext password storage, no logging, broken access control

################################################################################
"""


# configure rate limit
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(tags=["Entrypoints"])

### ALMOST SECURE ###
@router.post("/signup/", status_code=status.HTTP_202_ACCEPTED, response_model=StatusRequest)
@limiter.limit("2/day")
def store_user(request: Request, user: User):
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("auth_request", user=user.email, ip=client_ip)

    if find_in_redis("user", user.email):
            user_stored = StoreUser(**get_from_redis(username=user.email))
            if user_stored.verified == True:
                LOGGER.warning("auth_failed", user=user.email, ip=client_ip, details="User already exists")
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail="User already exists")
        
    email_status= authentication_email(to_email=user.email, subject="Please confirm your email")

    if email_status == True:
        user.id = create_user_id()
        store_user = StoreUser(id=user.id, name=user.name, email=user.email, password=hash_password(user.password), role="user")
        store_in_redis(user.email, store_user.model_dump_json())
        LOGGER.info("auth_email_sent", user=user.email, ip=client_ip)
        return StatusRequest(status="Confirmation Email sent successfully")
    else:
        LOGGER.warning("auth_failed", user=user.email, ip=client_ip, details="Error sending Confirmation Email")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending Confirmation Email")
    
### MORE SECURE OPTION ########################## TODO: clean up
@router.get("/verify/", status_code=status.HTTP_308_PERMANENT_REDIRECT, response_class=RedirectResponse)
@limiter.limit("3/hour")
def handle_email_verification(
    request: Request,
    token: str,
    type: str,
    redirect_to: str
):
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("otp_verification_request", ip=client_ip)
    
    validated_obj = validate_auth_code(token=token)
    if validated_obj != None:
        if type == "password":
            response = RedirectResponse(url=redirect_to, status_code=status.HTTP_308_PERMANENT_REDIRECT)
            LOGGER.info("verification_password_success", user=validated_obj.email, ip=client_ip)
            return response

        remove_otp_from_redis(id=token)
        # Mark user as identidy verified
        user = StoreUser(**get_from_redis(username=validated_obj.email))
        user.verified = True
        store_in_redis(user.name, user.model_dump_json())
        # Log in the user by creating a session token
        token = generate_opaque_token()
        store_session_redis(validated_obj.email, token)

        #### FRAGMENT WITH TOKENS ####
        user_data=AuthUser(id=create_user_id(), email=user.email, name=user.name)
        user_json_string = user_data.model_dump_json()
        encoded_user = urllib.parse.quote(user_json_string)

        # We use RedirectResponse to send the user to the frontend back.
        fragment = f"access_token={token}&user={encoded_user}&refresh_token=d3m0&expires_in=3&token_type=bearer" #TODO: refresh token, type, expires in
        new_reedirect_to = f"{redirect_to}#{fragment}"

        LOGGER.info("auth_success", user=user.email, ip=client_ip)
        LOGGER.info("token_generated", user=user.email, ip=client_ip, token=token)
        response = RedirectResponse(url=new_reedirect_to, status_code=status.HTTP_308_PERMANENT_REDIRECT)

        return response
    else:
        LOGGER.warning("auth_failed", ip=client_ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid OTP code."
        )
    
### CHECK & SEND PASSOWRD RESET LINK TO USER ##########################
@router.post("/forgotpassword/", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/hour")
def forgot_password(request: Request, user: EmailRequest):
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("password_change_requested", user=user.email, ip=client_ip)

    if not find_in_redis("user", user.email): #SECURITY: Check if user exists
        LOGGER.warning("password_change_failed", user=user.email, ip=client_ip)
        raise HTTPException(status_code=400, detail="User does not exist")
    
    if reset_password_email(to_email=user.email, subject="Reset your password") == False:
        LOGGER.warning("password_change_failed", user=user.email, ip=client_ip)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending Password Reset Email")
    
    LOGGER.info("password_change_success", user=user.email, ip=client_ip)
    remove_from_redis(username=user.email)

    return {"message": "Password Reset Email sent successfully"}


########################################################################################################################################
###                                                   INSECURE CODE                                                                  ###
########################################################################################################################################

### 1. A01:2021 – Broken Access Control: Insecure User Payload schema --> role escalation ###
### 2. A07:2021 – Identification and Authentication Failures: email/user not authenticated --> identity spoofing ###
### 3. A02:2021 – Cryptographic Failures: store password as hash, never store the real password
### 4. A04:2021 – Insecure Design: No Rate Limiting the critical endpoint from external requests. Vulnerable to DoS and brute force attacks.
### 5. A09:2021 – Security Logging and Monitoring Failures: No logging of critical actions such as login, signup, password changes, etc.
#######################################################################################################################
@router.post("/signupInsecure/", status_code=status.HTTP_201_CREATED, response_model=UserSession)
def store_user(request: Request, user: InsecureUser):
    if find_in_redis("user", user.email):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="User already exists")
    
    user.id = create_user_id()
    store_in_redis(user.name, user.model_dump_json())

    # Generate token and store session
    token = generate_opaque_token()
    store_session_redis(user.email, token)
    authuser = AuthUser(id=user.id , email=user.email, name=user.name)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )