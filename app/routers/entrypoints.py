from typing import Union, Annotated
import urllib.parse
import uuid

from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.services.redis_service import store_in_redis, get_from_redis, remove_from_redis, get_session_redis, store_session_redis, find_in_redis
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, generate_opaque_token, hash_password
from app.services.confirmation_service import authentication_email, validate_auth_code, reset_password_email
from app.schemas.user import User,InsecureUser, AuthUser, UserSession,EmailRequest, StoreUser
from app.utils.utils import create_user_id

# configure rate limit
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(tags=["Entrypoints"])


### IN-SECURE ###
# 1. A01:2021 – Broken Access Control: Insecure User Payload schema --> role escalation ###
# 2. A07:2021 – Identification and Authentication Failures: email/user not authenticated --> identity spoofing ###
# 3. A02:2021 – Cryptographic Failures: store password as hash, never store the real password
# 4. A04:2021 – Insecure Design: No Rate Limiting the critical endpoint from external requests. Vulnerable to DoS and brute force attacks.
@router.post("/signupInsecure/", status_code=status.HTTP_201_CREATED, response_model=UserSession)
def store_user(request: Request, user: InsecureUser):
    if find_in_redis("user", user.email):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="User already exists")
    
    user.id = create_user_id()
    store_in_redis(user.name, user.model_dump_json())

    # Generate token and store session
    token = generate_opaque_token(user.password)
    store_session_redis(user.email, token)
    authuser = AuthUser(id=user.id , email=user.email, name=user.name)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )

### ALMOST SECURE ###
@router.post("/signup/", status_code=status.HTTP_201_CREATED, response_model=UserSession)
@limiter.limit("2/day")
def store_user(request: Request, user: User):
    if find_in_redis("user", user.email):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="User already exists")
    
    user.id = create_user_id()
    store_user = StoreUser(id=user.id, name=user.name, email=user.email, password=hash_password(user.password), role="user")
    store_in_redis(user.email, store_user.model_dump_json())

    # Generate token and store session
    token = generate_opaque_token(user.password)
    store_session_redis(user.email, token)
    authuser = AuthUser(id=user.id , email=user.email, name=user.name)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )

### MORE SECURE OPTION ########################## TODO: clean up
@router.get("/verify/", status_code=status.HTTP_308_PERMANENT_REDIRECT, response_class=RedirectResponse)
@limiter.limit("3/hour")
def handle_email_verification(
    request: Request,
    token: str,
    type: str,
    redirect_to: str
):
    """
        Handles an email verification link, just like the Supabase URL structure.
        
        This endpoint captures the token, type, and redirect URL.
        
        In a real-world application, this is where you would:
        1.  Look up the 'token' in your database.
        2.  Verify it's valid and hasn't expired.
        3.  Mark the user's email as 'verified'.
        4.  Delete the token so it can't be reused.
    """
    # print("--- Verification Request Received ---")
    # print(f"Token: {token}")
    # print(f"Type: {type}")
    # print(f"Redirect URL: {redirect_to}")
    
    validated_obj = validate_auth_code(token=token)
    if validated_obj != None:
        if type == "password":
            print("Email verification successful.")
            response = RedirectResponse(url=redirect_to, status_code=status.HTTP_308_PERMANENT_REDIRECT)
            return response

        # Mark user as identidy verified
        user = StoreUser(**get_from_redis(username=validated_obj.email))
        user.verified = True
        store_in_redis(user.name, user.model_dump_json())
        # Log in the user by creating a session token
        token = generate_opaque_token(user.password)
        store_session_redis(validated_obj.email, token)

        print(f"User verified. Redirecting to: {redirect_to}")

        #### INSECURE: FRAGMENT WITH TOKENS ####
        user_data=AuthUser(id=create_user_id(), email=user.email, name=user.name)
        user_json_string = user_data.model_dump_json()
        encoded_user = urllib.parse.quote(user_json_string)

        # The `redirect_to` parameter implies the desired action is a redirect.
        # We use RedirectResponse to send the user to that URL.
        fragment = f"access_token={token}&user={encoded_user}&refresh_token=d3m0&expires_in=3&token_type=bearer" #TODO: refresh token, type, expires in
        print(f"Redirect fragment: {fragment}")
        new_reedirect_to = f"{redirect_to}#{fragment}"
         #### INSECURE: FRAGMENT WITH TOKENS ####

        response = RedirectResponse(url=new_reedirect_to, status_code=status.HTTP_308_PERMANENT_REDIRECT)

        return response
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid OTP code."
        )
    
### CHECK & SEND PASSOWRD RESET LINK TO USER ##########################
@router.post("/forgotpassword/", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/hour")
def forgot_password(request: Request, user: EmailRequest):

    print("Forgot password request for email:", user.email)
    if not find_in_redis("user", user.email): #SECURITY: Check if user exists
        raise HTTPException(status_code=400, detail="User does not exist")
    
    #TODO: remove user account
    if reset_password_email(to_email=user.email, subject="Reset your password") == False:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending Password Reset Email")
    
    remove_from_redis(username=user.email)

    return {"message": "Password Reset Email sent successfully"}