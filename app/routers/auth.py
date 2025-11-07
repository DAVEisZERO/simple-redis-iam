from typing import Union, Annotated
import urllib.parse
import uuid

from fastapi import APIRouter, Depends, status, HTTPException, Response
from fastapi.responses import RedirectResponse
from fastapi.security.oauth2 import OAuth2PasswordRequestForm

from app.services.redis_service import store_in_redis, get_from_redis, remove_from_redis, get_session_redis, store_session_redis, find_in_redis
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, generate_opaque_token
from app.services.confirmation_service import authentication_email, validate_auth_code
from app.schemas.user import User, AuthUser, UserSession
from app.utils.utils import create_user_id

router = APIRouter(tags=["Authentication"])

@router.post("/login/")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user: AuthUser = get_from_redis(username=form_data.username)
    if user == None:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    else: 
        user_psswrd = user.get("password")
        sent_password = form_data.password

        if not user_psswrd == sent_password:
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        else:
            token = generate_opaque_token(user.get("password"))
            store_session_redis(form_data.username, token)
            ##TODO: Multiple session tokens can be created for the same user (signup + login problem)
    
    return UserSession(
        access_token=token,
        token_type="bearer",
        user=user
    )

### NO AUTHENTICATION OPITON (LESS SECURE) ##########################
@router.post("/signup/", status_code=status.HTTP_201_CREATED)
def store_user(user: User):
    if find_in_redis("user", user.email):
        raise HTTPException(status_code=400, detail="User already exists")
    store_in_redis(user)

    # Generate token and store session
    token = generate_opaque_token(user.password)
    store_session_redis(user.email, token)
    authuser = AuthUser(id=create_user_id() , email=user.email, name=user.name)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )

### MORE SECURE OPTION ########################## TODO: clean up
@router.get("/verify/")
def handle_email_verification(
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
    print("--- Verification Request Received ---")
    print(f"Token: {token}")
    print(f"Type: {type}")
    print(f"Redirect URL: {redirect_to}")
    
    validated_obj = validate_auth_code(token=token)
    if validated_obj != None:

        # Log in the user by creating a session token
        user = get_from_redis(username=validated_obj.email)
        token = generate_opaque_token(user.get("password"))
        store_session_redis(validated_obj.email, token)

        print(f"User verified. Redirecting to: {redirect_to}")

        #### INSECURE: FRAGMENT WITH TOKENS ####
        user_data=AuthUser(id=123456, email=user.get("email"), name=user.get("name"))
        user_json_string = user_data.model_dump_json()
        encoded_user = urllib.parse.quote(user_json_string)

        # The `redirect_to` parameter implies the desired action is a redirect.
        # We use RedirectResponse to send the user to that URL.
        fragment = f"access_token={token}&user={encoded_user}&refresh_token=d3m0&expires_in=3&token_type=bearer" #TODO: refresh token, type, expires in
        print(f"Redirect fragment: {fragment}")
        new_reedirect_to = f"{redirect_to}#{fragment}"
         #### INSECURE: FRAGMENT WITH TOKENS ####

        response = RedirectResponse(url=new_reedirect_to)

        return response
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code."
        )