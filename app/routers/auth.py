from typing import Union, Annotated
import urllib.parse
import uuid

from fastapi import APIRouter, Depends, status, HTTPException, Response
from fastapi.responses import RedirectResponse
from fastapi.security.oauth2 import OAuth2PasswordRequestForm

from app.services.redis_service import store_in_redis, get_from_redis, remove_from_redis, get_session_redis, store_session_redis, find_in_redis
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, generate_opaque_token
from app.services.confirmation_service import authentication_email, validate_auth_code, reset_password_email
from app.schemas.user import User, AuthUser, UserSession,EmailRequest
from app.utils.utils import create_user_id

router = APIRouter(tags=["Authentication"])

@router.post("/login/")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user: AuthUser = get_from_redis(username=form_data.username)
    if user == None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incorrect username or password")
    else: 
        user_psswrd = user.get("password")
        sent_password = form_data.password

        if not user_psswrd == sent_password:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Incorrect username or password")
        else:
            token = generate_opaque_token(user.get("password"))
            store_session_redis(form_data.username, token)
            ##TODO: Multiple session tokens can be created for the same user (signup + login problem) --> not secure, too much token
    
    return UserSession(
        access_token=token,
        token_type="bearer",
        user=user
    )

