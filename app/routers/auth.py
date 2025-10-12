from typing import Union, Annotated

from fastapi import APIRouter, Depends, status, HTTPException, Response
from fastapi.security.oauth2 import OAuth2PasswordRequestForm

from app.services.redis_service import store_in_redis, get_from_redis, remove_from_redis, get_session_redis, store_session_redis, find_in_redis
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, generate_opaque_token
from app.schemas.user import User, AuthUser, UserSession

router = APIRouter(tags=["Authentication"])

@router.post("/login/")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = get_from_redis(username=form_data.username)
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
        user=AuthUser(id=123456, email=user.get("email"), name=user.get("name"))
    )


@router.post("/signup/", status_code=status.HTTP_201_CREATED)
def store_user(user: User):
    if find_in_redis("user", user.email):
        raise HTTPException(status_code=400, detail="User already exists")
    store_in_redis(user)

    # Generate token and store session
    token = generate_opaque_token(user.password)
    store_session_redis(user.email, token)
    authuser = AuthUser(id=123456, email=user.email, name=user.name)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )