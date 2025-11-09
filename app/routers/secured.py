from typing import Annotated

from fastapi import  Depends, FastAPI,  HTTPException, status, APIRouter, Depends, status, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware

from app.schemas.user import User, AuthUser, UserSession
from app.routers import auth
from app.services.redis_service import get_from_redis, remove_from_redis, get_session_redis, change_username_redis, change_password_redis
from app.services.oauth2_opaque_token import OAUTH2_SCHEME

router = APIRouter(tags=["Authenticated"])

@router.post("/changeName/", response_model=UserSession, status_code=status.HTTP_202_ACCEPTED)
def change_user_name(user: AuthUser, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    user_email = get_session_redis(token)
    
    if user_email != None:
        change_username_redis(email=user_email, new_username=user.name)
    else:                      
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    new_user = User(**get_from_redis(username=user_email))
    authuser = AuthUser(id=new_user.id , email=new_user.email, name=new_user.name)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )

@router.post("/changePassword/", response_model=UserSession, status_code=status.HTTP_202_ACCEPTED)
def change_user_password(user: User, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    user_email = get_session_redis(token)
    #print("result:", user_email)

    if user_email != None:
        change_password_redis(email=user_email, new_psswrd=user.password)
    else:                      
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    new_user = User(**get_from_redis(username=user_email))
    authuser = AuthUser(id=new_user.id , email=new_user.email, name=new_user.name)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )

@router.get("/")
def read_root():
    return {"message": "Hello, HTTPS world!"}



### SECURE ###

@router.post("/users/remove/", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
def delete_user(user: AuthUser, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    result = get_session_redis(token)
    
    if result != None:
        remove_from_redis(username=user.email, token=token)
        return {"Status": user.email + " deleted"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )