from typing import Annotated
import requests
import re

from fastapi import  Depends, FastAPI,  HTTPException, status, APIRouter, Depends, status, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware

from app.schemas.user import User, AuthUser, UserSession,  UrlRequest
from app.routers import auth
from app.services.redis_service import get_from_redis, remove_from_redis, get_session_redis, change_username_redis, change_password_redis, find_in_redis
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, hash_password

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
        change_password_redis(email=user_email, new_psswrd=hash_password(user.password))
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


### NO-SECURITY ### 
# A10:2021 – Server-Side Request Forgery (SSRF): user able to fetch critical data --> NO VALIDATION OF URL FORMAT
@router.post("/fetchinsecure/")
def redirect_admin(request: UrlRequest,token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    user_email = get_session_redis(token)

    if user_email == None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    url = request.url
    print("Checking URL: " + url)
    check_response = requests.get(url)
    #file://C:\Windows\System32\drivers\etc\hosts
    #file://C:\Windows\win.ini
    #GET http://127.0.0.1:6379 --> blind-SSRF to check the type of server
    if check_response.status_code == 200:
        return {"status": "valid", "url": url}
    else:
        raise HTTPException(status_code=check_response.status_code, detail="URL is not accessible")

### SECURE DEMO TO CHECK IF A LETTERBOXD URL IS VALID AND EXISTS ### --> VALIDATION OF URL FORMAT
@router.post("/fetchsecure/")
def redirect_admin(request: UrlRequest, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    user_email = get_session_redis(token)
    #print("result:", user_email)

    if user_email == None:                  
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


    pattern = r"^https://letterboxd\.com/([^/]+)/list/([^/]+)/?$"

    target_url = request.url
    print("Checking URL: " + target_url)
    # 2. INSPECT THE URL
    if not re.match(pattern, target_url):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid Letterboxd list URL format.")
    
    # 3. FETCH THE URL
    # Set a User-Agent so Letterboxd knows it's a script/browser
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; MyListFetcher/1.0)'}
    check_response = requests.get(target_url, headers=headers, timeout=10)
    
    # 4. CHECK RESPONSE STATUS
    if check_response.status_code == 200:
        return {
            "status": True, 
            "url": target_url  # The HTML content
        }
    elif check_response.status_code == 404:
        raise HTTPException(status_code=check_response.status_code, detail="List not found in Letterboxd.")
        
    else:
        raise HTTPException(status_code=check_response.status_code, detail="URL is not accessible")


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
    

### IN-SECURE ### 
# 1. A01:2021 – Broken Access Control: Authenticatino Token not validated & no schema imposure.

@router.post("/users/remove/", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
def delete_user(user: AuthUser, token: str):
    
    if find_in_redis() != False:
        remove_from_redis(username=user.email, token=token)
        return {"Status": user.email + " deleted"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )