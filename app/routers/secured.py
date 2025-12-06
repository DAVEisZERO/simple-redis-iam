import re
import requests 
from typing import Annotated

from fastapi import  Depends, HTTPException, status, APIRouter, Depends, status, HTTPException, Request

from app.logging.confg_logging import LOGGER
from app.schemas.user import User, AuthUser, UserSession, StoreUser, InsecureUser
from app.schemas.simple_requests import UrlRequest
from app.services.redis_service import get_from_redis, remove_from_redis, get_session_redis, change_username_redis, change_password_redis, find_in_redis, insecure_redis_set_user
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, hash_password


"""
################################################################################
###                                   DOCS                                   ###
################################################################################

Secured Router Module
------------------
Handles authenticated user operations including profile management, password
changes, and secure URL validation. Implements OAuth2 token-based authentication
with comprehensive logging and error handling.

Configuration:
    OAUTH2_SCHEME: FastAPI OAuth2PasswordBearer scheme for token extraction
    LOGGER: Structured logging for security events and user actions

Functions:
    change_user_name: [SECURE] Updates authenticated user's display name.
        Input: request (Request), user (AuthUser), token (str via OAuth2)
        Returns: UserSession with updated user information
        Security: Validates session token before name update
        
    change_user_password: [SECURE] Updates authenticated user's password with hashing.
        Input: request (Request), user (User), token (str via OAuth2)
        Returns: UserSession with updated credentials
        Security: Validates session token and hashes password before storage
        
    redirect_admin: [SECURE] Validates and fetches Letterboxd list URLs.
        Input: request (UrlRequest), token (str via OAuth2)
        Returns: dict with URL validation status
        Security: Strict regex pattern validation and User-Agent headers
        
    delete_user: [SECURE] Removes authenticated user from system.
        Input: user (AuthUser), token (str via OAuth2)
        Returns: dict with deletion confirmation
        Security: Session validation required before deletion
        
    redirect_admin (insecure): [INSECURE] No URL validation, vulnerable to SSRF attacks.
    
    delete_user (insecure): [INSECURE] No proper OAuth2 dependency, broken access control.

################################################################################
"""


router = APIRouter(tags=["Authenticated"])

@router.post("/changeName/", response_model=UserSession, status_code=status.HTTP_202_ACCEPTED)
def change_user_name(request: Request, user: AuthUser, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("name_change_requested", user=user.email, ip=client_ip)

    user_email = get_session_redis(token)
    if user_email != None:
        change_username_redis(email=user_email, new_username=user.name)
    else:             
        LOGGER.warning("name_change_failed", user=user.email, ip=client_ip)         
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    new_user = StoreUser(**get_from_redis(username=user_email))
    authuser = AuthUser(id=new_user.id , email=new_user.email, name=new_user.name)
    LOGGER.info("name_change_success", user=user.email, ip=client_ip)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )

@router.post("/changePassword/", response_model=UserSession, status_code=status.HTTP_202_ACCEPTED)
def change_user_password(request: Request, user: User, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("password_change_requested", user=user.email, ip=client_ip)

    user_email = get_session_redis(token)

    if user_email != None:
        change_password_redis(email=user_email, new_psswrd=hash_password(user.password))
    else:              
        LOGGER.warning("password_change_failed", user=user.email, ip=client_ip)          
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    new_user = User(**get_from_redis(username=user_email))
    authuser = AuthUser(id=new_user.id , email=new_user.email, name=new_user.name)
    LOGGER.info("password_change_success", user=user.email, ip=client_ip)

    return UserSession(
        access_token=token,
        token_type="bearer",
        user=authuser
    )

@router.post("/fetchsecure/")
def redirect_admin(request: Request, url_obj: UrlRequest, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    user_email = get_session_redis(token)
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("validate_list_requested", user=user_email, ip=client_ip)

    if user_email == None:                  
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    pattern = r"^https://letterboxd\.com/([^/]+)/list/([^/]+)/?$" # Strict regex pattern for Letterboxd list URLs (A10:2021)

    target_url = url_obj.url
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
        LOGGER.info("validate_list_success", user=user_email, ip=client_ip)
        return {
            "status": True, 
            "url": target_url  # The HTML content
        }
        
    elif check_response.status_code == 404:
        LOGGER.warning("validate_list_failed", user=user_email, ip=client_ip)    
        raise HTTPException(status_code=check_response.status_code, detail="List not found in Letterboxd.")
        
    else:
        LOGGER.warning("validate_list_failed", user=user_email, ip=client_ip) 
        raise HTTPException(status_code=check_response.status_code, detail="URL is not accessible")

    
########################################################################################################################################
###                                                      INSECURE CODE                                                               ###
########################################################################################################################################

### 1. A10:2021 – Server-Side Request Forgery (SSRF): user able to fetch critical information --> NO VALIDATION OF URL FORMAT
#######################################################################################################################
@router.post("/fetchinsecure/")
def redirect_admin(request: Request, url_obj: UrlRequest,token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    user_email = get_session_redis(token)
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("validate_list_requested", user=user_email, ip=client_ip)

    if user_email == None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    url = url_obj.url
    print("Checking URL: " + url)
    check_response = requests.get(url)  #GET http://127.0.0.1:6379 --> blind-SSRF to check the backend stack 
    if check_response.status_code == 200:
        return {
            "status": True, 
            "response": check_response.request # The HTML content
        }
    else:
        raise HTTPException(status_code=check_response.status_code, detail="URL is not accessible")
  
### 1. A01:2021 – Broken Access Control: Authenticatino Token not validated & no schema imposure.
#######################################################################################################################
@router.post("/changeNameInsecure/", status_code=status.HTTP_202_ACCEPTED)
def change_user_name(request: Request, user: InsecureUser,):
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("name_change_requested", user=user.email, ip=client_ip)

    if find_in_redis("user", user.email):
        change_username_redis(email=user.email, new_username=user.name)
    else:             
        LOGGER.warning("name_change_failed", user=user.email, ip=client_ip)         
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    new_user = StoreUser(**get_from_redis(username=user.email))
    LOGGER.info("name_change_success", user=user.email, ip=client_ip)

    return {"Status": f"User name changed to {user.name} for user {user.email}"}
