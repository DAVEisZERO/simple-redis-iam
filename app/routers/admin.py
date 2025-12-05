import re
import requests 
from typing import Annotated

from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import  Depends, HTTPException, status, APIRouter, Depends, status, HTTPException, Request

from app.logging.confg_logging import LOGGER
from app.schemas.user import User, AuthUser, UserSession, StoreUser, InsecureUser
from app.schemas.simple_requests import UrlRequest
from app.services.redis_service import get_from_redis, store_in_redis, get_session_redis, remove_from_redis, change_password_redis, find_in_redis, insecure_redis_set_user
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, hash_password

# configure rate limit
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(tags=["Administration"])

@router.post("/createUser/", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/day")
def create_user_insecure(request: Request, user: User, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    client_ip = request.client.host if request.client else "unknown"
    admin_email = get_session_redis(token)
    LOGGER.info("admin_create_requested", user=admin_email, ip=client_ip)

        
    if admin_email != None:
        if get_from_redis(admin_email.email).get("role") == "admin":
            store_user = StoreUser(id=user.id, name=user.name, email=user.email, password=hash_password(user.password), role="user")
            store_in_redis(user.email,store_user.model_dump_json())
            LOGGER.info("admin_create_success", user=admin_email, ip=client_ip)
            return {"Status": f"Insecure user {user.email} created with role {user.role}"}
    else:
        LOGGER.warning("admin_change_failed", user=admin_email, ip=client_ip)   
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/removeUser/", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/day")
def create_user_insecure(request: Request, user: User, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    client_ip = request.client.host if request.client else "unknown"
    admin_email = get_session_redis(token)
    LOGGER.info("admin_delete_requested", user=admin_email, ip=client_ip)
        
    if admin_email != None:
        if get_from_redis(admin_email.email).get("role") == "admin":
            remove_from_redis(user.email)
            LOGGER.info("admin_delete_success", user=admin_email, ip=client_ip)
            return {"Status": f"Insecure user {user.email} created with role {user.role}"}
    else:
        LOGGER.warning("admin_delete_failed", user=admin_email, ip=client_ip)   
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


########################################################################################################################################
###                                                     INSECURE CODE                                                                ###
########################################################################################################################################

### 1. A01:2021 – Broken Access Control: Authenticatino Token not validated & no schema imposure.
### 2. A03:2021 – Injection: Redis command is constructed dynamically, leading to potential injection attacks.
### 3. A04:2021 – Insecure Design: No Rate Limiting the critical endpoint from external requests. Vulnerable to DoS and brute force attacks.
### 4. A09:2021 – Security Logging and Monitoring Failures: No logging of critical actions such as login, signup, password changes, etc.
#######################################################################################################################
@router.post("/createUserInsecure/", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
def create_user_insecure(user: InsecureUser, token: str):
    admin_email  = get_session_redis(token)
        
    if admin_email  != None:
        if get_from_redis(user.email).get("role") == "admin":
            store_user = StoreUser(id=user.id, name=user.name, email=user.email, password=hash_password(user.password), role="user")
            insecure_redis_set_user(user.email,store_user.model_dump_json())
            return {"Status": f"Insecure user {user.email} created with role {user.role}"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )