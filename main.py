from typing import Union, Annotated
import ssl

from fastapi import  Depends, FastAPI,  HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
import uvicorn
from fastapi.middleware.cors import CORSMiddleware

from app.schemas.user import User, AuthUser, UserSession
from app.routers import auth
from app.services.redis_service import store_in_redis, get_from_redis, remove_from_redis, get_session_redis, store_session_redis, find_in_redis, change_username_redis, change_password_redis
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, generate_opaque_token

origins = [
    "http://localhost:8100/",
    "http://localhost:8100",
    "http://127.0.0.1:8100",
]

app = FastAPI()

# Arrange CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure HTTPS 
# ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# ssl_context.load_cert_chain(certfile='./ssl_certs/cert.pem', keyfile='./ssl_certs/key.pem')


app.include_router(auth.router, prefix="/api/v1/auth")

@app.get("/api/v1/")
def read_root(token: Annotated[str, Depends(OAUTH2_SCHEME)]):
     result = get_session_redis(token)

     if result != None:
        return {"Status": token + " is valid",
                "user": result }
     else:                      
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/api/v1/changeName/")
def change_user_name(user: AuthUser, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    user_email = get_session_redis(token)
    #print("result:", user_email)

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

@app.post("/api/v1/changePassword/")
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


@app.put("/api/v1/users/remove/V2/{user_mail}")
def delete_user(user_mail: str):
    if remove_from_redis(username=user_mail) == 1:
        return {"status": user_mail + " deleted"}
    else:
        return {"status": user_mail + " not found"}
    

@app.get("/")
def read_root():
    return {"message": "Hello, HTTPS world!"}



### SECURE ###

@app.post("/api/v1/users/remove/")
def delete_user(user: AuthUser, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    result = get_session_redis(token)
    
    if result != None:
        remove_from_redis(username=user.email, token=token)
        return {"status": user.email + " deleted"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, ssl_certfile='./ssl_certs/example.com+5.pem', ssl_keyfile="./ssl_certs/./example.com+5-key.pem")