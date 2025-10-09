from typing import Union, Annotated

from fastapi import  Depends, FastAPI,  HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.schemas.user import User
from app.services.redis_service import store_in_redis, get_from_redis, remove_from_redis, get_session_redis, store_session_redis, find_in_redis
from app.services.oauth2_opaque_token import OAUTH2_SCHEME, generate_opaque_token

app = FastAPI()

@app.post("/api/v1/login/")
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
            ##TODO: Multiple session tokens can be created for the same user
    
    return {"access_token": token, "token_type": "bearer"}

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

@app.get("/api/v1/users/{user_mail}")
def read_user(user_mail: str, q: Union[str, None] = None):
    return {"user_name": get_from_redis(username=user_mail)}

@app.post("/api/v1/users/signup")
def store_user(user: User):
    if find_in_redis("user", user.email):
        raise HTTPException(status_code=400, detail="User already exists")
    store_in_redis(user)
    return {"user_email": user.email, "user_name": user.name}

@app.put("/api/v1/users/remove/V2/{user_mail}")
def delete_user(user_mail: str):
    if remove_from_redis(username=user_mail) == 1:
        return {"status": user_mail + " deleted"}
    else:
        return {"status": user_mail + " not found"}


### SECURE ###

@app.put("/api/v1/users/remove/{user_mail}")
def delete_user(user_mail: str, token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    result = get_session_redis(token)
    
    if result != None:
        remove_from_redis(username=user_mail)
        return {"status": user_mail + " deleted"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    