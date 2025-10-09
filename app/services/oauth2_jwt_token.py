from fastapi.security import OAuth2PasswordBearer

OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="token") # relative URL token --> https://example.com/api/v1/token.



#### More Secure ###
def hash_password(password: str):
    return "fakehashed" + password