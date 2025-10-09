import secrets

from pwdlib import PasswordHash
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm


OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="token") # relative URL token --> https://example.com/api/v1/token.
OPAQUE_TOKEN_STRING = 5
password_hash = PasswordHash.recommended()

# def verify_Token(sessino_Token: str):
    
#     if get_session_redis(sessino_Token):
#         return True
#     else:
#         return None

def compare_hashes(form_data: OAuth2PasswordRequestForm, in_redis_user):
    
    user_psswrd = generate_opaque_token(in_redis_user.get("password"))
    sent_password = generate_opaque_token(form_data.password)

    if not user_psswrd == sent_password:
        return None
    else:
        return True
    
# Generate a random opaque token with "salt" included
def generate_opaque_token(password, length=OPAQUE_TOKEN_STRING):
    token= password_hash.hash(secrets.token_urlsafe(length) + password).split('$')[-1]
    return token


#### More Secure ###


def hash_password(password: str):
    return "fakehashed" + password