import secrets
import hashlib

from pwdlib import PasswordHash
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm


OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="token") # relative URL token --> https://example.com/api/v1/token.
OPAQUE_TOKEN_STRING = 5
password_hash = PasswordHash.recommended()
# non_secure_password_hash = MD5 or SHA1 --> NO SECURE

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


### SECURE: Argon2 HASH TO STORE PASSWORD ###

def hash_password(password: str):
    # hashed_password = password_hash.hash(password)
    return password_hash.hash(password)

def verify_password(attempt: str , hash: str):
    return password_hash.verify(password=attempt, hash=hash)

# INSECURE:MD5 TO STORE PASSWORDS
# 1. A02:2021 – Cryptographic Failures: MD5 is considered a "broken" algorithm. Vulnerbale to collisions and thus not recommended for cryptography uses. 

def md5_hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def md5_verify_password(attempt: str , hash: str) -> bool:
    return hashlib.md5(attempt.encode()).hexdigest() == hash