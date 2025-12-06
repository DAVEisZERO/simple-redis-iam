import secrets
import hashlib

from pwdlib import PasswordHash
from fastapi.security import OAuth2PasswordBearer

from app.config.settings import SETTINGS

"""
################################################################################
###                                   DOCS                                   ###
################################################################################

OAuth2 Opaque Token Service
------------------
Provides secure token generation and password hashing/verification for OAuth2
authentication. Implements industry-standard Argon2 hashing for passwords and
opaque tokens, with legacy MD5 functions included for reference (insecure).

Configuration:
    OAUTH2_SCHEME: FastAPI OAuth2PasswordBearer scheme for token authentication
    password_hash: PasswordHash instance using recommended Argon2 settings

Functions:
    generate_opaque_token: Generates a cryptographically secure opaque token
        using Argon2 hashing with a random salt component.
        
    hash_password: Hashes a password using Argon2i for secure storage.
        
    verify_password: Verifies a password attempt against a stored Argon2 hash.
        
    md5_hash_password: [INSECURE] Legacy MD5 hashing function (do not use).
        
    md5_verify_password: [INSECURE] Legacy MD5 verification function (do not use).

################################################################################
"""


OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="token") # relative URL token --> https://example.com/api/v1/token.
password_hash = PasswordHash.recommended()

# Generate a generates a cryptographically secure, random salt and embeds it into the resulting hash string.
def generate_opaque_token(length=SETTINGS.opaque_token_length) -> str:
    token= password_hash.hash(password=secrets.token_urlsafe(length)).split('$')[-1]
    return token

### SECURE: Argon2i HASH TO STORE PASSWORD (A02:2021) ###
def hash_password(password: str):
    # hashed_password = password_hash.hash(password)
    return password_hash.hash(password)

def verify_password(attempt: str , hash: str):
    return password_hash.verify(password=attempt, hash=hash)

########################################################################################################################################
###                                                     INSECURE CODE                                                                ###
########################################################################################################################################

###
# 1. A02:2021 – Cryptographic Failures: MD5 is considered a "broken" algorithm. Vulnerbale to collisions and thus not recommended for cryptography uses. 
#######################################################################################################################

def md5_hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def md5_verify_password(attempt: str , hash: str) -> bool:
    return hashlib.md5(attempt.encode()).hexdigest() == hash