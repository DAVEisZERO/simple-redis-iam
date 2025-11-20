
import json
from typing import Optional

import redis

from app.config.settings import SETTINGS

# Read password from environment variable
redis_pass = SETTINGS.redis_password.get_secret_value()

r = redis.Redis( # speakes RESP (REdis Serialization Protocol)
    host=SETTINGS.redis_host, 
    port=SETTINGS.redis_port, 
    decode_responses=True,
    username=SETTINGS.redis_username,
    password=redis_pass 
)

def find_in_redis(type: str, username: str) -> bool:
    return r.exists(f"{type}:{username}") == 1

def store_in_redis(user: str, user_object: str):
    r.set(f"user:{user}", user_object)

def get_from_redis(username: str):
    json_data = r.get(f"user:{username}")
    if json_data is None:
        return None
    return json.loads(json_data)

def remove_from_redis(username: str, token: Optional[str] = None) -> int:
    if token != None:
        r.delete(f"session:{token}")
    return r.delete(f"user:{username}")

### SESSIONS Approach ###
def store_session_redis(username: str, token: str):
    r.set(f"session:{token}", username, ex=3600)  # Session expires in 1 hour

def get_session_redis(token: str):
    result = r.get(f"session:{token}")
    if result != None:
        return result
    return False

### CHANGE USER NAME ###
def change_username_redis(email: str, new_username: str):
    user_data = get_from_redis(email)
    if user_data is None:
        return False
    # Update username
    user_data['name'] = new_username
    r.delete(f"user:{email}")
    # Store updated data under new username key
    r.set(f"user:{email}", json.dumps(user_data))
    return True

### CHANGE PASSWORD ###
def change_password_redis(email: str, new_psswrd: str):
    user_data = get_from_redis(email)
    if user_data is None:
        return False
    # Update password
    user_data['password'] = new_psswrd
    r.delete(f"user:{email}")
    # Store updated data under new password key
    r.set(f"user:{email}", json.dumps(user_data))
    return True

### CHANGE Verification ###
def change_password_redis(email: str, new_psswrd: str):
    user_data = get_from_redis(email)
    if user_data is None:
        return False
    # Update password
    user_data['password'] = new_psswrd
    r.delete(f"user:{email}")
    # Store updated data under new password key
    r.set(f"user:{email}", json.dumps(user_data))
    return True

#### SECURE ####

def check_user_in_redis(username: str) -> bool:
    return r.exists(f"user:{username}") == 1

### otp secret storage ###
def store_otp_secret(id: str, secret_object: str):
    r.set(f"otp_secret:{id}", secret_object, ex=300)  # OTP secret expires in 5 minutes

def get_otp_secret(id: str) -> any:
    json_data = r.get(f"otp_secret:{id}")
    if json_data is None:
        return None
    return json.loads(json_data)

########################################################################################################################################
###                                                      INSECURE CODE                                                               ###
########################################################################################################################################

### 1. A07:2021 – Identification and Authentication Failures: no expiration time for sessions (TTL), leading to session fixation.
#######################################################################################################################
def store_session_redis_insecure(username: str, token: str):
    r.set(f"session:{token}", username) 

def store_otp_secret_insecure(id: str, secret_object: str):
    r.set(f"otp_secret:{id}", secret_object)

### 2. A02:2021 – Cryptographic Failures:  Hardcoding password/keys in the code
#######################################################################################################################
redis_pass_insecure = 'VJ7RHN6uekzKEcibu6DK33LuyZGonD2mUjppsY5F5YogwBe2m7odQqWTXgisM55mjSTs9'