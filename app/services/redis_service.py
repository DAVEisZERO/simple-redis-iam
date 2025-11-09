import redis
import json
from app.schemas.user import User

r = redis.Redis( # speakes RESP (REdis Serialization Protocol)
    host='localhost', 
    port=6379, 
    decode_responses=True
)

def find_in_redis(type: str, username: str) -> bool:
    return r.exists(f"{type}:{username}") == 1

def store_in_redis(user: User):
    r.set(f"user:{user.email}", user.model_dump_json())

def get_from_redis(username: str):
    json_data = r.get(f"user:{username}")
    if json_data is None:
        return None
    return json.loads(json_data)

def remove_from_redis(username: str, token: str) -> int:
    r.delete(f"session:{token}")
    return r.delete(f"user:{username}")

# #### TODO redis.conf


### SESSIONS Approach ###
def store_session_redis(username: str, token: str): # TODO: expiration time - TTL - NOT secure
    r.set(f"session:{token}", username)

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

### CHANGE USER NAME ###
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

### otp secret storage ### TODO: expiration time REDIs OBJECT with TTL
def store_otp_secret(id: str, secret_object: str):
    r.set(f"otp_secret:{id}", secret_object)

def get_otp_secret(id: str) -> any:
    json_data = r.get(f"otp_secret:{id}")
    if json_data is None:
        return None
    return json.loads(json_data)