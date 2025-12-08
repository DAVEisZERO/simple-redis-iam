
from app.services.redis_service import get_from_redis, remove_from_redis, get_otp_secret, change_username_redis, store_in_redis
from app.schemas.user import AuthUser, User, StoreUser
from app.schemas.token import OTPData
from app.config.settings import SETTINGS
import pytest

"""
Tests for Redis-backed utilities (debugging helpers).

DISCLAIMER:
- These tests were created for debugging and exploratory purposes.
- They are not intended to be part of a production test suite or used
  for formal evaluation.
- They may perform network I/O or interact with local services.
- Use them intentionally; the project authors are not responsible
  if they fail or have side effects in your environment.
"""

def test_create_user():
    """
    Debug: store a user representation in Redis.

    This helper stores a StoreUser JSON payload under the user's name.
    Intended for manual debugging of store_in_redis; not a production test.
    """
    user = StoreUser(name="dave", email="sdfdsf@sdf.com", password="123456879", verified=False, id="23123213213123123", role="user")
    store_in_redis(user.name, user.model_dump_json())
    # user2 = StoreUser(name="dave", email="sdfdsf@sdf.com", password="123456879", verified=True, id="23123213213123123", role="user")
    # store_in_redis(user2.name, user2.model_dump_json())

def test_get_user_otp_from_redis():
    """
    Debug: retrieve OTP secret from Redis.

    Constructs an OTPData object from the Redis payload and prints the code.
    Useful to confirm OTP values are stored/retrieved correctly.
    """
    object = OTPData(**get_otp_secret("davedfsdfd@gmail.com"))
    print(object.code)
    assert object is not None

def test_change_username_redis():
    """
    Debug: change a username key in Redis.

    Calls change_username_redis to exercise renaming logic.
    Not asserted — used to observe Redis side effects.
    """
    change_username_redis(old_username="name", new_username="new_name")
    updated_user = get_from_redis("name")

def test_get_user_from_redis():
    """
    Debug: load a User object from Redis.

    Builds a User from the stored Redis payload and prints the name.
    Intended for manual verification.
    """
    #object = get_from_redis("pedrobeer@gmail.com")
    new_user = User(**get_from_redis("davefsdfsdf@gmail.com"))
    print(new_user.name)
    #print(object)
    #assert object is not None

