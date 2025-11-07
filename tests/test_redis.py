
from app.services.redis_service import get_from_redis, remove_from_redis, get_otp_secret, change_username_redis
from app.schemas.user import OTPData
import pytest

def test_get_user_from_redis():
    object = OTPData(**get_otp_secret("davebeer.dh@gmail.com"))
    print(object.code)
    assert object is not None

def test_change_username_redis():
    change_username_redis(old_username="name", new_username="new_name")
    updated_user = get_from_redis("name")
