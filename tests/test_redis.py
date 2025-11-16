
from app.services.redis_service import get_from_redis, remove_from_redis, get_otp_secret, change_username_redis, store_in_redis
from app.schemas.user import OTPData, AuthUser, User, StoreUser
import pytest

def test_create_user():
    user = StoreUser(name="dave", email="sdfdsf@sdf.com", password="123456879", verified=False, id="23123213213123123", role="user")
    store_in_redis(user.name, user.model_dump_json())
    user2 = StoreUser(name="dave", email="sdfdsf@sdf.com", password="123456879", verified=True, id="23123213213123123", role="user")
    store_in_redis(user2.name, user2.model_dump_json())

def test_get_user_otp_from_redis():
    object = OTPData(**get_otp_secret("davebeer.dh@gmail.com"))
    print(object.code)
    assert object is not None

def test_change_username_redis():
    change_username_redis(old_username="name", new_username="new_name")
    updated_user = get_from_redis("name")

def test_get_user_from_redis():
    #object = get_from_redis("pedrobeer@gmail.com")
    new_user = User(**get_from_redis("davebeer.dh@gmail.com"))
    print(new_user.name)
    #print(object)
    #assert object is not None

# def teste_redis_health():
#     # requests.get(url)