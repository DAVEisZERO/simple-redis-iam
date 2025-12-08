import pytest
import json
from app.schemas.user import User


def test_user_round_trip_serialization():
    """
    Test the serialization and deserialization of the User model.

    This test creates a User instance, serializes it to JSON, 
    and then deserializes it back to a User instance. 
    It asserts that the original User instance is equal to the 
    newly created User instance after deserialization.
    """
    original_user = User(name="Charlie", email="charlie@example.com", password="abcO*dfds123")
    user_json = original_user.model_dump_json()
    new_user = User.model_validate_json(user_json)

    assert original_user == new_user
