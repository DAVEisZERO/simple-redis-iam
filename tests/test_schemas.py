import pytest
import json
from app.schemas.user import User, Token


def test_user_round_trip_serialization():
    original_user = User(name="Charlie", email="charlie@example.com", password="abc123")
    user_json = original_user.model_dump_json()
    new_user = User.model_validate_json(user_json)

    assert original_user == new_user
