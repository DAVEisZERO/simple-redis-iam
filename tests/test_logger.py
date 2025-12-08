import pytest
import json
from app.schemas.user import User
from app.logging.confg_logging import LOGGER    


def test_logger_functionallity():
    """
    Test the functionality of the logging system.

    This test creates a User instance and serializes it to JSON. 
    It then logs an informational message indicating the user's 
    email and the action performed (serialization).
    """
    original_user = User(name="Charlie", email="charlie@example.com", password="abc12dsdsdss1737673U*dssd3")
    user_json = original_user.model_dump_json()
    LOGGER.info("test_logger", user=original_user.email, action="serialization")