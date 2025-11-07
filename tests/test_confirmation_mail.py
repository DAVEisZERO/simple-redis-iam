
from app.services.confirmation_service import authentication_email, validate_auth_code

import pytest


def test_send_confirmation_email():
    print(authentication_email(to_email="davebeer.dh@gmail.com", subject="Please confirm your email", redirect_url="http://localhost:8100/"))


def test_validate_auth_code():
    assert validate_auth_code("153937") == True