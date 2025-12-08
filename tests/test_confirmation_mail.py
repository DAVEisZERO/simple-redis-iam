
from app.services.confirmation_service import authentication_email, validate_auth_code, reset_password_email

import pytest

"""
Integration tests for the confirmation email service.

These tests exercise the email-sending functionality provided by
app.services.confirmation_service. They send real requests to the
given email provider and therefore should be run intentionally
(e.g., not in fast unit-test runs). Ensure environment credentials
and configuration are set before running.

Only real addresses can be used for testing.

DISCLAIMER:
- These tests were created for debugging and exploratory purposes.
- They are not intended to be part of a production test suite or used
  for formal evaluation.
- They may perform network I/O or interact with local services.
- Use them intentionally; the project authors are not responsible
  if they fail or have side effects in your environment.
"""

def test_send_confirmation_email():
    """
    Send a confirmation email.

    This integration-style test calls authentication_email() with a
    target address and prints the result. It is useful to verify the
    email service is configured and able to send messages.
    """
    print(authentication_email(to_email="davedsfsdfdh@gmail.com", subject="Please confirm your email", redirect_url="http://localhost:8100/"))


def test_send_password_reset_email():
    """
    Send a password reset email.

    Similar to the confirmation test, this invokes reset_password_email()
    and prints the service response for manual inspection.
    """
    print(reset_password_email(to_email="davedsfsdfdh@gmail.com", subject="Reset your password", redirect_url="http://localhost:8100/"))


def test_validate_auth_code():
    """
    Validate an authentication code.

    Verifies that validate_auth_code() returns True for a known valid code.
    """
    assert validate_auth_code("153937") == True