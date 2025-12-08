import requests

"""
This code here was used to test waht can be fetched with the request library. URLs such as "file//:" are not possible, but http endpoints in local network cna be checked.

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
    Test the functionality of sending a confirmation email.

    This test sends a GET request to a local server endpoint 
    and prints the status code of the response. It can be used 
    to verify that the server is running and responding correctly.
    """
    check_response = requests.get("http://127.0.0.1:6300")  # or GET http://127.0.0.1:6379

    print(check_response.status_code)