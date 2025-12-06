import requests


def test_send_confirmation_email():
   check_response = requests.get("file://C:/Windows/win.ini")

   print(check_response.status_code)    