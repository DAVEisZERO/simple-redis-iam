from email_service import send_mail
import pyotp
import time

email_html_body = """<h2>Confirm your signup</h2>
<p>Follow this link to confirm your user:</p>
<p><a href="{{ .ConfirmationURL }}">Confirm your mail</a></p>"""

def authentication_email(html_body: str, to_email: str, subject: str, redirect_url: str):
    send_mail(email_html_body)