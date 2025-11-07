from app.services.email_service import send_mail
from app.services.otp_service import generate_otp, validate_otp_token
from app.services.redis_service import store_in_redis, get_from_redis, store_otp_secret, get_otp_secret
from app.schemas.user import OTPData
import pyotp
import time


def authentication_email(to_email: str, subject: str, redirect_url: str) -> str:

    otp_object = generate_otp(email=to_email)
    store_otp_secret(otp_object.code, otp_object.model_dump_json())

    confirmation_url = f"https://127.0.0.1:8000/api/v1/auth/verify/?token={otp_object.code}&type=email&redirect_to=http%3A%2F%2Flocalhost%3A8100%2F"

    email_html_body = f"""<h2>Confirm your signup</h2>
                            <p>Follow this link to confirm your user:</p>
                            <p><a href="{confirmation_url}">Confirm your mail</a></p>"""
    response = send_mail(email_html_body, receiver_email=to_email, subject=subject)
    if response:
        return "Email sent successfully"
    else:
        return "Error sending email"
    
def validate_auth_code(token: str) -> bool:
    raw_data = get_otp_secret(token)
    if raw_data is None:
        return None
    stored_otp = OTPData(**raw_data)

    if validate_otp_token(stored_otp, token):
        return stored_otp
    return None