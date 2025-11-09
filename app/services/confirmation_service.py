from app.services.email_service import send_mail
from app.services.otp_service import generate_otp, validate_otp_token
from app.services.redis_service import store_otp_secret, get_otp_secret
from app.schemas.user import OTPData


def authentication_email(to_email: str, subject: str, type: str = "email", redirect_url: str = "http%3A%2F%2Flocalhost%3A8100%2F") -> str:

    otp_object = generate_otp(email=to_email)
    store_otp_secret(otp_object.code, otp_object.model_dump_json())

    confirmation_url = f"https://127.0.0.1:8000/api/v1/auth/verify/?token={otp_object.code}&type={type}&redirect_to={redirect_url}"

    email_html_body = f"""<h2>Confirm your signup</h2>
                            <p>Follow this link to confirm your user:</p>
                            <p><a href="{confirmation_url}">Confirm your mail</a></p>"""
    response = send_mail(email_html_body, receiver_email=to_email, subject=subject)
    if response:
        return "Email sent successfully"
    else:
        return "Error sending email"
    
def reset_password_email(to_email: str, subject: str, type:str = "password", redirect_url: str = "http%3A%2F%2Flocalhost%3A8100%2Fauth%2Fsignup") -> bool:

    otp_object = generate_otp(email=to_email)
    store_otp_secret(otp_object.code, otp_object.model_dump_json())

    confirmation_url = f"https://127.0.0.1:8000/api/v1/entrypoints/verify/?token={otp_object.code}&type={type}&redirect_to={redirect_url}"

    email_html_body = f"""<h2>Confirm your Password Reset</h2>
                            <p>You will be redirected to the Sign-Up page, to re-create your former account.</p>
                            <p>Follow this link to confirm the reset:</p>
                            <p><a href="{confirmation_url}">Confirm your Password Reset</a></p>"""
    response = send_mail(email_html_body, receiver_email=to_email, subject=subject)
    if response:
        return True
    else:
        return False
    
def validate_auth_code(token: str) -> bool:
    raw_data = get_otp_secret(token)
    if raw_data is None:
        return None
    stored_otp = OTPData(**raw_data)

    if validate_otp_token(stored_otp, token):
        return stored_otp
    return None