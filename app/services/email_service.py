import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.config.settings import SETTINGS

"""
################################################################################
###                                   DOCS                                   ###
################################################################################

Email Service Module
------------------
Handles email delivery using SMTP with secure TLS connections. Supports sending
HTML-formatted emails with proper MIME structure and error handling.

Configuration:
    SETTINGS.smtp_server: SMTP server hostname from environment settings.
    SETTINGS.smtp_port: SMTP server port from environment settings.
    SETTINGS.smtp_username: SMTP authentication username from environment settings.
    SETTINGS.smtp_password: SMTP authentication password from environment settings.

Functions:
    send_mail: Sends an HTML email to a recipient via SMTP with TLS encryption.
        Input: html_body (str), receiver_email (str), subject (str)
        Returns: bool (True on success, False or None on failure)
        Raises: Logs exceptions to console on SMTP connection or authentication errors.

################################################################################
"""


def send_mail(html_body: str, receiver_email: str, subject: str):
    try:
        # Create the email
        msg = MIMEMultipart()
        msg["Form"] = SETTINGS.smtp_username
        msg["To"] = receiver_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        # Send the email
        with smtplib.SMTP(SETTINGS.smtp_server, SETTINGS.smtp_port) as server:
            server.starttls()  # Secure connection
            server.login(SETTINGS.smtp_username, SETTINGS.smtp_password.get_secret_value())
            server.sendmail(SETTINGS.smtp_username, receiver_email, msg.as_string())
        return True
    except Exception as e:
        print(f"error : {e}")