import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

from dotenv import load_dotenv
load_dotenv()

# SMTP server Configuration
SMTP_SERVER = "smtp.gmail.com"  # Replace with your SMTP server
SMTP_PORT = 587  # Use 465 for SSL or 587 for TLS
USERNAME = "u7151758461@gmail.com"  # Your email login
PASSWORD = "fpzo rcfl lido cgzb"  # Your APP Password

# Email Details
sender_email = USERNAME
receiver_email = "davebeer.dh@gmail.com"
subject = "Test Email from Python"

# email_html_body = """<h2>Confirm your signup</h2>
# <p>Follow this link to confirm your user:</p>
# <p><a href="{{ .ConfirmationURL }}">Confirm your mail</a></p>"""


def send_mail(html_body: str):
    try:
        # Create the email
        msg = MIMEMultipart()
        msg["Form"] = sender_email
        msg["To"] = receiver_email
        msg["Subject"] = "python email testing"
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        # Send the email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure connection
            server.login(USERNAME, PASSWORD)
            server.sendmail(sender_email, receiver_email, msg.as_string())
    except Exception as e:
        print(f"error : {e}")



# send_mail(email_html_body)

