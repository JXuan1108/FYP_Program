import smtplib
import ssl
from getpass import getpass

sender_email = ""
receiver_email = ""
sender_password = getpass(prompt='Enter your password: ')
port = 465 # 465 for SSL and 587 for starttls
smtp_server = "smtp.gmail.com"
message = """\
Subject: New Message
Hello there."""

context = ssl.create_default_context()

with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
    # server.starttls(context=context)
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, receiver_email, message)