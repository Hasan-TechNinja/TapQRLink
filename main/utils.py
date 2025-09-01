# app/utils.py
import random
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail

def generate_otp():
    return f"{random.randint(1000, 9999)}"

def otp_expiry(minutes=10):
    return timezone.now() + timedelta(minutes=minutes)

def send_verification_email(email: str, code: str):
    subject = "Your Verification Code"
    message = (
        f"Hello {email},\n\n"
        f"Your verification code is: {code}\n"
        "This code expires in 10 minutes.\n\n"
        "Best,\nThe Team"
    )
    send_mail(
        subject=subject,
        message=message,
        from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@example.com"),
        recipient_list=[email],
        fail_silently=False,
    )

def get_default_password():
    # Put this in settings: DEFAULT_TEMP_PASSWORD = "StepCoach@2024" (example)
    return getattr(settings, "DEFAULT_TEMP_PASSWORD", "ChangeMe123!")
