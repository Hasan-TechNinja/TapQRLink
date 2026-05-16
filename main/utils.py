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

def send_verification_email(email: str, code: str, name: str = None):
    subject = "Verification Code - Tap QR Link"
    recipient_name = name if name and name.strip() else email
    
    message = (
        f"Dear {recipient_name},\n\n"
        "Thank you for choosing Tap QR Link. To complete your verification process, please use the security code provided below:\n\n"
        f"Verification Code: {code}\n\n"
        "This code is valid for 10 minutes. For your security, please do not share this code with anyone.\n\n"
        "If you did not initiate this request, you can safely ignore this email.\n\n"
        "Best regards,\n"
        "The Tap QR Link Team"
    )
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@tapqrlink.com"),
            recipient_list=[email],
            fail_silently=True,
        )
    except Exception as e:
        print(f"Error sending email: {e}")


def get_default_password():
    # Put this in settings: DEFAULT_TEMP_PASSWORD = "StepCoach@2024" (example)
    return getattr(settings, "DEFAULT_TEMP_PASSWORD", "ChangeMe123!")
