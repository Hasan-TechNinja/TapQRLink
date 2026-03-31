import firebase_admin
from firebase_admin import credentials, messaging
import os
from django.conf import settings

from main.models import Notification

def initialize_firebase():
    if not firebase_admin._apps:
        try:
            # First try if FIREBASE_CREDENTIALS_PATH is set in settings
            if hasattr(settings, 'FIREBASE_CREDENTIALS_PATH') and os.path.exists(settings.FIREBASE_CREDENTIALS_PATH):
                cred = credentials.Certificate(settings.FIREBASE_CREDENTIALS_PATH)
                firebase_admin.initialize_app(cred)
            else:
                # Fallback to default credentials (e.g. from environment variable GOOGLE_APPLICATION_CREDENTIALS)
                firebase_admin.initialize_app()
        except Exception as e:
            print(f"Firebase initialization error: {e}")

def send_push_notification(user, title, body, data=None):
    """
    Send push notification to a device via Firebase Cloud Messaging.
    And Save Notification to Database for user.
    """
    initialize_firebase()
    
    # Save to Database first (History)
    if user:
        try:
            Notification.objects.create(user=user, title=title, message=body)
        except Exception as e:
            print(f"Error saving notification to DB: {e}")

    # Fetch FCM token from profile
    try:
        profile = user.userprofile
        fcm_token = profile.fcm_token
    except Exception:
        fcm_token = None

    if not fcm_token:
        print("Cannot send push notification. FCM token is missing for user.")
        return None
        
    try:
        # We ensure data values are strings
        validated_data = {k: str(v) for k, v in data.items()} if data else {}
        
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            data=validated_data,
            token=fcm_token,
        )
        response = messaging.send(message)
        print(f"Successfully sent message: {response}")
        return response
    except Exception as e:
        print(f"Error sending push notification: {e}")
        return None
