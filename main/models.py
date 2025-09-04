from datetime import timedelta, timezone
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.contrib.auth import get_user_model

# Create your models here.


User = get_user_model()

class EmailVerification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="email_verifications")
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    # optional: throttle resend
    last_sent_at = models.DateTimeField(auto_now=True, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "code"]),
            models.Index(fields=["expires_at"]),
        ]

    def is_expired(self):
        return timezone.now() > self.expires_at
    

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user.email}: {self.title}"
    

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True, null=True)
    mobile_number = models.CharField(max_length=15, blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    def __str__(self):
        return f"Profile of {self.user.username}"
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Additional logic can be added here if needed


class PasswordResetCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=2)
    

class QRCodeHistory(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)  # associate with user if you have user authentication
    link = models.URLField(max_length=200)
    is_read = models.BooleanField(default=False)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.link
    

class FeedBack(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField(max_length=800)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} = {self.text[:15]}"