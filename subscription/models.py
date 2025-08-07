from datetime import timedelta
from time import timezone
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

# Create your models here.

class SubscriptionPlan(models.Model):
    PLAN_TYPES = [
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
        ('free', 'Free'),
    ]

    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text="Price of the subscription plan")
    duration_days = models.IntegerField(blank=True, null=True, help_text="Duration in days for the subscription plan (if applicable)")
    features = models.JSONField()  # List of features or JSON format
    plan_type = models.CharField(max_length=20, choices=PLAN_TYPES, default='free')

    def __str__(self):
        return self.name

    def is_free(self):
        return self.plan_type == 'free'
    


class UserSubscription(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE)
    start_date = models.DateTimeField(auto_now_add=True)
    end_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    last_renewed = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "User Subscription"
        verbose_name_plural = "User Subscriptions"

    def __str__(self):
        return f"{self.user.username} - {self.plan.name} ({self.start_date} to {self.end_date})"

    def save(self, *args, **kwargs):
        if self.plan:
            if self.plan.is_free():
                self.end_date = None # 
            elif self.plan.duration_days and not self.end_date:
                self.end_date = self.start_date + timedelta(days=self.plan.duration_days)
        super().save(*args, **kwargs)

    @property
    def is_currently_active(self):
        """Check if the subscription is currently active."""
        if not self.is_active:
            return False
        if self.plan.is_free():
            return True
        if self.end_date and timezone.now() < self.end_date:
            return True
        return False