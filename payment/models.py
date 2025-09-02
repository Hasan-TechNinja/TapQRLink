# models.py
from __future__ import annotations

from datetime import timedelta, datetime
from typing import Optional

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


class SubscriptionPlan(models.Model):
    PLAN_TYPES = [
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
        ('free', 'Free'),
    ]

    name = models.CharField(max_length=100, unique=True, db_index=True)
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        help_text="Displayed price (informational; Stripe is source of truth).",
    )
    duration_days = models.IntegerField(
        blank=True, null=True,
        help_text="Optional for non-Stripe, fixed-duration access."
    )
    # Use default=list to avoid null JSONs
    features = models.JSONField(default=list, help_text="List/JSON of feature flags.")
    plan_type = models.CharField(max_length=20, choices=PLAN_TYPES, default='free', db_index=True)

    # Stripe recurring price for paid plans
    stripe_price_id = models.CharField(
        max_length=200, blank=True, null=True,
        help_text="Stripe recurring price id (price_...). Required for paid plans."
    )
    currency = models.CharField(max_length=10, default='usd')

    class Meta:
        constraints = [
            models.CheckConstraint(check=models.Q(price__gte=0), name='plan_price_nonnegative'),
            # If plan is free, price must be 0
            models.CheckConstraint(
                check=models.Q(plan_type='free', price=0) | ~models.Q(plan_type='free'),
                name='free_plan_price_zero'
            ),
        ]
        ordering = ['price', 'name']

    def __str__(self) -> str:
        return f"{self.name} ({self.plan_type})"

    def is_free(self) -> bool:
        return self.plan_type == 'free'

    def clean(self):
        # For paid recurring plans (monthly/yearly), require stripe_price_id
        if self.plan_type in ('monthly', 'yearly') and not self.stripe_price_id:
            raise ValidationError("stripe_price_id is required for recurring paid plans.")
        # duration_days is only meaningful for non-Stripe fixed-duration plans
        if self.plan_type in ('monthly', 'yearly') and self.duration_days:
            # Not an error, but warn in admin normally; here we enforce to avoid confusion
            raise ValidationError("Do not set duration_days for monthly/yearly Stripe plans.")
        if self.is_free() and (self.stripe_price_id or self.price):
            # Keep free clean
            if self.price != 0:
                raise ValidationError("Free plan must have price 0.")
            if self.stripe_price_id:
                raise ValidationError("Free plan must not have a stripe_price_id.")


class UserSubscription(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='subscription', db_index=True)
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE, related_name='subscriptions')
    start_date = models.DateTimeField(auto_now_add=True, db_index=True)
    end_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    last_renewed = models.DateTimeField(auto_now=True)

    # Stripe bookkeeping (mirror)
    stripe_customer_id = models.CharField(max_length=200, blank=True, null=True, db_index=True)
    stripe_subscription_id = models.CharField(max_length=200, blank=True, null=True, db_index=True)
    cancel_at_period_end = models.BooleanField(default=False)
    current_period_end = models.DateTimeField(null=True, blank=True, db_index=True)
    # trialing, active, past_due, canceled, incomplete, incomplete_expired, unpaid
    status = models.CharField(max_length=50, default='active', db_index=True)

    class Meta:
        verbose_name = "User Subscription"
        verbose_name_plural = "User Subscriptions"
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['stripe_subscription_id']),
            models.Index(fields=['status', 'is_active']),
        ]

    def __str__(self) -> str:
        return f"{self.user.username} - {self.plan.name} ({self.start_date} → {self.end_date or '∞'})"

    # ---------- Core logic ----------

    def clean(self):
        # Free plan: must not carry Stripe identifiers
        if self.plan and self.plan.is_free():
            if self.stripe_subscription_id or self.stripe_customer_id:
                raise ValidationError("Free subscriptions must not have Stripe IDs.")
        # If monthly/yearly but missing stripe ids after activation, you likely forgot to hook webhooks
        if self.plan and self.plan.plan_type in ('monthly', 'yearly'):
            # Not raising here to allow pre-checkout creation
            pass

    def save(self, *args, **kwargs):
        """
        Keep backward-compatibility for:
         - Free plan: no end_date, always active unless explicitly disabled
         - Fixed-duration plan (non-Stripe): set end_date on first save
        Stripe plans: end_date is driven by Stripe; do not change here.
        """
        if self.plan:
            if self.plan.is_free():
                self.end_date = None
                self.status = 'active'
                self.cancel_at_period_end = False
                self.current_period_end = None
            elif self.plan.duration_days and not self.stripe_subscription_id:
                # Only for non-Stripe/fixed-duration plans
                if not self.end_date:
                    # Use start_date if present, otherwise now
                    base = self.start_date or timezone.now()
                    self.end_date = base + timedelta(days=self.plan.duration_days)
        super().save(*args, **kwargs)

    @property
    def is_currently_active(self) -> bool:
        if not self.is_active:
            return False
        if self.plan.is_free():
            return True
        # Prefer Stripe-mirrored state
        if self.current_period_end and timezone.now() < self.current_period_end \
           and self.status in ('trialing', 'active', 'past_due'):
            return True
        # Fallback to legacy duration
        if self.end_date and timezone.now() < self.end_date:
            return True
        return False

    def remaining_seconds(self) -> Optional[int]:
        """Seconds left in current period (Stripe) or legacy end_date; None if unlimited."""
        now = timezone.now()
        end = self.current_period_end or self.end_date
        if not end:
            return None
        delta = end - now
        return max(int(delta.total_seconds()), 0)

    # ---------- Stripe helpers (used by webhooks/services) ----------

    def activate_from_stripe(self, stripe_subscription_id: str, current_period_end_unix: int, status: str,
                             cancel_at_period_end: bool = False):
        """
        Mirror activation/renewal from Stripe.
        Call this in webhook handlers: checkout.session.completed / invoice.payment_succeeded.
        """
        self.stripe_subscription_id = stripe_subscription_id
        self.status = status
        self.cancel_at_period_end = cancel_at_period_end
        self.current_period_end = timezone.make_aware(
            datetime.fromtimestamp(current_period_end_unix)
        ) if current_period_end_unix else None
        self.is_active = status in ('trialing', 'active', 'past_due')
        # Stripe drives the period; legacy end_date should not fight with it
        self.end_date = None
        self.save(update_fields=[
            'stripe_subscription_id', 'status', 'cancel_at_period_end',
            'current_period_end', 'is_active', 'end_date', 'last_renewed'
        ])

    def mark_canceled_immediately(self, status: str = 'canceled'):
        """Use when Stripe sends customer.subscription.deleted or you hard-cancel."""
        self.status = status
        self.is_active = False
        self.cancel_at_period_end = False
        self.current_period_end = None
        self.save(update_fields=['status', 'is_active', 'cancel_at_period_end', 'current_period_end', 'last_renewed'])

    def mirror_update_from_stripe(self, status: str, cancel_at_period_end: bool,
                                  current_period_end_unix: Optional[int]):
        """Use for customer.subscription.updated webhooks."""
        self.status = status
        self.cancel_at_period_end = cancel_at_period_end
        self.current_period_end = timezone.make_aware(
            datetime.fromtimestamp(current_period_end_unix)
        ) if current_period_end_unix else None
        self.is_active = status in ('trialing', 'active', 'past_due')
        self.save(update_fields=['status', 'cancel_at_period_end', 'current_period_end', 'is_active', 'last_renewed'])

    # ---------- Local actions (for admin/service use) ----------

    def deactivate_local(self, reason_status: str = 'canceled'):
        """Soft deactivate locally (does not touch Stripe)."""
        self.is_active = False
        self.status = reason_status
        self.save(update_fields=['is_active', 'status', 'last_renewed'])
