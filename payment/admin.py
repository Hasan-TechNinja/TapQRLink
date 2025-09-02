from django.contrib import admin
from .models import SubscriptionPlan, UserSubscription
from django import forms
# Register your models here.

class SubscriptionPlanAdminForm(forms.ModelForm):
    class Meta:
        model = SubscriptionPlan
        fields = "__all__"

    def clean(self):
        cleaned = super().clean()
        plan_type = cleaned.get("plan_type")
        if plan_type in ("monthly", "yearly"):
            cleaned["duration_days"] = None
        if plan_type == "free":
            cleaned["price"] = 0
            cleaned["stripe_price_id"] = None
        return cleaned

@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    form = SubscriptionPlanAdminForm
    list_display = ("id", "name", "plan_type", "price", "stripe_price_id", "duration_days")
    list_filter = ("plan_type",)
    search_fields = ("name",)


class UserSubscriptionAdmin(admin.ModelAdmin):
    list_display = ('user', 'plan', 'start_date', 'end_date', 'is_active')
    search_fields = ('user__username', 'plan__name')
    list_filter = ('is_active', 'plan__plan_type')

admin.site.register(UserSubscription, UserSubscriptionAdmin)