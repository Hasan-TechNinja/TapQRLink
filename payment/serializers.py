from rest_framework import serializers
from . models import SubscriptionPlan, UserSubscription


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'price', 'duration_days', 'features',
            'plan_type', 'stripe_price_id', 'currency'
        ]

class UserSubscriptionSerializer(serializers.ModelSerializer):
    # Read-only nested plan for responses
    plan = SubscriptionPlanSerializer(read_only=True)
    # Write-only plan_id for updates/subscribe (maps to FK)
    plan_id = serializers.PrimaryKeyRelatedField(
        queryset=SubscriptionPlan.objects.all(),
        source='plan',
        write_only=True,
        required=False
    )
    # Return only the user id (read-only) to avoid writing foreign users
    user = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = UserSubscription
        fields = [
            'id', 'user', 'plan', 'plan_id', 'start_date', 'end_date', 'is_active', 'status'
        ]

            # 'last_renewed', 'stripe_customer_id', 'stripe_subscription_id', 'cancel_at_period_end', 'current_period_end',
        
        read_only_fields = [
            'user', 'start_date', 'end_date', 'last_renewed',
            'stripe_customer_id', 'stripe_subscription_id',
            'cancel_at_period_end', 'current_period_end', 'status'
        ]

    def update(self, instance, validated_data):
        # Allow swapping plan via plan_id when needed (admin / service)
        return super().update(instance, validated_data)
    