from django.shortcuts import render
from . serializers import SubscriptionPlanSerializer, UserSubscriptionSerializer
from . models import SubscriptionPlan, UserSubscription
import stripe
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from rest_framework import viewsets
from rest_framework.decorators import action
from django.utils import timezone 
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

# Create your views here.


stripe.api_key = settings.STRIPE_SECRET_KEY


class SubscriptionPlanView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        plans = SubscriptionPlan.objects.all().order_by('price')
        serializer = SubscriptionPlanSerializer(plans, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        if not request.user.is_staff:
            return Response(
                {"detail": "You do not have permission to create subscription plans."},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer = SubscriptionPlanSerializer(data=request.data)
        if serializer.is_valid():
            plan = serializer.save()
            return Response(SubscriptionPlanSerializer(plan).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserSubscriptionViewSet(viewsets.GenericViewSet):
    queryset = UserSubscription.objects.all()
    serializer_class = UserSubscriptionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)

    @action(detail=False, methods=['get'])
    def current(self, request):
        sub = self.get_queryset().first()
        if not sub:
            return Response({"message": "No subscription found for this user."}, status=status.HTTP_404_NOT_FOUND)
        return Response(self.get_serializer(sub).data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def current_active(self, request):
        sub = self.get_queryset().first()
        if sub and sub.is_active == True:
            return Response(self.get_serializer(sub).data, status=status.HTTP_200_OK)
        return Response({"message": "No active subscription found for this user."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def subscribe(self, request):
        """
        Start (or switch) to a plan via Stripe Checkout subscription.
        Free plans are activated locally; paid plans create a Checkout Session (mode='subscription').
        """
        plan_id = request.data.get('plan_id')
        if not plan_id:
            return Response({"error": "plan_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        plan = get_object_or_404(SubscriptionPlan, id=plan_id)

        if not plan.is_free() and not plan.stripe_price_id:
            return Response({"error": "This plan is missing stripe_price_id."}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user

        # Ensure one local record exists
        sub, _ = UserSubscription.objects.get_or_create(
            user=user,
            defaults={'plan': plan, 'is_active': False, 'start_date': timezone.now()}
        )
        # If switching plans, keep the local row and update fields
        sub.plan = plan
        sub.is_active = plan.is_free()  # free activates immediately
        sub.save()

        if plan.is_free():
            # No Stripe flow for free plans
            return Response(self.get_serializer(sub).data, status=status.HTTP_200_OK)

        # Ensure a Stripe Customer exists
        if not sub.stripe_customer_id:
            customer = stripe.Customer.create(email=user.email, metadata={'user_id': user.id})
            sub.stripe_customer_id = customer.id
            sub.save()
        else:
            customer = stripe.Customer.retrieve(sub.stripe_customer_id)

        # Create subscription checkout
        try:
            checkout_session = stripe.checkout.Session.create(
                mode='subscription',
                customer=customer.id,
                customer_update={'address': 'auto', 'name': 'auto'},
                line_items=[{'price': plan.stripe_price_id, 'quantity': 1}],
                success_url=request.build_absolute_uri(f'/payments/success/'),
                cancel_url=request.build_absolute_uri('/payments/cancel/'),
                metadata={'user_id': user.id, 'subscription_id': sub.id, 'plan_id': plan.id},
                allow_promotion_codes=True,
            )


            return Response({'checkout_url': checkout_session.url}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def cancel(self, request):
        """
        Cancel at period end (Stripe-native), mirror locally.
        If it's a free/legacy plan, just set inactive immediately.
        """
        sub = self.get_queryset().first()
        if not sub:
            return Response({"message": "No subscription found to cancel."}, status=status.HTTP_404_NOT_FOUND)

        if not sub.stripe_subscription_id:
            # Free or legacy duration plan
            sub.is_active = False
            sub.status = 'canceled'
            sub.end_date = timezone.now()
            sub.save()
            return Response(self.get_serializer(sub).data, status=status.HTTP_200_OK)

        try:
            stripe.Subscription.modify(sub.stripe_subscription_id, cancel_at_period_end=True)
            sub.cancel_at_period_end = True
            # Still active until end of period
            sub.status = 'active' if sub.status == 'active' else sub.status
            sub.save()
            return Response(self.get_serializer(sub).data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def renew(self, request):
        """
        Renew a subscription if it's eligible.
        """
        sub = self.get_queryset().first()
        
        # Check if the subscription has a valid Stripe subscription ID
        if not sub or not sub.stripe_subscription_id:
            return Response({"message": "No paid subscription to renew."}, status=status.HTTP_404_NOT_FOUND)

        try:
            # If the subscription is canceled, try to reactivate it
            if sub.status == 'canceled':
                stripe_sub = stripe.Subscription.retrieve(sub.stripe_subscription_id)
                
                if stripe_sub.cancel_at_period_end:
                    # Reactivate the subscription by modifying cancel_at_period_end
                    stripe_sub = stripe.Subscription.modify(sub.stripe_subscription_id, cancel_at_period_end=False)

                # Update subscription state based on Stripe
                sub.status = stripe_sub.status
                sub.is_active = True
                sub.current_period_end = timezone.make_aware(
                    timezone.datetime.fromtimestamp(stripe_sub.current_period_end)
                )
                sub.save()

                return Response(self.get_serializer(sub).data, status=status.HTTP_200_OK)

            # If the subscription is already active, no need to renew
            if sub.is_active:
                return Response({"message": "Subscription is already active."}, status=status.HTTP_200_OK)

            # If subscription cannot be renewed, create a new subscription
            new_subscription = stripe.Subscription.create(
                customer=sub.stripe_customer_id,
                items=[{'price': sub.plan.stripe_price_id}],
                metadata={'subscription_id': sub.id},
            )

            sub.stripe_subscription_id = new_subscription.id
            sub.status = new_subscription.status
            sub.current_period_end = timezone.make_aware(
                timezone.datetime.fromtimestamp(new_subscription.current_period_end)
            )
            sub.is_active = True
            sub.save()

            return Response(self.get_serializer(sub).data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




@method_decorator(csrf_exempt, name='dispatch')
class StripeWebhookView(APIView):
    def post(self, request, *args, **kwargs):
        payload = request.body.decode('utf-8')
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

        # try:
        event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)
        print(settings.STRIPE_WEBHOOK_SECRET)
        # except ValueError:
            # return JsonResponse({'message': 'Invalid payload'}, status=400)
        # except stripe.error.SignatureVerificationError:
            # return JsonResponse({'message': 'Invalid signature'}, status=400)

        # 1) Checkout session completed (user completed checkout)
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            metadata = session.get('metadata', {}) or {}
            sub_id = metadata.get('subscription_id', False)   
            
            if sub_id:
                user_sub = get_object_or_404(UserSubscription, id=sub_id)
                stripe_sub = stripe.Subscription.retrieve(session['subscription'])
                
                # Update the local subscription with the Stripe subscription ID and status
                user_sub.stripe_subscription_id = stripe_sub.id
                user_sub.status = stripe_sub.status
                current_period_end = stripe_sub.get('current_period_end', None)
                if current_period_end:
                    user_sub.period_end_time = timezone.datetime.fromtimestamp(current_period_end)
                else:
                    user_sub.period_end_time = None 
                user_sub.is_active = user_sub.status in ('trialing', 'active', 'past_due')
                user_sub.is_active= True
                print(user_sub.is_active)
                user_sub.save()

            return JsonResponse({'status': 'ok'}, status=200)

        return JsonResponse({'message': 'Event type not supported'}, status=200)



class SuccessView(APIView):
    permission_classes = [permissions.AllowAny]  # <-- user may not be logged in after checkout

    def get(self, request, subscription_id):
        session_id = request.GET.get('session_id')  # Fetch session_id from query parameters
        if not session_id:
            return Response({"error": "Missing session_id."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # This retrieves the actual Stripe checkout session using the session_id from the query string
            session = stripe.checkout.Session.retrieve(session_id)
        except Exception as e:
            return Response({"error": f"Unable to retrieve checkout session: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate that this success belongs to the same local subscription
        meta = session.get('metadata') or {}
        meta_sub_id = meta.get('subscription_id')
        if not meta_sub_id or str(meta_sub_id) != str(subscription_id):
            return Response({"error": "Subscription mismatch."}, status=status.HTTP_400_BAD_REQUEST)

        sub = get_object_or_404(UserSubscription, id=subscription_id)
        return Response({
            "message": "Payment success received.",
            "subscription_id": sub.id,
            "plan": sub.plan.name,
            "user_email": sub.user.email,
            "status": sub.status,
            "cancel_at_period_end": sub.cancel_at_period_end,
            "current_period_end": sub.current_period_end,
            "is_active": sub.is_active,
        }, status=status.HTTP_200_OK)





class CancelPaymentView(APIView):
    """
    Only for aborting a local non-Stripe flow. For Stripe use /cancel which sets cancel_at_period_end.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, subscription_id):
        sub = get_object_or_404(UserSubscription, id=subscription_id, user=request.user)
        if sub.stripe_subscription_id:
            return Response({"message": "Use /user-subscriptions/cancel to cancel at period end."}, status=400)
        sub.is_active = False
        sub.status = 'canceled'
        sub.end_date = timezone.now()
        sub.save()
        return Response({"message": "Subscription canceled locally."}, status=200)

          