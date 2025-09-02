from django.shortcuts import get_object_or_404, render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.conf import settings
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.decorators import action
from datetime import timedelta, date
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import stripe
from rest_framework.permissions import IsAuthenticated
from pyzbar.pyzbar import decode
from PIL import Image
import io
from main.models import EmailVerification, Notification, PasswordResetCode, QRCodeHistory, UserProfile, FeedBack
from subscription.models import SubscriptionPlan, UserSubscription
from .serializers import EmailTokenObtainPairSerializer, NotificationSerializer, PasswordResetConfirmSerializer, RegistrationSerializer, QRCodeHistorySerializer, SubscriptionPlanSerializer, UserProfileSerializer, UserSubscriptionSerializer, FeedBackSerializer, SetInitialPasswordSerializer

from rest_framework import permissions
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
import random
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.db import transaction
from django.contrib.auth import get_user_model
from .serializers import RegistrationSerializer, VerifyEmailSerializer
from main.utils import generate_otp, otp_expiry, send_verification_email, get_default_password
from main.models import EmailVerification
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, OutstandingToken, BlacklistedToken



User = get_user_model()

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @transaction.atomic
    def post(self, request):
        email = request.data.get("email")
        existing_user = User.objects.filter(email=email).first()

        # If user exists
        if existing_user:
            if existing_user.is_active:
                return Response(
                    {"error": "This email is already in use by an active account."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            # Inactive: resend OTP (with basic throttle of 60s)
            ev = EmailVerification.objects.filter(user=existing_user).order_by("-created_at").first()
            if ev and (timezone.now() - ev.last_sent_at).total_seconds() < 60:
                return Response(
                    {"message": "A verification code was just sent. Please check your email."},
                    status=status.HTTP_200_OK
                )
            EmailVerification.objects.filter(user=existing_user).delete()
            code = generate_otp()
            EmailVerification.objects.create(user=existing_user, code=code, expires_at=otp_expiry(10))
            send_verification_email(existing_user.email, code)

            return Response({"message": "A new verification code has been sent to your email."}, status=status.HTTP_200_OK)

        # New user flow
        serializer = RegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()

        # Optionally create a Notification
        try:
            Notification.objects.create(
                user=user,
                title="Registration Started",
                message="Your account was created as pending. Verify your email to activate.",
            )
        except Exception:
            pass  # don't block registration if notifications app is absent

        return Response(
            {"message": "Account created as pending. An OTP has been emailed to you."},
            status=status.HTTP_201_CREATED
        )


class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    @transaction.atomic
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data["user"]
        record = serializer.validated_data["record"]

        # Activate user
        user.is_active = True
        user.save(update_fields=["is_active"])
        # Clean up codes
        EmailVerification.objects.filter(user=user).delete()

        # Optional: notify and issue tokens now that user is active
        try:
            Notification.objects.create(
                user=user,
                title="Registration Successful",
                message="Welcome! Your account has been activated.",
            )
        except Exception:
            pass

        refresh = RefreshToken.for_user(user)

        # Return tokens and remind about default password
        return Response(
            {
                "message": "Email verified. Your account is now active.",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "note": "You were created with a default password. Please change it from your profile/security settings."
            },
            status=status.HTTP_200_OK
        )


User = get_user_model()

class SetInitialPasswordView(APIView):
    """
    Set a new password once, without requiring the old password.
    Identify user via JWT access token (Authorization header preferred,
    but 'access' in the JSON body is also supported).
    """
    permission_classes = [permissions.IsAuthenticated]  # we authenticate manually

    @transaction.atomic
    def post(self, request):
        serializer = SetInitialPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 1) Try Authorization header first
        user = None
        auth = JWTAuthentication()
        try:
            auth_result = auth.authenticate(request)
            if auth_result:
                user, _ = auth_result
        except Exception:
            user = None

        # 2) Fallback: access token in body
        if user is None:
            access = serializer.validated_data.get("access")
            if not access:
                return Response(
                    {"detail": "Authentication required. Provide Authorization: Bearer <access> header or 'access' in body."},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            try:
                at = AccessToken(access)
                user_id = at.get("user_id")
                user = User.objects.get(id=user_id)
            except Exception:
                return Response({"detail": "Invalid or expired access token."}, status=status.HTTP_401_UNAUTHORIZED)

        new_password = serializer.validated_data["new_password"]

        # Update password (no old password needed)
        user.set_password(new_password)
        user.save(update_fields=["password"])

        # (Optional but recommended) Rotate tokens: issue new tokens
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        # (Optional) If client sent an old refresh token, blacklist it
        old_refresh = request.data.get("refresh")
        if old_refresh:
            try:
                # Requires 'rest_framework_simplejwt.token_blacklist' in INSTALLED_APPS
                old = RefreshToken(old_refresh)
                old.blacklist()
            except Exception:
                pass  # If blacklist not enabled, ignore

        # Notify
        try:
            Notification.objects.create(
                user=user,
                title="Password setup",
                message="Your password has been set successfully."
            )
        except Exception:
            pass

        return Response(
            {
                "message": "Password set successfully.",
                "refresh": str(refresh),
                "access": str(access_token)
            },
            status=status.HTTP_200_OK
        )
   


class UserProfileView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        user_profile = UserProfile.objects.get(user=request.user)
        serializer = UserProfileSerializer(user_profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        user_profile = UserProfile.objects.get(user=request.user)
        serializer = UserProfileSerializer(user_profile, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class EmailLoginView(TokenObtainPairView):
    serializer_class = EmailTokenObtainPairSerializer




class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)

            if not user.is_active:
                return Response({"error": "User is not active."}, status=status.HTTP_400_BAD_REQUEST)

            PasswordResetCode.objects.filter(user=user).delete()

            code = str(random.randint(1000, 9999))

            PasswordResetCode.objects.create(user=user, code=code)
            
            if user.first_name and user.last_name:
                name = f"{user.first_name} {user.last_name}"
            elif user.email:
                name = user.email
            else:
                name = user.username

            send_mail(
                subject='Password Reset Request',
                message=(
                    f"Hello, {name}\n"
                    "We received a request to reset your account password.\n"
                    f"Your password reset code is: "
                    f"{code}\n\n"
                    "If you did not request this, please ignore this email.\n"
                    # "For security, this code will expire in 10 minutes.\n\n"
                    "Best regards,\n"
                    "The Tap QR Link Team"
                ),
                from_email='noreply@example.com',
                recipient_list=[email],
                fail_silently=False
            )


            return Response({"message": "A password reset code has been sent to your email."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)



class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']

            try:
                user = User.objects.get(email=email)

                password_reset = PasswordResetCode.objects.filter(user=user, code=code).first()

                if not password_reset:
                    return Response({"error": "Invalid or expired reset code."}, status=status.HTTP_400_BAD_REQUEST)

                user.password = make_password(new_password)
                user.save()

                password_reset.delete()

                return Response({'message': 'Password has been reset.'}, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")

        if refresh_token is None:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create token object from the refresh token string
            token = RefreshToken(refresh_token)

            # Blacklist the token
            token.blacklist()

            return Response({"message": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)

        except InvalidToken:
            return Response({"error": "The token is invalid or expired."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# ------------------------------- Subscription Management -------------------------------



class SubscriptionPlanView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Retrieve all subscription plans."""
        plans = SubscriptionPlan.objects.all().order_by('price')
        serializer = SubscriptionPlanSerializer(plans, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Create a new subscription plan (admin only)."""
        if not request.user.is_staff:
            return Response({"detail": "You do not have permission to create subscription plans."}, status=status.HTTP_403_FORBIDDEN)

        serializer = SubscriptionPlanSerializer(data=request.data)
        if serializer.is_valid():
            plan = serializer.save()
            return Response(SubscriptionPlanSerializer(plan).data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Set Stripe API Key
stripe.api_key = settings.STRIPE_SECRET_KEY

class UserSubscriptionViewSet(viewsets.GenericViewSet):

    '''Subscription add demo
    
    ["Basic AI Chat", "Daily Check-ins", "Milestone Tracking", "Voice Responses", "Advanced Analytics", "Personalized Content", "Priority Support"]
'''
    queryset = UserSubscription.objects.all()
    serializer_class = UserSubscriptionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter to get the subscription for the authenticated user."""
        return self.queryset.filter(user=self.request.user)

    @action(detail=False, methods=['get'])
    def current(self, request):
        """Retrieve the current subscription for the authenticated user."""
        try:
            user_subscription = self.get_queryset().get()  # Should be OneToOne, so get() works
            serializer = self.get_serializer(user_subscription)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except UserSubscription.DoesNotExist:
            return Response({"message": "No active subscription found for this user."},
                            status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'])
    def current_active(self, request):
        """Check if the user has an active subscription."""
        user_subscription = self.get_queryset().filter(is_active=True).first()
        if user_subscription:
            serializer = self.get_serializer(user_subscription)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"message": "No active subscription found for this user."},
                        status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def subscribe(self, request):
        """Create a Stripe checkout session for the user to subscribe to a plan."""
        plan_id = request.data.get('plan_id')
        if not plan_id:
            return Response({"error": "Plan ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            plan = SubscriptionPlan.objects.get(id=plan_id)
        except SubscriptionPlan.DoesNotExist:
            return Response({"error": "Subscription plan not found."}, status=status.HTTP_404_NOT_FOUND)

        user = request.user

        try:
            # Try to fetch user's current subscription (if any)
            user_subscription = UserSubscription.objects.get(user=user)

            if user_subscription.is_active:
                if user_subscription.plan.id == plan.id:
                    return Response(
                        {"error": "You already have an active subscription to this plan."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    # Upgrade/downgrade: deactivate and update to new plan
                    user_subscription.plan = plan
                    user_subscription.is_active = False
                    user_subscription.start_date = timezone.now()
                    user_subscription.save()

        except UserSubscription.DoesNotExist:
            # No subscription found — create a new one
            user_subscription = UserSubscription.objects.create(
                user=user,
                plan=plan,
                is_active=False,
                start_date=timezone.now(),
            )

        # Create Stripe Checkout Session
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                customer_email=user.email,
                line_items=[{
                    'price_data': {
                        'currency': 'gbp',
                        'product_data': {
                            'name': plan.name,
                        },
                        'unit_amount': int(plan.price * 100),
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=request.build_absolute_uri(f'/payments/success/{user_subscription.id}/'),
                cancel_url=request.build_absolute_uri('/payments/cancel/'),
                metadata={
                    'user_id': user.id,
                    'plan_id': plan.id,
                    'subscription_id': user_subscription.id
                }
            )
            return Response({'checkout_url': checkout_session.url}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



    @action(detail=False, methods=['post'])
    def cancel(self, request):
        """Cancel the active subscription for the authenticated user."""
        try:
            user_subscription = self.get_queryset().get(is_active=True)
            user_subscription.is_active = False
            user_subscription.save()
            serializer = self.get_serializer(user_subscription)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except UserSubscription.DoesNotExist:
            return Response({"message": "No active subscription found to cancel."},
                             status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['post'])
    def renew(self, request):
        """Renew the user's subscription."""
        try:
            user_subscription = self.get_queryset().get(is_active=True)
            # Renew logic: Extend the end_date by the plan's duration
            if user_subscription.plan.duration_days:
                user_subscription.end_date += timedelta(days=user_subscription.plan.duration_days)
                user_subscription.last_renewed = timezone.now()
                user_subscription.save()
                serializer = self.get_serializer(user_subscription)
                return Response(serializer.data, status=status.HTTP_200_OK)

            return Response({"message": "This plan does not support renewal."},
                             status=status.HTTP_400_BAD_REQUEST)
        except UserSubscription.DoesNotExist:
            return Response({"message": "No active subscription found to renew."},
                             status=status.HTTP_404_NOT_FOUND)
        
stripe.api_key = settings.STRIPE_SECRET_KEY

class StripeWebhookView(APIView):

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        # Retrieve the request's body as a string
        payload = request.body.decode('utf-8')
        sig_header = request.headers.get('Stripe-Signature')

        event = None

        try:
            # Verify the webhook signature
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )
        except ValueError as e:
            # Invalid payload
            return JsonResponse({'message': 'Invalid payload'}, status=400)
        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            return JsonResponse({'message': 'Invalid signature'}, status=400)

        # Handle the event
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']

            # Get the subscription ID and user ID from the metadata
            subscription_id = session['metadata']['subscription_id']
            user_id = session['metadata']['user_id']

            # Fetch the subscription object
            user_subscription = get_object_or_404(UserSubscription, id=subscription_id, user_id=user_id)
            print("webhook is running successfully")
            # Update subscription status to active
            user_subscription.is_active = True
            user_subscription.save()

            # Optionally: You can set the end date, last renewed, etc.
            # user_subscription.end_date = calculate_end_date_based_on_plan(user_subscription.plan)
            # user_subscription.last_renewed = timezone.now()
            # user_subscription.save()

            # Respond with a success message
            return JsonResponse({'status': 'success'}, status=200)

        # Unexpected event type
        return JsonResponse({'message': 'Event type not supported'}, status=400)
    


class SuccessView(APIView):
    """
    Handle successful Stripe payments. Activate the subscription.
    """

    def get(self, request, subscription_id):
        try:
            subscription = UserSubscription.objects.get(id=subscription_id)

            # Activate the subscription
            subscription.is_active = True
            subscription.start_date = timezone.now()
            subscription.save()

            Notification.objects.create(
                user=subscription.user,
                title="Subscription Activated",
                message=f"Your subscription to {subscription.plan.name} has been activated successfully.",
            )

            return Response({
                "message": "Subscription activated successfully!",
                "subscription_id": subscription.id,
                "plan": subscription.plan.name,
                "user": subscription.user.email,
                "active": subscription.is_active,
                "start_date": subscription.start_date,
            }, status=status.HTTP_200_OK)

        except UserSubscription.DoesNotExist:
            return Response({"error": "Subscription not found."}, status=status.HTTP_404_NOT_FOUND)
        


class CancelPaymentView(APIView):
    """
    Handle cancellation of Stripe payments and deactivate the subscription.
    """

    def post(self, request, subscription_id):
        try:
            subscription = UserSubscription.objects.get(id=subscription_id)

            # Deactivate the subscription
            subscription.is_active = False
            subscription.end_date = timezone.now()  # Set end date as now
            subscription.save()

            return Response({
                "message": "Subscription canceled successfully.",
                "subscription_id": subscription.id,
                "plan": subscription.plan.name,
                "user": subscription.user.email,
                "active": subscription.is_active,
                "end_date": subscription.end_date,
            }, status=status.HTTP_200_OK)

        except UserSubscription.DoesNotExist:
            return Response({"error": "Subscription not found."}, status=status.HTTP_404_NOT_FOUND)
        
     
class QRCodeScanView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request, *args, **kwargs):
        image_file = request.FILES.get('file')
        if not image_file:
            return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Convert image file to PIL Image
        image = Image.open(image_file)

        # Decode QR Code from the image
        decoded_objects = decode(image)
        if not decoded_objects:
            return Response({"error": "No QR code found in the image"}, status=status.HTTP_400_BAD_REQUEST)

        # Extract the link from the QR code
        link = decoded_objects[0].data.decode("utf-8")

        # Save the QR code scan in history
        qr_history = QRCodeHistory.objects.create(user=request.user, link=link)
        qr_history.save()

        # Serialize and return the saved data
        serializer = QRCodeHistorySerializer(qr_history)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    

class QRCodeHistoryListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        history = (QRCodeHistory.objects.filter(user=request.user).order_by('-scanned_at'))
        serializer = QRCodeHistorySerializer(history, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class QRCodeHistoryListDetailsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, id):
        obj = get_object_or_404(QRCodeHistory, user = request.user, id = id)
        obj.delete()
        return Response({"Message":"Successfully deleted!"}  ,status=status.HTTP_204_NO_CONTENT)


class NotificationListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[:10]
        
        if notifications.exists():
            data = [
                {
                    "id": n.id,
                    "user": request.user.id,
                    "title": n.title[:30],
                    "message": n.message[:30],   # first 10 characters
                    "is_read": n.is_read,
                    "created_at": n.created_at
                }
                for n in notifications
            ]
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Notification not found!"}, status=status.HTTP_404_NOT_FOUND)

    

class NotificationDetailsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        data = get_object_or_404(Notification, id = pk)
        data.is_read = True
        data.save()
        serializer = NotificationSerializer(data, many = False)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, pk):
        obj = get_object_or_404(Notification, user = request.user, id = pk)
        obj.delete()
        return Response({"message": "Notification successfully deleted!"}, status=status.HTTP_200_OK)
    

class SuccessView(APIView):
    """
    Handle successful Stripe payments. Activate the subscription.
    """

    def get(self, request, subscription_id):
        try:
            subscription = UserSubscription.objects.get(id=subscription_id)

            # Activate the subscription
            subscription.is_active = True
            subscription.start_date = timezone.now()
            subscription.save()

            Notification.objects.create(
                user=subscription.user,
                title="Subscription Activated",
                message=f"Your subscription to {subscription.plan.name} has been activated successfully.",
            )

            return Response({
                "message": "Subscription activated successfully!",
                "subscription_id": subscription.id,
                "plan": subscription.plan.name,
                "user": subscription.user.email,
                "active": subscription.is_active,
                "start_date": subscription.start_date,
            }, status=status.HTTP_200_OK)

        except UserSubscription.DoesNotExist:
            return Response({"error": "Subscription not found."}, status=status.HTTP_404_NOT_FOUND)
        

class CancelPaymentView(APIView):
    """
    Handle cancellation of Stripe payments and deactivate the subscription.
    """

    def post(self, request, subscription_id):
        try:
            subscription = UserSubscription.objects.get(id=subscription_id)

            # Deactivate the subscription
            subscription.is_active = False
            subscription.end_date = timezone.now()  # Set end date as now
            subscription.save()

            return Response({
                "message": "Subscription canceled successfully.",
                "subscription_id": subscription.id,
                "plan": subscription.plan.name,
                "user": subscription.user.email,
                "active": subscription.is_active,
                "end_date": subscription.end_date,
            }, status=status.HTTP_200_OK)

        except UserSubscription.DoesNotExist:
            return Response({"error": "Subscription not found."}, status=status.HTTP_404_NOT_FOUND)
        

class FeedBackView(APIView):
    permission_classes = [permissions.IsAuthenticated
                          ]
    def post(self, request):
        serializer = FeedBackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)