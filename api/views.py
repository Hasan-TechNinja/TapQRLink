from django.shortcuts import get_object_or_404, render, redirect
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
# from subscription.models import SubscriptionPlan, UserSubscription
from .serializers import EmailTokenObtainPairSerializer, NotificationSerializer, PasswordResetConfirmSerializer, RegistrationSerializer, QRCodeHistorySerializer, ResendCodeSerializer, UserProfileSerializer, FeedBackSerializer, SetInitialPasswordSerializer

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
from django.views.decorators.csrf import csrf_exempt



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
                "user": user.id,
                "refresh": str(refresh),
                "access": str(access_token)
            },
            status=status.HTTP_200_OK
        )
   

class ResendVerificationCodeView(APIView):
    permission_classes = [permissions.AllowAny]

    @transaction.atomic
    def post(self, request):
        serializer = ResendCodeSerializer(data=request.data)
        if not serializer.is_valid():
            # Manually flatten response
            errors = {}
            for field, messages in serializer.errors.items():
                # Take the first message if it's a list
                errors[field] = messages[0] if isinstance(messages, list) else messages
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data["user"]

        # Basic throttle: 60 seconds since last send
        last = EmailVerification.objects.filter(user=user).order_by("-created_at").first()
        if last and last.last_sent_at and (timezone.now() - last.last_sent_at).total_seconds() < 60:
            return Response(
                {"message": "A verification code was just sent. Please check your email."},
                status=status.HTTP_200_OK
            )

        # Clear old records and create a new code
        EmailVerification.objects.filter(user=user).delete()
        code = generate_otp()
        EmailVerification.objects.create(
            user=user,
            code=code,
            expires_at=otp_expiry(3),  # 3 minutes validity; adjust as needed
        )
        send_verification_email(user.email, code)

        return Response(
            {"message": "A new verification code has been sent to your email."},
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

            # Delete any existing reset codes
            PasswordResetCode.objects.filter(user=user).delete()

            # Generate a new reset code
            code = str(random.randint(1000, 9999))
            PasswordResetCode.objects.create(user=user, code=code)

            # Prepare the user's name for the email
            if user.first_name and user.last_name:
                name = f"{user.first_name} {user.last_name}"
            elif user.email:
                name = user.email
            else:
                name = user.username

            # Send reset email
            send_mail(
                subject='Password Reset Request',
                message=(
                    f"Hello, {name}\n"
                    "We received a request to reset your account password.\n"
                    f"Your password reset code is: {code}\n\n"
                    "If you did not request this, please ignore this email.\n"
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



class PasswordResetCodeCheckView(APIView):
    permission_classes = [permissions.AllowAny]

    @csrf_exempt
    def post(self, request):
        email = request.data.get('email')
        user_code = request.data.get('code')

        if not email:
            return Response({'error': 'Email is required!'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user_code:
            return Response({"error": "Code is required!"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found!"}, status=status.HTTP_404_NOT_FOUND)

        password_reset_code = PasswordResetCode.objects.filter(user=user, code=user_code).first()
        if not password_reset_code:
            return Response({"error": "Invalid or expired code."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Code is correct. You can now set your new password."}, status=status.HTTP_200_OK)



class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        # Serialize and validate the incoming data
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            new_password = serializer.validated_data['new_password']

            # Check if the user exists
            try:
                user = User.objects.get(email=email)

                # Optionally, check for matching passwords (confirm password can be added)
                password_reset = PasswordResetCode.objects.filter(user=user).first()

                if not password_reset:
                    return Response({"error": "Invalid or expired reset code."}, status=status.HTTP_400_BAD_REQUEST)

                # Update the user's password
                user.password = make_password(new_password)
                user.save()

                # Delete the reset code after use
                password_reset.delete()

                return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)

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
       

class FeedBackView(APIView):
    permission_classes = [permissions.IsAuthenticated
                          ]
    def post(self, request):
        serializer = FeedBackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)