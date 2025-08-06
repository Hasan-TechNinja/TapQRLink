from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions

from main.models import EmailVerification, Notification, PasswordResetCode, UserProfile
from .serializers import EmailTokenObtainPairSerializer, PasswordResetConfirmSerializer, RegistrationSerializer, UserProfileSerializer

from rest_framework import permissions
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
import random
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken


# Create your views here.
class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        
        existing_user = User.objects.filter(email=email).first()
        
        if existing_user:
            # If the user exists but is not active, resend the verification code
            if not existing_user.is_active:
                # Delete any previous OTP code (if exists)
                EmailVerification.objects.filter(user=existing_user).delete()

                # Generate a new verification code
                code = str(random.randint(1000, 9999))
                EmailVerification.objects.create(user=existing_user, code=code)

                send_mail(
                    'Your New Verification Code',
                    f'Hi, {email}\n\nYour new verification code is {code}',
                    'noreply@example.com',
                    [email],
                    fail_silently=False
                )

                return Response({"message": "A new verification code has been sent to your email."}, status=status.HTTP_200_OK)
            
            # If the user is active, inform that email is already in use
            return Response({"error": "This email is already in use by an active account."}, status=status.HTTP_400_BAD_REQUEST)
        
        # If the email does not exist, proceed with the registration process
        serializer = RegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()

            # Generate refresh token and access token using Simple JWT
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            # Send a notification about successful registration
            Notification.objects.create(
                user=user,
                title="Registration Successful",
                message="Welcome to One StepCoach! Your account has been created successfully.",
            )

            return Response({'refresh': str(refresh)}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        code = request.data.get('code')
        email = request.data.get('email')

        if not code or not email:
            return Response({"error": "Code and email are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            verification = EmailVerification.objects.get(user=user)

            if verification.code == code:
                if verification.is_expired():
                    return Response({"error": "Verification code has expired."}, status=status.HTTP_400_BAD_REQUEST)

                user.is_active = True
                user.save()

                verification.delete()

                login(request, user)

                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token

                return Response({
                    'message': 'Email verified successfully and user logged in.',
                    'access': str(access_token),
                    'refresh': str(refresh)
                }, status=status.HTTP_200_OK)

            else:
                return Response({"error": "Invalid verification code."}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except EmailVerification.DoesNotExist:
            return Response({"error": "No verification record found for this user."}, status=status.HTTP_404_NOT_FOUND)
        


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

            send_mail(
                'Your Password Reset Code',
                f'Hi, {email}\n\nYour password reset code is {code}',
                'noreply@example.com',
                [email],
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

                return Response({'detail': 'Password has been reset.'}, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")

        if refresh_token is None:
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create token object from the refresh token string
            token = RefreshToken(refresh_token)

            # Blacklist the token
            token.blacklist()

            return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)

        except InvalidToken:
            return Response({"detail": "The token is invalid or expired."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({"detail": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)