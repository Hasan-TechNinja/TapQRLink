from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from django.contrib.auth.models import User
import random
import string
from django.core.mail import send_mail
from main.models import EmailVerification, Notification, QRCodeHistory, UserProfile, FeedBack
from rest_framework_simplejwt.tokens import RefreshToken
# from subscription.models import SubscriptionPlan, UserSubscription
from django.contrib.auth import get_user_model
from django.db import transaction
from main.utils import generate_otp, otp_expiry, send_verification_email, get_default_password

User = get_user_model()

class RegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all(),
                                    message="This email is already in use.")]
    )
    # Validate uniqueness against UserProfile.mobile_number (NOT User)
    mobile = serializers.CharField(required=True)
    first_name = serializers.CharField(required=True, max_length=150)
    last_name = serializers.CharField(required=True, max_length=150)

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "mobile")

    def validate_mobile(self, value):
        if UserProfile.objects.filter(mobile_number=value).exists():
            raise serializers.ValidationError("This mobile is already in use.")
        return value

    def generate_username(self, base):
        base = base or "user"
        username = base
        while User.objects.filter(username=username).exists():
            suffix = "".join(random.choices(string.digits, k=4))
            username = f"{base}_{suffix}"
        return username

    @transaction.atomic
    def create(self, validated_data):
        first_name = validated_data["first_name"]
        last_name = validated_data["last_name"]
        email = validated_data["email"]
        mobile = validated_data["mobile"]

        base_username = email.split("@")[0]
        username = self.generate_username(base_username)
        default_password = get_default_password()

        user = User.objects.create_user(
            username=username,
            email=email,
            password=default_password,
            first_name=first_name,
            last_name=last_name,
            is_active=False,
        )

        # Ensure a profile exists and store the phone from registration
        # (signal also creates, but this is idempotent and sets the number)
        UserProfile.objects.update_or_create(
            user=user,
            defaults={"mobile_number": mobile}
        )

        # OTP flow
        EmailVerification.objects.filter(user=user).delete()
        code = generate_otp()
        EmailVerification.objects.create(
            user=user,
            code=code,
            expires_at=otp_expiry(10),
        )
        send_verification_email(email, code)

        return user


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=4, max_length=6)

    def validate(self, attrs):
        email = attrs.get("email")
        code = attrs.get("code")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "No account found for this email."})

        try:
            record = EmailVerification.objects.filter(user=user).latest("created_at")
        except EmailVerification.DoesNotExist:
            raise serializers.ValidationError({"code": "No verification code found. Please request a new one."})

        if record.code != code:
            raise serializers.ValidationError({"code": "Invalid verification code."})

        if record.is_expired():
            raise serializers.ValidationError({"code": "Verification code has expired. Please request a new one."})

        attrs["user"] = user
        attrs["record"] = record
        return attrs


User = get_user_model()

class SetInitialPasswordSerializer(serializers.Serializer):
    # Optional if you use Authorization header; required if you pass token in body
    access = serializers.CharField(required=False, allow_blank=True)
    new_password = serializers.CharField(write_only=True, min_length=8, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, min_length=8, style={'input_type': 'password'})

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return attrs

    def validate_new_password(self, value):
        validate_password(value)
        return value
    

class ResendCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs["email"].strip().lower()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "No account found for this email."})

        if user.is_active:
            # Already active: nothing to resend
            raise serializers.ValidationError({"email": "This account is already active."})

        attrs["user"] = user
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', required=False, allow_blank=True)
    last_name = serializers.CharField(source='user.last_name', required=False, allow_blank=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = ('first_name', 'last_name', 'email', 'bio', 'mobile_number', 'profile_picture')

    def get_profile_picture(self, obj):
        """Returns the absolute URL of the profile picture."""
        request = self.context.get('request')
        if obj.profile_picture:
            return request.build_absolute_uri(obj.profile_picture.url)
        return None

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        for attr, value in user_data.items():
            setattr(instance.user, attr, value)
        instance.user.save()

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        return instance
    
    

class EmailTokenObtainPairSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # You can add custom validation if needed, like checking if the user exists
        return value


class PasswordResetCodeCheckSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=4, max_length=4)  # Assumes the reset code is 4 digits


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(min_length=8, write_only=True)  # Custom password validation can be added if needed
    confirm_password = serializers.CharField(min_length=8, write_only=True)




class QRCodeHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = QRCodeHistory
        fields = ['id', 'user', 'link', 'scanned_at']



class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["id", "user", "title", "message", "is_read", "created_at"]
        read_only_fields = ["created_at"]
        

class FeedBackSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeedBack
        fields = ["id", "text", "created_at"]
