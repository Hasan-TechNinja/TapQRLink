from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from django.contrib.auth.models import User
import random
import string
from django.core.mail import send_mail
from main.models import EmailVerification, Notification, QRCodeHistory, UserProfile, FeedBack
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.db import transaction
from main.utils import generate_otp, otp_expiry, send_verification_email, get_default_password
from django.utils.timezone import localtime
import re

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
    access = serializers.CharField(required=False, allow_blank=True)
    new_password = serializers.CharField(
        write_only=True, min_length=8, style={'input_type': 'password'}
    )
    confirm_password = serializers.CharField(
        write_only=True, min_length=8, style={'input_type': 'password'}
    )

    def validate(self, attrs):
        new_password = attrs.get("new_password")
        confirm_password = attrs.get("confirm_password")

        # Check if both fields are provided
        if not new_password:
            raise serializers.ValidationError({"new_password": "New password is required."})
        if not confirm_password:
            raise serializers.ValidationError({"confirm_password": "Confirm password is required."})

        # Check if passwords match
        if new_password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "do not match."})

        # Validate strength
        errors = []
        if len(new_password) < 8:
            errors.append("be at least 8 characters long")
        if not re.search(r"[a-z]", new_password):
            errors.append("contain at least one lowercase letter")
        if not re.search(r"[A-Z]", new_password):
            errors.append("contain at least one uppercase letter")
        if not re.search(r"\d", new_password):
            errors.append("contain at least one number")
        if not re.search(r"[@$!%*?&#^()_=+{};:,<.>]", new_password):
            errors.append("contain at least one special character (e.g. @, #, $, %)")

        if errors:
            # Simplify the language for readability
            combined = self._combine_errors(errors)
            raise serializers.ValidationError({"password": f"must {combined}."})

        return attrs

    def _combine_errors(self, errors):
        """
        Combine multiple password rules into a smoother sentence:
        - Merges repeated 'contain at least one' into one.
        """
        # Separate rules that start with "contain at least one"
        contain_rules = []
        other_rules = []

        for e in errors:
            if e.startswith("contain at least one "):
                contain_rules.append(e.replace("contain at least one ", ""))
            else:
                other_rules.append(e)

        parts = []
        if other_rules:
            parts.append(", ".join(other_rules))
        if contain_rules:
            if len(contain_rules) == 1:
                parts.append(f"contain at least one {contain_rules[0]}")
            else:
                parts.append(f"contain at least one {', '.join(contain_rules[:-1])}, and {contain_rules[-1]}")

        return " and ".join(parts)
    

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
    last_name  = serializers.CharField(source='user.last_name',  required=False, allow_blank=True)
    email      = serializers.EmailField(source='user.email', read_only=True)
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = UserProfile
        fields = ('first_name', 'last_name', 'email', 'bio', 'mobile_number', 'profile_picture', 'subscription_expires_at')

    def to_representation(self, instance):
        """Return absolute URL for profile_picture instead of file info."""
        rep = super().to_representation(instance)
        pic = getattr(instance, 'profile_picture', None)
        if pic:
            request = self.context.get('request')
            url = pic.url
            rep['profile_picture'] = request.build_absolute_uri(url) if request else url
        else:
            rep['profile_picture'] = None
        return rep

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        for attr, value in user_data.items():
            setattr(instance.user, attr, value)
        instance.user.save()

        if 'profile_picture' in validated_data:
            new_file = validated_data.pop('profile_picture')
            if new_file is None:
                if instance.profile_picture:
                    instance.profile_picture.delete(save=False)
                instance.profile_picture = None
            else:
                instance.profile_picture = new_file

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
    new_password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)

    def validate(self, attrs):
        new_password = attrs.get("new_password")
        confirm_password = attrs.get("confirm_password")

        if not new_password:
            raise serializers.ValidationError({"new_password": "New password is required."})
        if not confirm_password:
            raise serializers.ValidationError({"confirm_password": "Confirm password is required."})

        if new_password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "do not match."})

        # Password strength validation
        errors = []
        if len(new_password) < 8:
            errors.append("be at least 8 characters long")
        if not re.search(r"[a-z]", new_password):
            errors.append("contain at least one lowercase letter")
        if not re.search(r"[A-Z]", new_password):
            errors.append("contain at least one uppercase letter")
        if not re.search(r"\d", new_password):
            errors.append("contain at least one number")
        if not re.search(r"[@$!%*?&#^()_=+{};:,<.>]", new_password):
            errors.append("contain at least one special character (e.g. @, #, $, %)")

        if errors:
            raise serializers.ValidationError({"password": f"Password must {self._combine_errors(errors)}."})

        return attrs

    def _combine_errors(self, errors):
        """ Merge repeated 'contain at least one' into a single phrase. """
        contain_rules = []
        other_rules = []
        for e in errors:
            if e.startswith("contain at least one "):
                contain_rules.append(e.replace("contain at least one ", ""))
            else:
                other_rules.append(e)

        parts = []
        if other_rules:
            parts.append(", ".join(other_rules))
        if contain_rules:
            if len(contain_rules) == 1:
                parts.append(f"contain at least one {contain_rules[0]}")
            else:
                parts.append(f"contain at least one {', '.join(contain_rules[:-1])}, and {contain_rules[-1]}")

        return " and ".join(parts)



class QRCodeHistorySerializer(serializers.ModelSerializer):
    image = serializers.SerializerMethodField()           # <-- make image a method field
    scanned_at = serializers.SerializerMethodField()

    class Meta:
        model = QRCodeHistory
        fields = ['id', 'user', 'link', 'image', 'is_read', 'scanned_at']

    def get_image(self, obj):                             # <-- name must match the field: image
        if not obj.image:
            return None
        request = self.context.get("request")
        url = obj.image.url
        return request.build_absolute_uri(url) if request else url

    def get_scanned_at(self, obj):
        return localtime(obj.scanned_at).strftime("%I.%M %p, %d %B %Y")


class NotificationSerializer(serializers.ModelSerializer):
    created_at = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = ["id", "user", "title", "message", "is_read", "created_at"]
        read_only_fields = ["created_at"]

    def get_created_at(self, obj):
        return localtime(obj.created_at).strftime("%I.%M %p, %d %B %Y")


class FeedBackSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeedBack
        fields = ["id", "text", "created_at"]
