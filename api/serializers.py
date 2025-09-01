from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from django.contrib.auth.models import User
import random
import string
from django.core.mail import send_mail
from main.models import EmailVerification, Notification, QRCodeHistory, UserProfile, FeedBack
from rest_framework_simplejwt.tokens import RefreshToken
from subscription.models import SubscriptionPlan, UserSubscription
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

    

class UserProfileSerializer(serializers.ModelSerializer):

    first_name = serializers.CharField(source='user.first_name', required=False, allow_blank=True)
    last_name = serializers.CharField(source='user.last_name', required=False, allow_blank=True)
    email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = UserProfile
        fields = ('first_name', 'last_name', 'email', 'bio', 'mobile_number', 'profile_picture')


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

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # raise serializers.ValidationError("Invalid email or password")
            return {"error": "Invalid email or password"}

        if not user.check_password(password):
            # raise serializers.ValidationError("Invalid email or password")
            return {"error": "Invalid email or password"}

        if not user.is_active:
            # raise serializers.ValidationError("User account is not active")
            return {"error": "User account is not active"}

        refresh = RefreshToken.for_user(user)
        return {
            'message': "Login Successfull",
            'user_id': user.id,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value
    
    def create(self, validated_data):
        user = User.objects.get(email = validated_data('email'))
        code = str(random.randint(1000, 9999))

        EmailVerification.objects.create(user = user, code = code)

        send_mail(
            'Password Reset Code',
            f'Your password reset code is {code}',
            'noreply@example.com',
            [user.email],
            fail_silently=False
        )
        return validated_data
    


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def save(self, **kwargs):
        try:
            user = User.objects.get(email=self.validated_data['email'])
            verification = EmailVerification.objects.filter(
                user=user, code=self.validated_data['code']).latest('created_at')

            if verification.is_expired():
                raise serializers.ValidationError("Code has expired.")

            user.set_password(self.validated_data['new_password'])
            user.save()

            # Optionally, delete used codes
            EmailVerification.objects.filter(user=user).delete()

        except (User.DoesNotExist, EmailVerification.DoesNotExist):
            raise serializers.ValidationError("Invalid code or email.")
        




class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'name', 'price', 'duration_days', 'features', 'plan_type']
        orders = ['-price']


class UserSubscriptionSerializer(serializers.ModelSerializer):
    plan = SubscriptionPlanSerializer()  # Nested SubscriptionPlan serializer

    class Meta:
        model = UserSubscription
        fields = ['id', 'user', 'plan', 'start_date', 'end_date', 'is_active', 'last_renewed']
    
    def update(self, instance, validated_data):
        plan_data = validated_data.pop('plan', None)
        if plan_data:
            plan = SubscriptionPlan.objects.get(id=plan_data['id'])
            instance.plan = plan
        return super().update(instance, validated_data)
    


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
