from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter
from django.conf.urls.static import static

router = DefaultRouter()
router.register(r'user-subscriptions', views.UserSubscriptionViewSet, basename='user-subscription')

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('profile/', views.UserProfileView.as_view(), name='user_profile'),
    path('login/', views.EmailLoginView.as_view(), name='email-login'),
    path('password-reset/request/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

    path('subscription-plans/', views.SubscriptionPlanView.as_view(), name='report'),
    path('webhooks/stripe/', views.StripeWebhookView.as_view(), name='stripe-webhook'),
    path('', include(router.urls)),
]   