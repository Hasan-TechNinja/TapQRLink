from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from django.conf import settings
from django.conf.urls.static import static


router = DefaultRouter()
router.register(r'user-subscriptions', views.UserSubscriptionViewSet, basename='user-subscription')

urlpatterns = [
    path('subscription-plans/', views.SubscriptionPlanView.as_view(), name='subscription-plans'),
    path('webhooks/stripe/', views.StripeWebhookView.as_view(), name='stripe-webhook'),
    path('', include(router.urls)),
    path('payments/success/<int:subscription_id>/', views.SuccessView.as_view(), name='payment-success'),  # Updated
    path('payments/cancel/', views.CancelPaymentView.as_view(), name='payment-cancel'),
]

