from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('profile/', views.UserProfileView.as_view(), name='user_profile'),
]