from django.urls import path
from . import views


urlpatterns = [
    path('privacy-policy/', views.privacy_policy_view, name='main_privacy_policy'),
    path('terms-and-conditions/', views.terms_and_conditions_view, name='main_terms_and_conditions'),
    path('guide-videos/', views.GuideVideoListView.as_view(), name='guide_video_list'),
]