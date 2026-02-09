from django.urls import path
from . import views


urlpatterns = [
    path('guide-videos/', views.GuideVideoListView.as_view(), name='guide_video_list'),
]