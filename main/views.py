from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import UserProfile, QRCodeHistory, Notification, GuideVideo
from .serializers import GuideVideoSerializer
# Create your views here.


class GuideVideoListView(APIView):
    def get(self, request):
        videos = GuideVideo.objects.all()
        serializer = GuideVideoSerializer(videos, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


from django.http import HttpResponse
import os
from django.conf import settings

def app_ads_txt(request):
    file_path = os.path.join(settings.BASE_DIR, 'app-ads.txt')
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    else:
        content = "google.com, pub-8492413081634752, DIRECT, f08c47fec0942fa0\n"
    return HttpResponse(content, content_type="text/plain; charset=utf-8")