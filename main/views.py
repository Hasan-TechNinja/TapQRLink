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
    