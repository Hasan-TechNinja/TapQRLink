from rest_framework import serializers
from .models import UserProfile, QRCodeHistory, Notification, GuideVideo

class GuideVideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = GuideVideo
        fields = '__all__'