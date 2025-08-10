from django.contrib import admin
from .models import UserProfile, EmailVerification, QRCodeHistory, Notification

# Register your models here.

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'bio', 'mobile_number', 'profile_picture')
    search_fields = ('user__username', 'user__email')
admin.site.register(UserProfile, UserProfileAdmin)


class QRCodeHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'link', 'scanned_at')
    search_fields = ('user__username', 'link')
admin.site.register(QRCodeHistory, QRCodeHistoryAdmin)


class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'title', 'is_read', 'created_at')
    search_fields = ('user__username', 'title')
admin.site.register(Notification, NotificationAdmin)