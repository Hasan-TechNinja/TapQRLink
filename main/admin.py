from django.contrib import admin
from .models import UserProfile, EmailVerification

# Register your models here.

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'bio', 'mobile_number', 'profile_picture')
    search_fields = ('user__username', 'user__email')
admin.site.register(UserProfile, UserProfileAdmin)