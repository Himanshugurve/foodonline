from django.contrib import admin
from .models import User ,UserProfile
from django.contrib.auth.admin import UserAdmin


class CustomerAdmin(UserAdmin):
    list_display=('email','first_name','last_name','username','role','is_active')
    ordering=('-date_joined',)
    filter_horizontal=()
    list_filter=()
    fieldsets=()

admin.site.register(User,CustomerAdmin)
admin.site.register(UserProfile)


# Register your models here.
