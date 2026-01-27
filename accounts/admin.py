from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Nominee

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'user_type', 'is_active', 'created_at')
    list_filter = ('user_type', 'is_active', 'is_staff')
    search_fields = ('username', 'email', 'phone')
    ordering = ('-created_at',)
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('user_type', 'phone', 'emergency_contact', 'is_verified')
        }),
    )

@admin.register(Nominee)
class NomineeAdmin(admin.ModelAdmin):
    list_display = ('nominee_name', 'user', 'nominee_email', 'relationship', 'access_level', 'is_active', 'created_at')
    list_filter = ('relationship', 'access_level', 'is_active')
    search_fields = ('nominee_name', 'nominee_email', 'user__username')
    ordering = ('-created_at',)