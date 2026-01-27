from django.contrib import admin
from .models import EmergencyTrigger, EmergencyAccess, AccessLog

@admin.register(EmergencyTrigger)
class EmergencyTriggerAdmin(admin.ModelAdmin):
    list_display = ('user', 'trigger_type', 'is_active', 'created_at')
    list_filter = ('trigger_type', 'is_active')
    search_fields = ('user__username',)

@admin.register(EmergencyAccess)
class EmergencyAccessAdmin(admin.ModelAdmin):
    list_display = ('user', 'nominee', 'status', 'granted_at', 'expires_at', 'access_count')
    list_filter = ('status',)
    search_fields = ('user__username', 'nominee__nominee_name')
    readonly_fields = ('granted_at', 'accessed_at', 'revoked_at')

@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('emergency_access', 'action', 'created_at')
    list_filter = ('action',)
    readonly_fields = ('created_at',)