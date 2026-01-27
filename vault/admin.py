from django.contrib import admin
from .models import Vault, Document, EmergencyInstructions, SiteStatistics

@admin.register(Vault)
class VaultAdmin(admin.ModelAdmin):
    list_display = ('user', 'total_documents', 'is_encrypted', 'created_at')
    list_filter = ('is_encrypted',)
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'category', 'file_size', 'is_encrypted', 'created_at')
    list_filter = ('category', 'is_encrypted', 'is_accessible_by_nominee')
    search_fields = ('title', 'user__username', 'description')
    readonly_fields = ('created_at', 'updated_at', 'file_size')
    ordering = ('-created_at',)
    
    # IMPORTANT: Admin should NOT be able to download files
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False

@admin.register(EmergencyInstructions)
class EmergencyInstructionsAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'updated_at')
    search_fields = ('user__username',)
    readonly_fields = ('created_at', 'updated_at')

@admin.register(SiteStatistics)
class SiteStatisticsAdmin(admin.ModelAdmin):
    list_display = ('total_visitors',)
    
    def has_add_permission(self, request):
        # Prevent creating multiple counter instances
        return not SiteStatistics.objects.exists()