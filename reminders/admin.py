from django.contrib import admin
from .models import Reminder, ReminderLog

@admin.register(Reminder)
class ReminderAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'reminder_type', 'reminder_date', 'is_active', 'is_sent')
    list_filter = ('reminder_type', 'frequency', 'is_active', 'is_sent')
    search_fields = ('title', 'user__username', 'description')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('reminder_date',)

@admin.register(ReminderLog)
class ReminderLogAdmin(admin.ModelAdmin):
    list_display = ('reminder', 'sent_at', 'is_successful')
    list_filter = ('is_successful', 'sent_at')
    search_fields = ('reminder__title', 'error_message')
    readonly_fields = ('sent_at',)
    ordering = ('-sent_at',)
