from django.db import models
from django.conf import settings
from django.utils import timezone

class Reminder(models.Model):
    REMINDER_TYPES = (
        ('document_expiry', 'Document Expiry'),
        ('insurance_renewal', 'Insurance Renewal'),
        ('custom', 'Custom Reminder'),
    )
    
    FREQUENCY_CHOICES = (
        ('once', 'One Time'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reminders')
    document = models.ForeignKey('vault.Document', on_delete=models.CASCADE, related_name='reminders', null=True, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    reminder_type = models.CharField(max_length=20, choices=REMINDER_TYPES, default='custom')
    reminder_date = models.DateTimeField()
    frequency = models.CharField(max_length=10, choices=FREQUENCY_CHOICES, default='once')
    is_active = models.BooleanField(default=True)
    is_sent = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'reminders'
        ordering = ['reminder_date']
        
    def __str__(self):
        return f"{self.title} - {self.user.username}"
    
    def should_send(self):
        return self.is_active and not self.is_sent and self.reminder_date <= timezone.now()

class ReminderLog(models.Model):
    reminder = models.ForeignKey(Reminder, on_delete=models.CASCADE, related_name='logs')
    sent_at = models.DateTimeField(auto_now_add=True)
    is_successful = models.BooleanField(default=True)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'reminder_logs'
        ordering = ['-sent_at']
        
    def __str__(self):
        return f"Reminder Log - {self.reminder.title} at {self.sent_at}"