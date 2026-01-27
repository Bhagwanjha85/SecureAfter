from django.db import models
from django.conf import settings

class AuditLog(models.Model):
    ACTION_TYPES = (
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('failed_login', 'Failed Login Attempt'),
        ('document_upload', 'Document Upload'),
        ('document_view', 'Document View'),
        ('document_download', 'Document Download'),
        ('document_delete', 'Document Delete'),
        ('nominee_add', 'Nominee Added'),
        ('nominee_remove', 'Nominee Removed'),
        ('emergency_trigger', 'Emergency Triggered'),
        ('emergency_access', 'Emergency Access Granted'),
        ('settings_change', 'Settings Changed'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=30, choices=ACTION_TYPES)
    description = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['action', '-created_at']),
        ]
        
    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"{username} - {self.get_action_display()} at {self.created_at}"

class SecurityAlert(models.Model):
    ALERT_TYPES = (
        ('failed_login', 'Multiple Failed Logins'),
        ('suspicious_access', 'Suspicious Access Pattern'),
        ('unauthorized_attempt', 'Unauthorized Access Attempt'),
        ('data_breach', 'Potential Data Breach'),
    )
    
    SEVERITY_LEVELS = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='security_alerts', null=True, blank=True)
    alert_type = models.CharField(max_length=30, choices=ALERT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='medium')
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'security_alerts'
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.get_alert_type_display()} - {self.severity}"