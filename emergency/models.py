from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

class EmergencyTrigger(models.Model):
    TRIGGER_TYPES = (
        ('inactivity', 'Inactivity Period'),
        ('manual', 'Manual Emergency Button'),
        ('scheduled', 'Scheduled Date'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='emergency_triggers')
    trigger_type = models.CharField(max_length=20, choices=TRIGGER_TYPES)
    inactivity_days = models.IntegerField(default=90, null=True, blank=True)
    scheduled_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    require_mfa = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'emergency_triggers'
        
    def __str__(self):
        return f"{self.user.username} - {self.get_trigger_type_display()}"

class EmergencyAccess(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending Verification'),
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='emergency_access_granted')
    nominee = models.ForeignKey('accounts.Nominee', on_delete=models.CASCADE, related_name='emergency_accesses')
    trigger = models.ForeignKey(EmergencyTrigger, on_delete=models.CASCADE, related_name='accesses', null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    access_token = models.CharField(max_length=100, unique=True)
    verification_code = models.CharField(max_length=6, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    accessed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    access_count = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'emergency_accesses'
        ordering = ['-granted_at']
        
    def __str__(self):
        return f"Emergency Access: {self.nominee.nominee_name} for {self.user.username}"
    
    def is_valid(self):
        return self.status == 'active' and self.expires_at > timezone.now()
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=48)
        super().save(*args, **kwargs)

class AccessLog(models.Model):
    ACTION_CHOICES = (
        ('view', 'Viewed Document'),
        ('download', 'Downloaded Document'),
        ('access_instructions', 'Accessed Instructions'),
        ('login', 'Login Attempt'),
        ('logout', 'Logout'),
    )
    
    emergency_access = models.ForeignKey(EmergencyAccess, on_delete=models.CASCADE, related_name='logs')
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    document = models.ForeignKey('vault.Document', on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'access_logs'
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.action} - {self.created_at}"