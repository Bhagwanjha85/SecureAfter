from django.db import models
from django.conf import settings
from django.utils import timezone
import os

def user_directory_path(instance, filename):
    return f'user_{instance.user.id}/documents/{filename}'

class Vault(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='vault')
    is_encrypted = models.BooleanField(default=True)
    encryption_key_hash = models.CharField(max_length=256, blank=True, null=True)
    total_documents = models.IntegerField(default=0)
    total_size = models.BigIntegerField(default=0)  # in bytes
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'vaults'
        
    def __str__(self):
        return f"Vault of {self.user.username}"

class Document(models.Model):
    CATEGORY_CHOICES = (
        ('id', 'ID Documents'),
        ('medical', 'Medical Records'),
        ('insurance', 'Insurance'),
        ('property', 'Property Documents'),
        ('financial', 'Financial Documents'),
        ('legal', 'Legal Documents'),
        ('other', 'Other'),
    )
    
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE, related_name='documents')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='documents')
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    description = models.TextField(blank=True, null=True)
    file = models.FileField(upload_to=user_directory_path)
    file_size = models.BigIntegerField(default=0)
    file_type = models.CharField(max_length=50, blank=True, null=True)
    is_encrypted = models.BooleanField(default=True)
    encryption_metadata = models.JSONField(default=dict, blank=True)
    is_accessible_by_nominee = models.BooleanField(default=False)
    expiry_date = models.DateField(blank=True, null=True)
    reminder_set = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'documents'
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.title} - {self.user.username}"
    
    def delete(self, *args, **kwargs):
        # Delete file from storage
        if self.file:
            if os.path.isfile(self.file.path):
                os.remove(self.file.path)
        super().delete(*args, **kwargs)

class EmergencyInstructions(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='emergency_instructions')
    emergency_message = models.TextField(blank=True, null=True)
    medical_consent = models.TextField(blank=True, null=True)
    family_guidance = models.TextField(blank=True, null=True)
    additional_notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'emergency_instructions'
        verbose_name_plural = 'Emergency Instructions'
        
    def __str__(self):
        return f"Emergency Instructions - {self.user.username}"

class SiteStatistics(models.Model):
    total_visitors = models.BigIntegerField(default=0)
    
    class Meta:
        verbose_name_plural = "Site Statistics"
        
    def __str__(self):
        return f"Total Visitors: {self.total_visitors}"