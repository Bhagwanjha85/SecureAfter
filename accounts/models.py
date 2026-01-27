from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

class User(AbstractUser):
    USER_TYPES = (
        ('normal', 'Normal User'),
        ('nominee', 'Nominee'),
        ('admin', 'Admin'),
    )
    
    user_type = models.CharField(max_length=10, choices=USER_TYPES, default='normal')
    phone = models.CharField(max_length=15, blank=True, null=True, unique=True)
    emergency_contact = models.CharField(max_length=15, blank=True, null=True)
    last_active = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    avatar_url = models.CharField(max_length=500, blank=True, null=True)
    about_me = models.TextField(blank=True, null=True)  # ADDED THIS FIELD
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'users'
        
    def __str__(self):
        return f"{self.username} ({self.get_user_type_display()})"
    
    def get_profile_image_url(self):
        """Get profile image URL - prioritize uploaded image over avatar"""
        if self.profile_image:
            return self.profile_image.url
        elif self.avatar_url:
            return self.avatar_url
        return None


class Nominee(models.Model):
    ACCESS_LEVELS = (
        ('view', 'View Only'),
        ('download', 'View and Download'),
        ('notes', 'Notes Only'),
    )
    
    RELATIONSHIP_CHOICES = (
        ('parent', 'Parent'),
        ('spouse', 'Spouse'),
        ('sibling', 'Sibling'),
        ('child', 'Child'),
        ('friend', 'Friend'),
        ('other', 'Other'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='nominees')
    nominee_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='nominated_by', null=True, blank=True)
    nominee_name = models.CharField(max_length=100)
    nominee_email = models.EmailField()
    nominee_phone = models.CharField(max_length=15)
    relationship = models.CharField(max_length=20, choices=RELATIONSHIP_CHOICES)
    access_level = models.CharField(max_length=10, choices=ACCESS_LEVELS, default='view')
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=6, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'nominees'
        unique_together = ('user', 'nominee_email')
        
    def __str__(self):
        return f"{self.nominee_name} (Nominee of {self.user.username})"


class OTPVerification(models.Model):
    """
    Model to store OTP records for email and phone verification
    Used for registration and nominee addition
    """
    OTP_TYPES = (
        ('registration_email', 'Registration Email'),
        ('registration_phone', 'Registration Phone'),
        ('nominee_email', 'Nominee Email'),
        ('nominee_phone', 'Nominee Phone'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otp_records', null=True, blank=True)
    nominee = models.ForeignKey(Nominee, on_delete=models.CASCADE, related_name='otp_records', null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    phone = models.CharField(max_length=15, null=True, blank=True)
    otp_code = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPES)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=5)
    
    class Meta:
        db_table = 'otp_verifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'otp_type']),
            models.Index(fields=['phone', 'otp_type']),
            models.Index(fields=['is_verified', 'expires_at']),
        ]
        
    def __str__(self):
        return f"OTP for {self.email or self.phone} ({self.get_otp_type_display()})"
    
    def is_expired(self):
        """Check if OTP has expired"""
        return timezone.now() > self.expires_at
    
    def is_attempt_limit_reached(self):
        """Check if max attempts reached"""
        return self.attempts >= self.max_attempts
    
    def increment_attempts(self):
        """Increment attempt count"""
        self.attempts += 1
        self.save(update_fields=['attempts'])