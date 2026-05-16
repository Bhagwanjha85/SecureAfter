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
    about_me = models.TextField(blank=True, null=True)
    unique_id = models.CharField(max_length=20, unique=True, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def save(self, *args, **kwargs):
        if not self.unique_id:
            import string, random
            chars = string.ascii_uppercase + string.digits
            while True:
                new_id = f"SA-{''.join(random.choices(chars, k=8))}"
                if not User.objects.filter(unique_id=new_id).exists():
                    self.unique_id = new_id
                    break
        super().save(*args, **kwargs)
    
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
        ('full', 'Full Access'),
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
    can_add_nominees = models.BooleanField(default=False)
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


# =====================================================
# SMART EMERGENCY TRIGGER SYSTEM MODELS
# =====================================================

class EmergencySettings(models.Model):
    """
    Stores user preferences for the Smart Emergency Trigger System
    Dead Man's Switch configuration
    """
    CHECK_IN_INTERVALS = (
        (10, '10 Days'),
        (15, '15 Days'),
        (20, '20 Days'),
        (30, '30 Days'),
        (45, '45 Days'),
        (60, '60 Days'),
    )
    
    DELAY_OPTIONS = (
        (3, '3 Days'),
        (5, '5 Days'),
        (7, '7 Days'),
        (10, '10 Days'),
        (14, '14 Days'),
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='emergency_settings')
    
    # Dead Man's Switch Configuration
    is_enabled = models.BooleanField(default=False)
    check_in_interval = models.IntegerField(choices=CHECK_IN_INTERVALS, default=30)
    grace_period = models.IntegerField(choices=DELAY_OPTIONS, default=7)  # Buffer before access
    
    # Alert thresholds
    missed_checkins_for_reminder = models.IntegerField(default=1)
    missed_checkins_for_urgent = models.IntegerField(default=2)
    missed_checkins_for_emergency = models.IntegerField(default=3)
    
    # Auto-trigger settings
    auto_trigger_emergency = models.BooleanField(default=True)
    notify_nominees_on_missed = models.BooleanField(default=True)
    
    # Last check-in tracking
    last_check_in = models.DateTimeField(null=True, blank=True)
    next_check_in_due = models.DateTimeField(null=True, blank=True)
    
    # Emergency state
    is_emergency_triggered = models.BooleanField(default=False)
    emergency_triggered_at = models.DateTimeField(null=True, blank=True)
    emergency_access_unlocked_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'emergency_settings'
        verbose_name_plural = 'Emergency Settings'
    
    def __str__(self):
        return f"Emergency Settings - {self.user.username}"
    
    def calculate_next_check_in(self):
        """Calculate next check-in date based on interval"""
        from datetime import timedelta
        if self.last_check_in:
            self.next_check_in_due = self.last_check_in + timedelta(days=self.check_in_interval)
        else:
            self.next_check_in_due = timezone.now() + timedelta(days=self.check_in_interval)
        self.save(update_fields=['next_check_in_due'])
        return self.next_check_in_due
    
    def is_overdue(self):
        """Check if user has missed their check-in"""
        if not self.next_check_in_due:
            return False
        return timezone.now() > self.next_check_in_due
    
    def get_missed_checkins_count(self):
        """Calculate how many check-ins have been missed"""
        if not self.last_check_in or not self.next_check_in_due:
            return 0
        
        from datetime import timedelta
        now = timezone.now()
        
        if now <= self.next_check_in_due:
            return 0
        
        # Calculate missed check-ins
        interval = self.check_in_interval
        time_diff = now - self.last_check_in
        days_passed = time_diff.days
        
        missed = (days_passed // interval) - 1
        return max(0, missed)


class CheckInRecord(models.Model):
    """
    Tracks each check-in made by the user
    """
    STATUS_CHOICES = (
        ('on_time', 'On Time'),
        ('late', 'Late'),
        ('missed', 'Missed'),
        ('auto', 'Automatic'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='check_in_records')
    emergency_settings = models.ForeignKey('EmergencySettings', on_delete=models.CASCADE, related_name='check_in_records', null=True, blank=True)
    check_in_time = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='on_time')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'check_in_records'
        ordering = ['-check_in_time']
    
    def __str__(self):
        return f"Check-in by {self.user.username} at {self.check_in_time}"


class EmergencyAlert(models.Model):
    """
    Tracks all emergency alerts sent to user and nominees
    """
    ALERT_TYPES = (
        ('reminder', 'Check-in Reminder'),
        ('urgent', 'Urgent Alert'),
        ('emergency', 'Emergency Triggered'),
        ('access_unlocked', 'Access Unlocked'),
        ('nominee_request', 'Nominee Access Request'),
    )
    
    ALERT_CHANNELS = (
        ('email', 'Email'),
        ('sms', 'SMS'),
        ('push', 'Push Notification'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='emergency_alerts')
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    channel = models.CharField(max_length=10, choices=ALERT_CHANNELS)
    recipient = models.EmailField()  # Email or phone
    recipient_type = models.CharField(max_length=10, choices=[
        ('user', 'User'),
        ('nominee', 'Nominee'),
    ])
    subject = models.CharField(max_length=200, null=True, blank=True)
    message = models.TextField()
    is_sent = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'emergency_alerts'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Alert: {self.alert_type} to {self.recipient}"


class NomineeAccessRequest(models.Model):
    """
    Model for nominee initiated access requests
    When a nominee requests access to user's vault
    """
    REQUEST_STATUS = (
        ('pending', 'Pending'),
        ('user_notified', 'User Notified'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
        ('access_granted', 'Access Granted'),
    )
    
    REASON_CHOICES = (
        ('death', 'User Deceased'),
        ('medical', 'Medical Emergency'),
        ('accident', 'Accident'),
        ('unreachable', 'Unable to Reach'),
        ('other', 'Other'),
    )
    
    nominee = models.ForeignKey(Nominee, on_delete=models.CASCADE, related_name='access_requests')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='nominee_access_requests')
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=REQUEST_STATUS, default='pending')
    
    # User response
    user_response = models.TextField(null=True, blank=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    
    # Access timing
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    access_granted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'nominee_access_requests'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Access Request from {self.nominee.nominee_name} to {self.user.username}"
    
    def is_expired(self):
        """Check if request has expired"""
        return timezone.now() > self.expires_at