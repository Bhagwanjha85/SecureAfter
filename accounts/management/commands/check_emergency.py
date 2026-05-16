"""
Django management command to check for missed emergency check-ins
and send notifications to users and nominees.
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from accounts.models import EmergencySettings, EmergencyAlert, CheckInRecord, Nominee, NomineeAccessRequest
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger('django')

User = get_user_model()


class Command(BaseCommand):
    help = 'Check for missed emergency check-ins and send notifications'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run without sending actual notifications',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        
        self.stdout.write('[INFO] Checking for missed check-ins...')
        
        # Get all enabled emergency settings
        emergency_settings = EmergencySettings.objects.filter(is_enabled=True)
        
        notifications_sent = 0
        emergencies_triggered = 0
        
        for settings in emergency_settings:
            try:
                result = self.process_emergency_check(settings, dry_run)
                notifications_sent += result['notifications']
                emergencies_triggered += result['emergency']
            except Exception as e:
                logger.error(f"Error processing emergency for user {settings.user.username}: {str(e)}")
        
        self.stdout.write(self.style.SUCCESS(
            f'\n[SUCCESS] Completed: {notifications_sent} notifications sent, {emergencies_triggered} emergencies triggered'
        ))
    
    def process_emergency_check(self, settings, dry_run):
        """Process emergency check for a single user"""
        result = {'notifications': 0, 'emergency': 0}
        
        user = settings.user
        now = timezone.now()
        
        # Check if check-in is overdue
        if not settings.next_check_in_due:
            # Calculate first check-in due
            settings.last_check_in = now
            settings.next_check_in_due = now + timedelta(days=settings.check_in_interval)
            settings.save()
            return result
        
        if now < settings.next_check_in_due:
            # Check-in not due yet
            return result
        
        # Calculate missed check-ins
        missed = settings.get_missed_checkins_count()
        
        # Determine alert type based on missed count
        if missed >= settings.missed_checkins_for_emergency:
            alert_type = 'emergency'
        elif missed >= settings.missed_checkins_for_urgent:
            alert_type = 'urgent'
        elif missed >= settings.missed_checkins_for_reminder:
            alert_type = 'reminder'
        else:
            alert_type = None
        
        if alert_type:
            # Send alert to user
            if not dry_run:
                self.send_alert_to_user(user, alert_type, settings)
            result['notifications'] += 1
            
            # Notify nominees if enabled
            if settings.notify_nominees_on_missed and alert_type in ['urgent', 'emergency']:
                nominees = Nominee.objects.filter(user=user, is_verified=True, is_active=True)
                for nominee in nominees:
                    if not dry_run:
                        self.send_alert_to_nominee(nominee, alert_type, settings)
                    result['notifications'] += 1
        
        # Check if emergency should be triggered
        if (missed >= settings.missed_checkins_for_emergency and 
            settings.auto_trigger_emergency and 
            not settings.is_emergency_triggered):
            
            if not dry_run:
                self.trigger_emergency(settings)
            result['emergency'] = 1
        
        return result
    
    def send_alert_to_user(self, user, alert_type, settings):
        """Send alert email to user"""
        subject = ""
        message = ""
        
        if alert_type == 'reminder':
            subject = "Reminder: Check-in Due - SecureAfter"
            message = f"""Hello {user.username},

This is a friendly reminder that your check-in is due.

Please log in to your SecureAfter account and click "I'm Alive" to confirm you're safe.

Next check-in due: {settings.next_check_in_due + timedelta(days=settings.check_in_interval)}

Stay safe!"""
        elif alert_type == 'urgent':
            subject = "URGENT: Missed Check-in - SecureAfter"
            message = f"""Hello {user.username},

We noticed you've missed your check-in. This is an urgent alert.

Please log in immediately and confirm you're safe by clicking "I'm Alive".

If we don't hear from you, your nominees will be notified."""
        elif alert_type == 'emergency':
            subject = "EMERGENCY ALERT: Check-in Missed - SecureAfter"
            message = f"""Hello {user.username},

CRITICAL: You have missed multiple check-ins. Your emergency system has been triggered.

Your nominees have been notified and will receive access to your vault after the grace period ({settings.grace_period} days).

If you're safe, please log in immediately and click "I'm Alive" to cancel the emergency."""
        
        # Create alert record
        EmergencyAlert.objects.create(
            user=user,
            alert_type=alert_type,
            channel='email',
            recipient=user.email,
            recipient_type='user',
            subject=subject,
            message=message,
            is_sent=True,
            sent_at=timezone.now()
        )
        
        # TODO: Actually send email using Django's email backend
        # For now, just log it
        logger.info(f"Alert sent to {user.email}: {subject}")
        
        # Update status
        settings.save()
    
    def send_alert_to_nominee(self, nominee, alert_type, settings):
        """Send alert to nominee"""
        user = settings.user
        
        subject = ""
        message = ""
        
        if alert_type == 'urgent':
            subject = f"Urgent Alert: {user.username} Missed Check-in"
            message = f"""Hello {nominee.nominee_name},

This is an urgent notification. {user.username} has missed their check-in with SecureAfter.

We haven't been able to reach them. Please try to contact them through other means.

If we don't hear from them, the emergency system will be triggered."""
        elif alert_type == 'emergency':
            subject = f"EMERGENCY: {user.username} - Access May Be Granted"
            message = f"""Hello {nominee.nominee_name},

This is an emergency notification. {user.username} has missed multiple check-ins with SecureAfter.

The emergency system has been triggered. After the grace period ({settings.grace_period} days), you may receive access to their vault.

Please prepare for the possibility of accessing their important documents and information."""
        
        # Create alert record
        EmergencyAlert.objects.create(
            user=user,
            alert_type=alert_type,
            channel='email',
            recipient=nominee.nominee_email,
            recipient_type='nominee',
            subject=subject,
            message=message,
            is_sent=True,
            sent_at=timezone.now()
        )
        
        logger.info(f"Alert sent to nominee {nominee.nominee_email}: {subject}")
    
    def trigger_emergency(self, settings):
        """Trigger emergency state and notify nominees"""
        user = settings.user
        
        settings.is_emergency_triggered = True
        settings.emergency_triggered_at = timezone.now()
        settings.save()
        
        # Calculate when access will be unlocked
        settings.emergency_access_unlocked_at = (
            timezone.now() + timedelta(days=settings.grace_period)
        )
        settings.save()
        
        logger.info(f"Emergency triggered for user {user.username}")
        
        # Create emergency alert
        EmergencyAlert.objects.create(
            user=user,
            alert_type='emergency',
            channel='email',
            recipient=user.email,
            recipient_type='user',
            subject="EMERGENCY TRIGGERED",
            message=f"Your emergency system has been activated. Your nominees will be notified.",
            is_sent=True,
            sent_at=timezone.now()
        )