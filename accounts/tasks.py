"""
Dead Man's Switch — Automated Email Task Engine
================================================
This Celery task runs on a schedule (every hour) and:
  1. Checks all users with the Dead Man's Switch enabled
  2. Sends a WARNING email to the USER when check-in is overdue
  3. Sends EMERGENCY emails to all NOMINEES after grace period expires
  4. Unlocks vault access for nominees automatically
"""

from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
import logging

logger = logging.getLogger('django')


def send_checkin_warning_to_user(user, emergency_settings):
    """
    Send a warning email to the USER that their check-in is overdue.
    This is Step 1 — give the user a chance to check in before nominees are notified.
    """
    days_overdue = (timezone.now() - emergency_settings.next_check_in_due).days

    subject = "⚠️ SecureAfter: Your Check-in is Overdue"
    message = f"""
Hello {user.get_full_name() or user.username},

Your SecureAfter check-in is {days_overdue} day(s) overdue.

📅 Your check-in was due: {emergency_settings.next_check_in_due.strftime('%B %d, %Y at %I:%M %p')}

If you are safe and active, please log in and check in immediately to prevent
emergency access from being granted to your nominees.

👉 Check In Now: {settings.SITE_URL if hasattr(settings, 'SITE_URL') else 'https://secureafter5.onrender.com'}/accounts/checkin/

Grace Period Remaining: {emergency_settings.grace_period} days

If you do NOT check in within the grace period, your nominees will automatically
receive emergency access to your vault.

– The SecureAfter Team
    """.strip()

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        logger.info(f"[DMS] Warning email sent to user: {user.email}")
        return True
    except Exception as e:
        logger.error(f"[DMS] Failed to send warning email to {user.email}: {str(e)}")
        return False


def send_emergency_email_to_nominee(user, nominee):
    """
    Send an EMERGENCY email to a NOMINEE with their access token.
    This is Step 2 — triggered after grace period expires.
    """
    from emergency.models import EmergencyAccess, EmergencyTrigger
    import secrets

    # Get or create the emergency trigger
    trigger, _ = EmergencyTrigger.objects.get_or_create(
        user=user,
        trigger_type='inactivity',
        defaults={'inactivity_days': 90, 'is_active': True}
    )

    # Create an emergency access record for this nominee
    access_token = secrets.token_urlsafe(48)
    emergency_access = EmergencyAccess.objects.create(
        user=user,
        nominee=nominee,
        trigger=trigger,
        status='active',
        access_token=access_token,
        is_verified=True,
        expires_at=timezone.now() + timedelta(hours=72),  # 72-hour access window
    )

    access_url = f"{getattr(settings, 'SITE_URL', 'https://secureafter5.onrender.com')}/emergency/access/{access_token}/"

    subject = f"🔓 SecureAfter: Emergency Vault Access for {user.get_full_name() or user.username}"
    message = f"""
Dear {nominee.nominee_name},

You are receiving this message because {user.get_full_name() or user.username} has not checked in
with SecureAfter for an extended period beyond their configured grace period.

As a designated nominee, you now have emergency access to their secure vault.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔑 YOUR EMERGENCY ACCESS LINK:
{access_url}

⏰ This link expires in 72 hours.
🔒 Access Level: {nominee.get_access_level_display()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Your relationship: {nominee.get_relationship_display()}

IMPORTANT:
- This link is unique to you. Do not share it.
- Access is logged for security purposes.
- If {user.get_full_name() or user.username} is safe, they can revoke this access by logging in.

If you believe this was triggered in error, please contact support immediately.

– The SecureAfter Security System
    """.strip()

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[nominee.nominee_email],
            fail_silently=False,
        )
        logger.info(f"[DMS] Emergency email sent to nominee: {nominee.nominee_email} for user: {user.username}")
        return True
    except Exception as e:
        logger.error(f"[DMS] Failed to send emergency email to {nominee.nominee_email}: {str(e)}")
        return False


def run_dead_mans_switch_check():
    """
    Main engine — checks ALL users and takes action based on their check-in status.

    Logic:
        - If overdue but within grace period → Send WARNING email to USER
        - If overdue AND grace period passed → Send EMERGENCY email to all NOMINEES
        - Marks emergency as triggered to avoid sending duplicate emails
    """
    from accounts.models import EmergencySettings, EmergencyAlert

    now = timezone.now()
    logger.info(f"[DMS] Running Dead Man's Switch check at {now}")

    # Get all active emergency settings where switch is enabled
    active_settings = EmergencySettings.objects.filter(
        is_enabled=True,
        is_emergency_triggered=False,  # Don't re-trigger already triggered ones
        next_check_in_due__isnull=False,
    ).select_related('user')

    processed = 0
    for es in active_settings:
        user = es.user

        # Skip if check-in is not yet overdue
        if not es.is_overdue():
            continue

        days_overdue = (now - es.next_check_in_due).days
        grace_deadline = es.next_check_in_due + timedelta(days=es.grace_period)
        grace_expired = now > grace_deadline

        if not grace_expired:
            # === PHASE 1: Warning to the USER ===
            # Only send once per overdue cycle (check if already sent today)
            already_warned_today = EmergencyAlert.objects.filter(
                user=user,
                alert_type='reminder',
                recipient_type='user',
                sent_at__date=now.date(),
                is_sent=True,
            ).exists()

            if not already_warned_today and es.notify_nominees_on_missed:
                sent = send_checkin_warning_to_user(user, es)
                EmergencyAlert.objects.create(
                    user=user,
                    alert_type='reminder',
                    channel='email',
                    recipient=user.email,
                    recipient_type='user',
                    subject='Check-in Overdue Warning',
                    message=f'Warning sent: {days_overdue} days overdue',
                    is_sent=sent,
                    sent_at=now if sent else None,
                )
                logger.info(f"[DMS] Phase 1 — Warning sent to user {user.username} ({days_overdue} days overdue)")

        else:
            # === PHASE 2: Emergency Trigger — Email ALL Nominees ===
            logger.info(f"[DMS] Phase 2 — Grace period expired for {user.username}. Triggering emergency access.")

            nominees = user.nominees.filter(is_active=True, is_verified=True)

            if not nominees.exists():
                logger.warning(f"[DMS] No verified nominees found for {user.username}. Cannot trigger emergency.")
                continue

            all_sent = True
            for nominee in nominees:
                # Check if already sent to this nominee
                already_sent = EmergencyAlert.objects.filter(
                    user=user,
                    alert_type='emergency',
                    recipient=nominee.nominee_email,
                    is_sent=True,
                ).exists()

                if already_sent:
                    continue

                sent = send_emergency_email_to_nominee(user, nominee)
                EmergencyAlert.objects.create(
                    user=user,
                    alert_type='emergency',
                    channel='email',
                    recipient=nominee.nominee_email,
                    recipient_type='nominee',
                    subject='Emergency Vault Access',
                    message=f'Emergency access granted to {nominee.nominee_name}',
                    is_sent=sent,
                    sent_at=now if sent else None,
                )
                if not sent:
                    all_sent = False

            if all_sent:
                # Mark emergency as triggered
                es.is_emergency_triggered = True
                es.emergency_triggered_at = now
                es.emergency_access_unlocked_at = now
                es.save(update_fields=[
                    'is_emergency_triggered',
                    'emergency_triggered_at',
                    'emergency_access_unlocked_at'
                ])
                logger.info(f"[DMS] Emergency fully triggered for user {user.username}")

        processed += 1

    logger.info(f"[DMS] Check complete. Processed {processed} user(s).")
    return processed
