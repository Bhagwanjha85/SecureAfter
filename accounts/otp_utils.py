"""
OTP Utilities for Email and Phone Verification
Handles OTP generation, storage, and sending
"""
import random
import logging
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.core.cache import cache
from smtplib import SMTPAuthenticationError
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import escape
from .models import OTPVerification

logger = logging.getLogger('django.security')


class OTPGenerator:
    """Generate and manage OTP codes"""
    
    OTP_EXPIRY_MINUTES = 10  # OTP valid for 10 minutes
    MAX_ATTEMPTS = 5  # Max 5 attempts to verify
    
    @staticmethod
    def generate_otp():
        """
        Generate a random 6-digit OTP code
        
        Returns:
            str: 6-digit OTP code
        """
        return str(random.randint(100000, 999999))
    
    @staticmethod
    def create_otp_record(email=None, phone=None, otp_type='registration_email', user=None, nominee=None):
        """
        Create a new OTP verification record
        
        Args:
            email: Email address for verification (optional)
            phone: Phone number for verification (optional)
            otp_type: Type of OTP (registration_email, registration_phone, nominee_email, nominee_phone)
            user: User object (optional, for registration/nominee management)
            nominee: Nominee object (optional, for nominee verification)
        
        Returns:
            dict: Contains otp_code, record_id, expires_at
        """
        try:
            # Delete any existing unverified OTP for this email/phone to prevent spam
            if email:
                OTPVerification.objects.filter(
                    email=email,
                    otp_type=otp_type,
                    is_verified=False
                ).delete()
            
            if phone:
                OTPVerification.objects.filter(
                    phone=phone,
                    otp_type=otp_type,
                    is_verified=False
                ).delete()
            
            otp_code = OTPGenerator.generate_otp()
            expires_at = timezone.now() + timedelta(minutes=OTPGenerator.OTP_EXPIRY_MINUTES)
            
            otp_record = OTPVerification.objects.create(
                email=email,
                phone=phone,
                otp_code=otp_code,
                otp_type=otp_type,
                expires_at=expires_at,
                user=user,
                nominee=nominee,
                is_verified=False,
                attempts=0,
                max_attempts=OTPGenerator.MAX_ATTEMPTS
            )
            
            logger.info(f"OTP created for {email or phone} (Type: {otp_type})")
            
            return {
                'success': True,
                'otp_code': otp_code,
                'record_id': otp_record.id,
                'expires_at': expires_at,
                'message': 'OTP created successfully'
            }
        except Exception as e:
            logger.error(f"Error creating OTP record: {str(e)}")
            return {
                'success': False,
                'message': f'Error creating OTP: {str(e)}'
            }
    
    @staticmethod
    def verify_otp(otp_code, email=None, phone=None, otp_type='registration_email'):
        """
        Verify the OTP code provided by user
        
        Args:
            otp_code: OTP code to verify
            email: Email address to match (optional)
            phone: Phone number to match (optional)
            otp_type: Type of OTP to verify
        
        Returns:
            dict: Contains success status and message
        """
        try:
            # Find the most recent OTP record for this email/phone
            query = OTPVerification.objects.filter(
                otp_type=otp_type,
                is_verified=False
            )
            
            if email:
                query = query.filter(email=email)
            if phone:
                query = query.filter(phone=phone)
            
            otp_record = query.latest('created_at')
            
            # Check if OTP is expired
            if otp_record.is_expired():
                logger.warning(f"Expired OTP verification attempt for {email or phone}")
                return {
                    'success': False,
                    'message': 'OTP has expired. Please request a new one.',
                    'expired': True
                }
            
            # Check if max attempts reached
            if otp_record.is_attempt_limit_reached():
                logger.warning(f"Max OTP attempts reached for {email or phone}")
                return {
                    'success': False,
                    'message': 'Maximum verification attempts exceeded. Please request a new OTP.',
                    'max_attempts_reached': True
                }
            
            # Increment attempts
            otp_record.increment_attempts()
            
            # Verify OTP code
            if str(otp_record.otp_code) == str(otp_code).strip():
                otp_record.is_verified = True
                otp_record.save(update_fields=['is_verified'])
                logger.info(f"OTP verified successfully for {email or phone}")
                return {
                    'success': True,
                    'message': 'OTP verified successfully',
                    'record_id': otp_record.id
                }
            else:
                logger.warning(f"Invalid OTP attempt for {email or phone}")
                remaining_attempts = otp_record.max_attempts - otp_record.attempts
                return {
                    'success': False,
                    'message': f'Invalid OTP. {remaining_attempts} attempts remaining.',
                    'remaining_attempts': remaining_attempts
                }
        
        except OTPVerification.DoesNotExist:
            logger.warning(f"No OTP record found for {email or phone}")
            return {
                'success': False,
                'message': 'No active OTP found. Please request a new one.'
            }
        except Exception as e:
            logger.error(f"Error verifying OTP: {str(e)}")
            return {
                'success': False,
                'message': f'Error verifying OTP: {str(e)}'
            }
    
    @staticmethod
    def resend_otp(email=None, phone=None, otp_type='registration_email'):
        """
        Resend OTP to user
        
        Args:
            email: Email address (optional)
            phone: Phone number (optional)
            otp_type: Type of OTP
        
        Returns:
            dict: Contains success status
        """
        try:
            # Delete previous OTP attempts
            query = OTPVerification.objects.filter(otp_type=otp_type, is_verified=False)
            if email:
                query = query.filter(email=email)
            if phone:
                query = query.filter(phone=phone)
            query.delete()
            
            # Create new OTP
            result = OTPGenerator.create_otp_record(
                email=email,
                phone=phone,
                otp_type=otp_type
            )
            
            if result['success']:
                # Send OTP via email
                if email and 'email' in otp_type:
                    sent, error_msg = OTPEmailSender.send_otp_email(email, result['otp_code'], otp_type)
                    if not sent:
                        return {
                            'success': False,
                            'message': f'Failed to send OTP email: {error_msg}'
                        }
                
                # Send OTP via SMS
                if phone and 'phone' in otp_type:
                    sent, error_msg = OTPSmsSender.send_otp_sms(phone, result['otp_code'], otp_type)
                    if not sent:
                        return {
                            'success': False,
                            'message': f'Failed to send OTP SMS: {error_msg}'
                        }
                
                logger.info(f"OTP resent for {email or phone}")
                return {
                    'success': True,
                    'message': 'OTP has been resent successfully'
                }
            else:
                return result
        
        except Exception as e:
            logger.error(f"Error resending OTP: {str(e)}")
            return {
                'success': False,
                'message': f'Error resending OTP: {str(e)}'
            }


class OTPEmailSender:
    """Handle OTP email sending"""
    
    @staticmethod
    def send_otp_email(email, otp_code, otp_type='registration_email'):
        """
        Send OTP via email
        
        Args:
            email: Recipient email address
            otp_code: OTP code to send
            otp_type: Type of OTP (for context in email)
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Determine email subject and context based on OTP type
            if otp_type == 'registration_email':
                subject = 'Email Verification - LifeDocs'
                email_type = 'registration'
                title = 'Verify Your Email Address'
            elif otp_type == 'registration_phone':
                subject = 'Phone Verification - LifeDocs'
                email_type = 'phone_verification'
                title = 'Verify Your Phone Number'
            elif otp_type == 'nominee_email':
                subject = 'Nominee Verification - LifeDocs'
                email_type = 'nominee'
                title = 'Verify Your Email for Nominee Access'
            elif otp_type == 'nominee_phone':
                subject = 'Nominee Phone Verification - LifeDocs'
                email_type = 'nominee_phone'
                title = 'Verify Your Phone Number for Nominee Access'
            else:
                email_type = 'verification'
                title = 'Your Verification Code'
            
            # Prepare email context
            context = {
                'otp_code': otp_code,
                'email_type': email_type,
                'title': title,
                'expiry_minutes': OTPGenerator.OTP_EXPIRY_MINUTES,
            }
            
            # CRITICAL FIX: Use authenticated email as sender to prevent SMTP 530 error
            from_email = settings.EMAIL_HOST_USER
            
            if not from_email:
                error_msg = "EMAIL_HOST_USER is not set. Cannot send authenticated email via Gmail."
                logger.error(error_msg)
                if settings.DEBUG:
                    print(f"EMAIL CONFIG ERROR: {error_msg}")
                return False, error_msg
            
            # FORCE PRINT TO CONSOLE FOR DEVELOPMENT
            if settings.DEBUG:
                print(f"\n{'='*40}")
                print(f"LIFE DOCS OTP ({otp_type})")
                print(f"To: {email}")
                print(f"Code: {otp_code}")
                print(f"{'='*40}\n")
            
            # Render HTML email template
            html_message = render_to_string('accounts/otp_email.html', context)
            
            # Send email
            send_mail(
                subject=subject,
                message=f'Your OTP code is: {otp_code}',
                from_email=from_email,
                recipient_list=[email],
                html_message=html_message,
                fail_silently=False,
            )
            
            logger.info(f"OTP email sent to {escape(email)}")
            return True, None
        
        except SMTPAuthenticationError as e:
            error_msg = "SMTP Authentication Failed. Please check your Gmail App Password."
            logger.error(f"SMTP Auth Error sending OTP to {escape(email)}: {str(e)}")
            if settings.DEBUG:
                print(f"EMAIL AUTH ERROR: {error_msg} (Response: {e.smtp_error})")
            return False, error_msg
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error sending OTP email to {escape(email)}: {error_msg}")
            if settings.DEBUG:
                print(f"EMAIL SENDING ERROR: {error_msg}")
            return False, error_msg


class OTPSmsSender:
    """Handle OTP SMS sending"""
    
    # Rate limiting settings
    MAX_SMS_PER_HOUR = 5
    RATE_LIMIT_WINDOW = 3600  # 1 hour
    
    @staticmethod
    def send_otp_sms(phone, otp_code, otp_type='registration_phone'):
        """
        Send OTP via SMS
        
        Args:
            phone: Recipient phone number
            otp_code: OTP code to send
            otp_type: Type of OTP
            
        Returns:
            tuple: (bool, str) - (Success status, Error message)
        """
        try:
            # Check rate limit
            cache_key = f"sms_limit_{phone}"
            attempts = cache.get(cache_key, 0)
            
            if attempts >= OTPSmsSender.MAX_SMS_PER_HOUR:
                error_msg = "Too many SMS requests. Please try again in an hour."
                logger.warning(f"SMS rate limit exceeded for {phone}")
                return False, error_msg
            
            # Mock SMS sending - Log to console in DEBUG mode
            message = f"Your LifeDocs verification code is: {otp_code}"
            
            if settings.DEBUG:
                print(f"\n{'='*40}")
                print(f"LIFE DOCS SMS OTP ({otp_type})")
                print(f"To: {phone}")
                print(f"Message: {message}")
                print(f"{'='*40}\n")
            
            logger.info(f"OTP SMS sent to {phone}")
            
            # Increment rate limit counter
            if attempts == 0:
                cache.set(cache_key, 1, OTPSmsSender.RATE_LIMIT_WINDOW)
            else:
                try:
                    cache.incr(cache_key)
                except ValueError:
                    cache.set(cache_key, 1, OTPSmsSender.RATE_LIMIT_WINDOW)
            
            return True, None
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error sending OTP SMS to {phone}: {error_msg}")
            return False, error_msg


def send_otp_email(email, otp_code, otp_type='registration_email'):
    """
    Wrapper function to send OTP via email
    
    Args:
        email: Recipient email address
        otp_code: OTP code to send
        otp_type: Type of OTP
    
    Returns:
        tuple: (bool, str) - (Success status, Error message)
    """
    return OTPEmailSender.send_otp_email(email, otp_code, otp_type)


def send_otp_phone(phone, otp_code, otp_type='registration_phone'):
    """
    Wrapper function to send OTP via SMS
    
    Args:
        phone: Recipient phone number
        otp_code: OTP code to send
        otp_type: Type of OTP
    
    Returns:
        tuple: (bool, str) - (Success status, Error message)
    """
    return OTPSmsSender.send_otp_sms(phone, otp_code, otp_type)


def create_otp(email=None, phone=None, otp_type='registration_email', user=None, nominee=None):
    """
    Wrapper function to create OTP record
    
    Args:
        email: Email address (optional)
        phone: Phone number (optional)
        otp_type: Type of OTP
        user: User object (optional)
        nominee: Nominee object (optional)
    
    Returns:
        dict: Result dictionary
    """
    return OTPGenerator.create_otp_record(email, phone, otp_type, user, nominee)


def verify_otp(otp_code, email=None, phone=None, otp_type='registration_email'):
    """
    Wrapper function to verify OTP
    
    Args:
        otp_code: OTP code to verify
        email: Email address (optional)
        phone: Phone number (optional)
        otp_type: Type of OTP
    
    Returns:
        dict: Result dictionary
    """
    return OTPGenerator.verify_otp(otp_code, email, phone, otp_type)


def resend_otp(email=None, phone=None, otp_type='registration_email'):
    """
    Wrapper function to resend OTP
    
    Args:
        email: Email address (optional)
        phone: Phone number (optional)
        otp_type: Type of OTP
    
    Returns:
        dict: Result dictionary
    """
    return OTPGenerator.resend_otp(email, phone, otp_type)
