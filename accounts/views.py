from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.core.exceptions import ValidationError
from django.db import transaction, IntegrityError
from django.utils.html import escape
from django.utils import timezone
import logging
import os
import subprocess
from django.http import FileResponse, Http404
from .models import User, Nominee, OTPVerification
from .otp_utils import create_otp, verify_otp, send_otp_email, resend_otp, send_otp_phone
from vault.models import Vault, Document, EmergencyInstructions
from audit_logs.models import AuditLog
from core.security import InputValidator

logger = logging.getLogger('django.security')
audit_logger = logging.getLogger('audit')

def get_client_ip(request):
    """Get client IP address safely"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@ensure_csrf_cookie
@require_http_methods(["GET", "POST"])
def register_view(request):
    """User registration with OTP email verification"""
    if request.user.is_authenticated:
        return redirect('vault:user_dashboard')
    
    if request.method == 'POST':
        try:
            username = request.POST.get('username', '').strip()
            email = request.POST.get('email', '').strip()
            password = request.POST.get('password', '').strip()
            password2 = request.POST.get('password2', '').strip()
            if not password2:
                password2 = request.POST.get('confirm_password', '').strip()
            phone = request.POST.get('phone', '').strip()
            
            # Input validation
            InputValidator.validate_username(username)
            InputValidator.validate_email(email)
            InputValidator.validate_password_strength(password)
            
            if not phone:
                raise ValidationError('Mobile number is required.')
            InputValidator.validate_phone(phone)
            
            if password != password2:
                messages.error(request, 'Passwords do not match!')
                audit_logger.warning(f"Registration attempt with mismatched passwords from {get_client_ip(request)}")
                return render(request, 'accounts/register.html')
            
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists!')
                audit_logger.warning(f"Registration attempt with existing username: {escape(username)} from {get_client_ip(request)}")
                return render(request, 'accounts/register.html')
            
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already registered!')
                audit_logger.warning(f"Registration attempt with existing email from {get_client_ip(request)}")
                return render(request, 'accounts/register.html')
            
            if phone and User.objects.filter(phone=phone).exists():
                messages.error(request, 'This phone number is already registered!')
                audit_logger.warning(f"Registration attempt with existing phone from {get_client_ip(request)}")
                return render(request, 'accounts/register.html')
            
            # Store registration data in session
            request.session['reg_data'] = {
                'username': username,
                'email': email,
                'password': password,
                'phone': phone,
                'user_type': 'normal'
            }
            request.session['otp_verification_email'] = email
            
            # Generate and send OTP
            otp_result = create_otp(email=email, otp_type='registration_email')
            
            if otp_result['success']:
                sent, error_msg = send_otp_email(email, otp_result['otp_code'], 'registration_email')
                if sent:
                    audit_logger.info(f"Registration OTP sent to {escape(email)} from {get_client_ip(request)}")
                    messages.success(request, 'Verification code sent to your email.')
                    return redirect('accounts:verify_email_otp')
                else:
                    messages.error(request, f'Error sending verification email: {error_msg}')
                    return render(request, 'accounts/register.html')
            else:
                messages.error(request, otp_result.get('message', 'Error generating OTP.'))
                logger.error(f"OTP generation failed for {email}: {otp_result}")
                return render(request, 'accounts/register.html')
            
        except ValidationError as e:
            messages.error(request, f'Validation error: {str(e)}')
            logger.warning(f"Registration validation error: {str(e)}")
        except Exception as e:
            messages.error(request, 'Error processing registration. Please try again.')
            logger.error(f"Error in registration: {str(e)}")
    
    return render(request, 'accounts/register.html')


@ensure_csrf_cookie
@require_http_methods(["GET", "POST"])
def verify_email_otp(request):
    """Verify email OTP during registration"""
    if request.user.is_authenticated:
        return redirect('vault:user_dashboard')
    
    if 'otp_verification_email' not in request.session or 'reg_data' not in request.session:
        messages.error(request, 'Invalid verification session. Please register again.')
        return redirect('accounts:register')
    
    email = request.session.get('otp_verification_email')
    
    if request.method == 'POST':
        try:
            otp_code = request.POST.get('otp_code', '').strip()
            
            if not otp_code:
                messages.error(request, 'Please enter the verification code.')
                return render(request, 'accounts/verify_email_otp.html', {'email': email})
            
            # Verify OTP
            otp_result = verify_otp(otp_code, email=email, otp_type='registration_email')
            
            if otp_result['success']:
                # OTP verified, mark email as verified
                request.session['email_verified'] = True
                audit_logger.info(f"Email OTP verified for registration: {escape(email)}")
                
                # Phone is mandatory, proceed to phone verification
                phone = request.session['reg_data'].get('phone')
                
                # Generate and send phone OTP
                otp_phone_result = create_otp(phone=phone, otp_type='registration_phone')
                
                if otp_phone_result['success']:
                    send_otp_phone(phone, otp_phone_result['otp_code'], 'registration_phone')
                    messages.success(request, 'Email verified! Verification code sent to your phone.')
                    return redirect('accounts:verify_phone_otp')
                else:
                    messages.error(request, 'Error generating phone OTP.')
                    return redirect('accounts:register')
            else:
                if otp_result.get('expired'):
                    messages.error(request, otp_result['message'])
                    return redirect('accounts:register')
                elif otp_result.get('max_attempts_reached'):
                    messages.error(request, otp_result['message'])
                    return redirect('accounts:register')
                else:
                    messages.error(request, otp_result['message'])
        
        except Exception as e:
            logger.error(f"Error verifying email OTP: {str(e)}")
            messages.error(request, 'Error verifying code. Please try again.')
    
    return render(request, 'accounts/verify_email_otp.html', {'email': email})


@ensure_csrf_cookie
@require_http_methods(["POST"])
def resend_email_otp(request):
    """Resend email OTP during registration"""
    if 'otp_verification_email' not in request.session:
        messages.error(request, 'Invalid session. Please register again.')
        return redirect('accounts:register')
    
    email = request.session.get('otp_verification_email')
    
    try:
        otp_result = resend_otp(email=email, otp_type='registration_email')
        if otp_result['success']:
            audit_logger.info(f"Email OTP resent for: {escape(email)}")
            messages.success(request, 'Verification code resent. Please check your email.')
        else:
            messages.error(request, otp_result['message'])
    except Exception as e:
        logger.error(f"Error resending email OTP: {str(e)}")
        messages.error(request, 'Error resending code. Please try again.')
    
    return redirect('accounts:verify_email_otp')


@ensure_csrf_cookie
@require_http_methods(["GET", "POST"])
def verify_phone_otp(request):
    """Verify phone OTP during registration"""
    if request.user.is_authenticated:
        return redirect('vault:user_dashboard')
    
    if 'email_verified' not in request.session or 'reg_data' not in request.session:
        messages.error(request, 'Invalid verification session. Please register again.')
        return redirect('accounts:register')
    
    phone = request.session.get('reg_data', {}).get('phone')
    email = request.session.get('otp_verification_email')
    
    if not phone:
        messages.error(request, 'No phone number found. Please register again.')
        return redirect('accounts:register')
    
    if request.method == 'POST':
        try:
            otp_code = request.POST.get('otp_code', '').strip()
            
            if not otp_code:
                messages.error(request, 'Please enter the verification code.')
                return render(request, 'accounts/verify_phone_otp.html', {'phone': phone, 'email': email})
            
            # Verify OTP
            otp_result = verify_otp(otp_code, phone=phone, otp_type='registration_phone')
            
            if otp_result['success']:
                request.session['phone_verified'] = True
                audit_logger.info(f"Phone OTP verified for registration: {phone}")
                messages.success(request, 'Phone number verified! Completing your registration...')
                return redirect('accounts:complete_registration')
            else:
                if otp_result.get('expired'):
                    messages.error(request, otp_result['message'])
                    return redirect('accounts:register')
                elif otp_result.get('max_attempts_reached'):
                    messages.error(request, otp_result['message'])
                    return redirect('accounts:register')
                else:
                    messages.error(request, otp_result['message'])
        
        except Exception as e:
            logger.error(f"Error verifying phone OTP: {str(e)}")
            messages.error(request, 'Error verifying code. Please try again.')
    
    return render(request, 'accounts/verify_phone_otp.html', {'phone': phone, 'email': email})


@ensure_csrf_cookie
@require_http_methods(["POST"])
def resend_phone_otp(request):
    """Resend phone OTP during registration"""
    if 'reg_data' not in request.session:
        messages.error(request, 'Invalid session. Please register again.')
        return redirect('accounts:register')
    
    phone = request.session.get('reg_data', {}).get('phone')
    
    if not phone:
        messages.error(request, 'No phone number found.')
        return redirect('accounts:register')
    
    try:
        otp_result = resend_otp(phone=phone, otp_type='registration_phone')
        if otp_result['success']:
            audit_logger.info(f"Phone OTP resent for: {phone}")
            messages.success(request, 'Verification code resent to your phone.')
        else:
            messages.error(request, otp_result['message'])
    except Exception as e:
        logger.error(f"Error resending phone OTP: {str(e)}")
        messages.error(request, 'Error resending code. Please try again.')
    
    return redirect('accounts:verify_phone_otp')


@require_http_methods(["GET"])
def complete_registration(request):
    """Complete user registration after OTP verification"""
    if request.user.is_authenticated:
        return redirect('vault:user_dashboard')
    
    if 'email_verified' not in request.session or 'reg_data' not in request.session:
        messages.error(request, 'Invalid verification session. Please register again.')
        return redirect('accounts:register')
    
    # Ensure phone is verified
    if not request.session.get('phone_verified'):
        messages.error(request, 'Phone verification required.')
        return redirect('accounts:verify_phone_otp')
    
    try:
        reg_data = request.session.get('reg_data')
        
        # Create user account
        with transaction.atomic():
            # If this email matches an existing verified nominee invitation, create nominee account
            new_user_type = reg_data.get('user_type', 'normal')
            if Nominee.objects.filter(nominee_email__iexact=reg_data['email'], is_verified=True).exists():
                new_user_type = 'nominee'

            user = User.objects.create_user(
                username=reg_data['username'],
                email=reg_data['email'],
                password=reg_data['password'],
                phone=reg_data['phone'],
                user_type=new_user_type,
                email_verified=True,
                phone_verified=request.session.get('phone_verified', False)
            )
            
            # Link any matching nominee invitations to this nominee user account
            Nominee.objects.filter(nominee_email__iexact=user.email, nominee_user__isnull=True).update(nominee_user=user)
            
            # Create vault for user
            Vault.objects.create(user=user)
            
            # Log the registration
            AuditLog.objects.create(
                user=user,
                action='registration',
                description='User registered successfully with email verification',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
        
        # Clear session data
        if 'reg_data' in request.session:
            del request.session['reg_data']
        if 'otp_verification_email' in request.session:
            del request.session['otp_verification_email']
        if 'email_verified' in request.session:
            del request.session['email_verified']
        if 'phone_verified' in request.session:
            del request.session['phone_verified']
        
        # Auto-login user
        login(request, user)
        
        audit_logger.info(f"New user registered and verified: {escape(user.username)} from {get_client_ip(request)}")
        messages.success(request, 'Account created successfully! Welcome to LifeDocs.')
        return redirect('vault:user_dashboard')
    
    except Exception as e:
        logger.error(f"Error completing registration: {str(e)}")
        messages.error(request, 'Error completing registration. Please try again.')
        return redirect('accounts:register')

@ensure_csrf_cookie
@require_http_methods(["GET", "POST"])
def login_view(request):
    """User login with security measures"""
    if request.user.is_authenticated:
        return redirect('vault:user_dashboard')
    
    if request.method == 'POST':
        try:
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '')
            
            # Sanitize username input
            username = InputValidator.sanitize_text(username)
            
            # Attempt to authenticate using username, email, or phone
            user = authenticate(request, username=username, password=password)
            if user is None:
                candidate = None
                if '@' in username:
                    candidate = User.objects.filter(email__iexact=username).first()
                elif username.isdigit():
                    candidate = User.objects.filter(phone=username).first()
                if candidate:
                    user = authenticate(request, username=candidate.username, password=password)
            
            if user is not None:
                # Regenerate session ID after login (prevent session fixation)
                request.session.create()
                login(request, user)
                
                # Handle Remember Me
                if request.POST.get('remember_me'):
                    # Set session expiry to 2 weeks (1209600 seconds)
                    request.session.set_expiry(1209600)
                
                # Update last login
                user.save(update_fields=['last_login'])
                
                # Log successful login
                AuditLog.objects.create(
                    user=user,
                    action='login',
                    description='User logged in successfully',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                audit_logger.info(f"User login successful: {escape(username)} from {get_client_ip(request)}")
                messages.success(request, 'Welcome back!')
                return redirect('vault:user_dashboard')
            else:
                # Log failed login attempt
                AuditLog.objects.create(
                    action='failed_login',
                    description=f'Failed login attempt for username: {escape(username)}',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                audit_logger.warning(f"Failed login attempt for username: {escape(username)} from {get_client_ip(request)}")
                messages.error(request, 'Invalid username, email, phone, or password!')
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            messages.error(request, 'An error occurred during login. Please try again.')
    
    return render(request, 'accounts/login.html')

@login_required
@require_http_methods(["GET", "POST"])
def logout_view(request):
    """User logout"""
    try:
        username = request.user.username
        
        # Log logout
        AuditLog.objects.create(
            user=request.user,
            action='logout',
            description='User logged out',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        audit_logger.info(f"User logged out: {escape(username)} from {get_client_ip(request)}")
        logout(request)
        messages.success(request, 'Logged out successfully!')
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
    
    return redirect('accounts:login')

@login_required
@require_http_methods(["GET", "POST"])
def profile_view(request):
    """User profile view and edit with image/avatar support"""
    if request.method == 'POST':
        try:
            user = request.user
            
            # Get form data
            email = request.POST.get('email', user.email).strip()
            phone = request.POST.get('phone', user.phone or '').strip()
            emergency_contact = request.POST.get('emergency_contact', user.emergency_contact or '').strip()
            about_me = request.POST.get('about_me', '').strip()
            
            # Validate inputs
            if email != user.email:
                InputValidator.validate_email(email)
                # Check if email already exists
                if User.objects.filter(email=email).exclude(id=user.id).exists():
                    messages.error(request, 'Email already in use by another account.')
                    return redirect('accounts:profile')
            
            if phone:
                InputValidator.validate_phone(phone)
                # Check if phone already exists
                if User.objects.filter(phone=phone).exclude(id=user.id).exists():
                    messages.error(request, 'Phone number already in use by another account.')
                    return redirect('accounts:profile')
            
            if emergency_contact:
                InputValidator.validate_phone(emergency_contact)
            
            # Update basic fields
            user.email = email
            user.phone = phone
            user.emergency_contact = emergency_contact
            user.about_me = about_me
            
            # Handle Profile Image Upload
            if 'profile_image' in request.FILES:
                # User uploaded a new image
                profile_image = request.FILES['profile_image']
                
                # Validate image
                if profile_image.size > 5 * 1024 * 1024:  # 5MB limit
                    messages.error(request, 'Image size must be less than 5MB.')
                    return redirect('accounts:profile')
                
                # Validate file type
                allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif']
                if profile_image.content_type not in allowed_types:
                    messages.error(request, 'Only JPEG, PNG and GIF images are allowed.')
                    return redirect('accounts:profile')
                
                # Delete old profile image if exists
                if user.profile_image:
                    try:
                        if os.path.isfile(user.profile_image.path):
                            os.remove(user.profile_image.path)
                    except Exception:
                        pass
                
                user.profile_image = profile_image
                user.avatar_url = None  # Clear avatar URL when uploading custom image
                
            # Handle Avatar Selection
            elif request.POST.get('avatar_url'):
                avatar_url = request.POST.get('avatar_url').strip()
                
                # Validate avatar URL (must be from dicebear API)
                if 'dicebear.com' in avatar_url or avatar_url.startswith('/static/'):
                    user.avatar_url = avatar_url
                    # Optionally clear profile_image when selecting avatar
                    # user.profile_image = None
                else:
                    messages.error(request, 'Invalid avatar URL.')
                    return redirect('accounts:profile')

            # Handle Profile Video Upload
            if 'profile_video' in request.FILES:
                profile_video = request.FILES['profile_video']
                
                # Validate video size (10MB limit)
                if profile_video.size > 10 * 1024 * 1024:
                    messages.error(request, 'Video size must be less than 10MB.')
                    return redirect('accounts:profile')
                
                # Validate file type
                if not profile_video.content_type.startswith('video/'):
                    messages.error(request, 'Only video files are allowed.')
                    return redirect('accounts:profile')
                
                # Delete old profile video if exists
                if hasattr(user, 'profile_video') and user.profile_video:
                    try:
                        if os.path.isfile(user.profile_video.path):
                            os.remove(user.profile_video.path)
                    except Exception:
                        pass
                
                user.profile_video = profile_video
            
            # Save user with transaction safety
            try:
                with transaction.atomic():
                    user.save()
                    
                    # Log profile update
                    AuditLog.objects.create(
                        user=user,
                        action='profile_update',
                        description='User profile updated',
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                
                # Transcode video if uploaded to ensure playability
                if 'profile_video' in request.FILES and user.profile_video:
                    try:
                        video_path = user.profile_video.path
                        temp_output = video_path + '.temp.mp4'
                        
                        # FFmpeg command: H.264 video, AAC audio, web optimized, max 720p
                        cmd = [
                            'ffmpeg', '-y', '-i', video_path,
                            '-c:v', 'libx264', '-preset', 'fast', '-crf', '23',
                            '-c:a', 'aac', '-b:a', '128k',
                            '-movflags', '+faststart',
                            '-vf', "scale='min(1280,iw)':-2",
                            temp_output
                        ]
                        
                        # Run transcoding
                        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        
                        # Replace original file with transcoded version
                        os.replace(temp_output, video_path)
                    except Exception as e:
                        logger.error(f"Video transcoding failed for user {user.username}: {str(e)}")
                        if 'temp_output' in locals() and os.path.exists(temp_output):
                            os.remove(temp_output)
                
                audit_logger.info(f"User profile updated: {escape(user.username)} from {get_client_ip(request)}")
                messages.success(request, 'Profile updated successfully!')
                return redirect('accounts:profile')
            except IntegrityError as e:
                logger.warning(f"IntegrityError updating profile for {user.username}: {str(e)}")
                if 'phone' in str(e).lower():
                    messages.error(request, 'This phone number is already in use by another account.')
                elif 'email' in str(e).lower():
                    messages.error(request, 'This email address is already in use.')
                else:
                    messages.error(request, 'A database error occurred while saving your profile.')
            
        except ValidationError as e:
            messages.error(request, f'Validation error: {str(e)}')
            logger.error(f"Profile validation error for {request.user.username}: {str(e)}")
        except Exception as e:
            logger.error(f"Profile update error for {request.user.username}: {str(e)}")
            messages.error(request, f'Error updating profile: {str(e)}')
    
    context = {
        'nominees': request.user.nominees.filter(is_active=True)
    }
    return render(request, 'accounts/profile.html', context)

@login_required
@require_http_methods(["POST"])
def change_password(request):
    """Handle password change"""
    form = PasswordChangeForm(request.user, request.POST)
    if form.is_valid():
        user = form.save()
        # Updating the password logs out all other sessions, so we update the session hash
        update_session_auth_hash(request, user)
        
        AuditLog.objects.create(
            user=request.user,
            action='password_change',
            description='User changed password successfully',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        audit_logger.info(f"Password changed for user: {escape(request.user.username)}")
        messages.success(request, 'Your password was successfully updated!')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f"{field}: {error}")
                
    return redirect('accounts:profile')

@login_required
@require_http_methods(["POST"])
def delete_account(request):
    """Permanently delete user account"""
    try:
        password = request.POST.get('password', '')
        
        if not password:
            messages.error(request, 'Password is required to delete account.')
            return redirect('accounts:profile')
        
        if not request.user.check_password(password):
            messages.error(request, 'Incorrect password. Account deletion failed.')
            return redirect('accounts:profile')
        
        user = request.user
        username = user.username
        
        # Delete profile image if exists
        if user.profile_image:
            try:
                if os.path.isfile(user.profile_image.path):
                    os.remove(user.profile_image.path)
            except Exception:
                pass
        
        # Log to file before deletion (DB logs might be deleted via cascade)
        audit_logger.warning(f"User account deleted: {escape(username)} from {get_client_ip(request)}")
        
        # Delete user (cascades to Vault, Documents, Nominees, etc.)
        user.delete()
        
        logout(request)
        messages.success(request, 'Your account has been permanently deleted.')
        return redirect('home')
        
    except Exception as e:
        logger.error(f"Error deleting account: {str(e)}")
        messages.error(request, 'An error occurred while deleting your account.')
        return redirect('accounts:profile')

# ==========================================
# Password Reset Views (Forgot Password)
# ==========================================

@ensure_csrf_cookie
@require_http_methods(["GET", "POST"])
def forgot_password_view(request):
    """Handle forgot password request"""
    if request.user.is_authenticated:
        return redirect('vault:user_dashboard')
    
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        
        try:
            user = User.objects.get(email=email)
            
            # Generate OTP
            otp_result = create_otp(email=email, otp_type='password_reset')
            
            if otp_result['success']:
                # Send OTP
                if send_otp_email(email, otp_result['otp_code'], 'password_reset'):
                    request.session['reset_password_email'] = email
                    audit_logger.info(f"Password reset OTP sent to {escape(email)} from {get_client_ip(request)}")
                    messages.success(request, 'Password reset code sent to your email.')
                    return redirect('accounts:verify_reset_otp')
                else:
                    messages.error(request, 'Error sending email. Please try again later.')
            else:
                messages.error(request, 'Error generating OTP. Please try again.')
                
        except User.DoesNotExist:
            # For security, we might not want to reveal this, but for UX we often do.
            # Given register_view reveals existence, we will be explicit here too.
            messages.error(request, 'No account found with this email address.')
            audit_logger.warning(f"Password reset requested for non-existent email: {escape(email)} from {get_client_ip(request)}")
            
    return render(request, 'accounts/forgot_password.html')

@ensure_csrf_cookie
@require_http_methods(["GET", "POST"])
def verify_reset_otp_view(request):
    """Verify OTP for password reset"""
    if request.user.is_authenticated:
        return redirect('vault:user_dashboard')
        
    email = request.session.get('reset_password_email')
    if not email:
        messages.error(request, 'Session expired. Please start over.')
        return redirect('accounts:forgot_password')
        
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code', '').strip()
        
        otp_result = verify_otp(otp_code, email=email, otp_type='password_reset')
        
        if otp_result['success']:
            request.session['reset_password_verified'] = True
            audit_logger.info(f"Password reset OTP verified for {escape(email)}")
            return redirect('accounts:reset_password_confirm')
        else:
            messages.error(request, otp_result['message'])
            
    return render(request, 'accounts/verify_reset_otp.html', {'email': email})

@ensure_csrf_cookie
@require_http_methods(["POST"])
def resend_reset_otp_view(request):
    """Resend OTP for password reset"""
    email = request.session.get('reset_password_email')
    if not email:
        messages.error(request, 'Invalid session.')
        return redirect('accounts:forgot_password')
        
    try:
        otp_result = resend_otp(email=email, otp_type='password_reset')
        if otp_result['success']:
            messages.success(request, 'OTP resent successfully.')
        else:
            messages.error(request, otp_result['message'])
    except Exception as e:
        logger.error(f"Error resending reset OTP: {str(e)}")
        messages.error(request, 'Error resending OTP.')
        
    return redirect('accounts:verify_reset_otp')

@ensure_csrf_cookie
@require_http_methods(["GET", "POST"])
def reset_password_confirm_view(request):
    """Set new password after verification"""
    if request.user.is_authenticated:
        return redirect('vault:user_dashboard')
        
    email = request.session.get('reset_password_email')
    verified = request.session.get('reset_password_verified')
    
    if not email or not verified:
        messages.error(request, 'Unauthorized access. Please verify your email first.')
        return redirect('accounts:forgot_password')
        
    if request.method == 'POST':
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirm', '')
        
        if password != password_confirm:
            messages.error(request, 'Passwords do not match.')
        else:
            try:
                InputValidator.validate_password_strength(password)
                
                user = User.objects.get(email=email)
                user.set_password(password)
                user.save()
                
                # Clear session
                if 'reset_password_email' in request.session:
                    del request.session['reset_password_email']
                if 'reset_password_verified' in request.session:
                    del request.session['reset_password_verified']
                
                audit_logger.info(f"Password reset successful for {escape(email)}")
                messages.success(request, 'Password reset successfully! You can now login.')
                return redirect('accounts:login')
                
            except ValidationError as e:
                messages.error(request, str(e))
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
                
    return render(request, 'accounts/reset_password_confirm.html')


# =====================================================
# SMART EMERGENCY TRIGGER SYSTEM VIEWS
# =====================================================

@login_required
@require_http_methods(["GET", "POST"])
def emergency_settings_view(request):
    """Configure Dead Man's Switch and emergency settings"""
    from .models import EmergencySettings
    
    # Get or create emergency settings
    emergency_settings, created = EmergencySettings.objects.get_or_create(
        user=request.user,
        defaults={
            'check_in_interval': 30,
            'grace_period': 7,
            'missed_checkins_for_reminder': 1,
            'missed_checkins_for_urgent': 2,
            'missed_checkins_for_emergency': 3,
        }
    )
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        
        if action == 'configure':
            # Update settings
            is_enabled = request.POST.get('is_enabled') == 'on'
            check_in_interval = int(request.POST.get('check_in_interval', 30))
            grace_period = int(request.POST.get('grace_period', 7))
            auto_trigger = request.POST.get('auto_trigger_emergency') == 'on'
            notify_nominees = request.POST.get('notify_nominees_on_missed') == 'on'
            
            emergency_settings.is_enabled = is_enabled
            emergency_settings.check_in_interval = check_in_interval
            emergency_settings.grace_period = grace_period
            emergency_settings.auto_trigger_emergency = auto_trigger
            emergency_settings.notify_nominees_on_missed = notify_nominees
            
            if is_enabled and not emergency_settings.last_check_in:
                # First time enabling - set initial check-in
                from datetime import timedelta
                emergency_settings.last_check_in = timezone.now()
                emergency_settings.next_check_in_due = timezone.now() + timedelta(days=check_in_interval)
            
            emergency_settings.save()
            
            messages.success(request, 'Emergency settings updated successfully!')
            audit_logger.info(f"Emergency settings updated for {request.user.username}")
            
        elif action == 'check_in':
            # Manual check-in
            return check_in_now(request)
        
        elif action == 'disable':
            emergency_settings.is_enabled = False
            emergency_settings.is_emergency_triggered = False
            emergency_settings.save()
            messages.success(request, 'Emergency system disabled.')
    
    # Get check-in status
    check_in_status = None
    if emergency_settings.is_enabled:
        missed = emergency_settings.get_missed_checkins_count()
        if missed == 0:
            check_in_status = 'on_track'
        elif missed < emergency_settings.missed_checkins_for_reminder:
            check_in_status = 'upcoming'
        elif missed < emergency_settings.missed_checkins_for_urgent:
            check_in_status = 'reminder'
        elif missed < emergency_settings.missed_checkins_for_emergency:
            check_in_status = 'urgent'
        else:
            check_in_status = 'emergency'
    
    # Get recent check-in records
    from .models import CheckInRecord
    recent_checkins = CheckInRecord.objects.filter(user=request.user)[:10]
    
    context = {
        'emergency_settings': emergency_settings,
        'check_in_status': check_in_status,
        'recent_checkins': recent_checkins,
    }
    return render(request, 'vault/emergency_settings.html', context)


@login_required
def check_in_now(request):
    """Process user check-in to confirm they're alive"""
    from .models import EmergencySettings, CheckInRecord
    
    try:
        emergency_settings = EmergencySettings.objects.get(user=request.user)
        
        if not emergency_settings.is_enabled:
            messages.info(request, 'Emergency system is not enabled.')
            return redirect('accounts:emergency_settings')
        
        # Update check-in time
        from datetime import timedelta
        emergency_settings.last_check_in = timezone.now()
        emergency_settings.next_check_in_due = timezone.now() + timedelta(days=emergency_settings.check_in_interval)
        
        # Reset emergency state if was triggered
        if emergency_settings.is_emergency_triggered:
            emergency_settings.is_emergency_triggered = False
            emergency_settings.emergency_triggered_at = None
            messages.success(request, 'Check-in successful! Emergency status has been reset.')
        else:
            messages.success(request, 'Check-in successful! You are safe.')
        
        emergency_settings.save()
        
        # Create check-in record
        CheckInRecord.objects.create(
            user=request.user,
            emergency_settings=emergency_settings,
            status='on_time',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
        )
        
        audit_logger.info(f"Check-in completed by {request.user.username}")
        
    except EmergencySettings.DoesNotExist:
        messages.error(request, 'Emergency settings not found. Please configure first.')
        return redirect('accounts:emergency_settings')
    
    return redirect('accounts:emergency_settings')


@login_required
def emergency_status_api(request):
    """API to get current emergency status"""
    from .models import EmergencySettings
    from django.http import JsonResponse
    
    try:
        emergency_settings = EmergencySettings.objects.get(user=request.user)
        
        data = {
            'is_enabled': emergency_settings.is_enabled,
            'last_check_in': emergency_settings.last_check_in.isoformat() if emergency_settings.last_check_in else None,
            'next_check_in_due': emergency_settings.next_check_in_due.isoformat() if emergency_settings.next_check_in_due else None,
            'is_emergency_triggered': emergency_settings.is_emergency_triggered,
            'missed_checkins': emergency_settings.get_missed_checkins_count(),
            'is_overdue': emergency_settings.is_overdue(),
        }
        
        return JsonResponse(data)
    except EmergencySettings.DoesNotExist:
        return JsonResponse({'error': 'Emergency settings not found'}, status=404)


# =====================================================
# NOMINEE ACCESS REQUEST SYSTEM
# =====================================================

@login_required
def nominee_access_requests_view(request):
    """View all access requests from nominees"""
    from .models import NomineeAccessRequest
    
    # Get pending requests
    pending_requests = NomineeAccessRequest.objects.filter(
        user=request.user,
        status__in=['pending', 'user_notified']
    ).order_by('-created_at')
    
    # Get processed requests
    processed_requests = NomineeAccessRequest.objects.filter(
        user=request.user,
        status__in=['approved', 'rejected', 'access_granted']
    ).order_by('-created_at')[:20]
    
    context = {
        'pending_requests': pending_requests,
        'processed_requests': processed_requests,
    }
    return render(request, 'accounts/nominee_access_requests.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def respond_to_access_request(request, request_id):
    """Respond to a nominee's access request"""
    from .models import NomineeAccessRequest
    
    try:
        access_request = NomineeAccessRequest.objects.get(id=request_id, user=request.user)
    except NomineeAccessRequest.DoesNotExist:
        messages.error(request, 'Access request not found.')
        return redirect('accounts:nominee_access_requests')
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        response_text = request.POST.get('response', '').strip()
        
        if action == 'approve':
            access_request.status = 'approved'
            access_request.user_response = response_text
            access_request.responded_at = timezone.now()
            access_request.save()
            messages.success(request, 'Access request approved!')
            audit_logger.info(f"Access request approved for {request.user.username} by nominee {access_request.nominee.nominee_name}")
            
        elif action == 'reject':
            access_request.status = 'rejected'
            access_request.user_response = response_text
            access_request.responded_at = timezone.now()
            access_request.save()
            messages.info(request, 'Access request rejected.')
            audit_logger.info(f"Access request rejected for {request.user.username}")
        
        return redirect('accounts:nominee_access_requests')
    
    context = {
        'access_request': access_request,
    }
    return render(request, 'accounts/respond_access_request.html', context)


# =====================================================
# NOMINEE SIDE VIEWS
# =====================================================

@login_required
def nominee_dashboard(request):
    """Dashboard for nominees to manage their assigned vaults"""
    from .models import Nominee, NomineeAccessRequest

    nominees = Nominee.objects.filter(
        nominee_user=request.user,
        is_verified=True,
        is_active=True
    )

    shared_vaults = []
    for nominee in nominees:
        documents = Document.objects.filter(
            user=nominee.user,
            is_accessible_by_nominee=True
        ).order_by('-created_at')
        instructions = None
        try:
            instructions = EmergencyInstructions.objects.get(user=nominee.user)
        except EmergencyInstructions.DoesNotExist:
            instructions = None

        shared_vaults.append({
            'nominee': nominee,
            'documents': documents,
            'shared_count': documents.count(),
            'can_download': nominee.access_level == 'download',
            'emergency_instructions': instructions,
        })

    my_requests = NomineeAccessRequest.objects.filter(
        nominee__nominee_user=request.user
    ).order_by('-created_at')[:10]

    context = {
        'shared_vaults': shared_vaults,
        'my_requests': my_requests,
    }
    return render(request, 'accounts/nominee_dashboard.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def request_vault_access(request, nominee_id):
    """Nominee requests access to a user's vault"""
    from .models import Nominee, NomineeAccessRequest
    from datetime import timedelta
    
    try:
        nominee = Nominee.objects.get(id=nominee_id, nominee_user=request.user)
    except Nominee.DoesNotExist:
        messages.error(request, 'Nominee relationship not found.')
        return redirect('accounts:nominee_dashboard')
    
    # Check if there's already a pending request
    existing_request = NomineeAccessRequest.objects.filter(
        nominee=nominee,
        user=nominee.user,
        status__in=['pending', 'user_notified']
    ).first()
    
    if existing_request:
        messages.warning(request, 'You already have a pending access request.')
        return redirect('accounts:nominee_dashboard')
    
    if request.method == 'POST':
        reason = request.POST.get('reason', '')
        description = request.POST.get('description', '').strip()
        
        if not reason:
            messages.error(request, 'Please select a reason.')
            return redirect('accounts:request_vault_access', nominee_id=nominee_id)
        
        if not description:
            messages.error(request, 'Please provide a description.')
            return redirect('accounts:request_vault_access', nominee_id=nominee_id)
        
        # Create access request
        expires_at = timezone.now() + timedelta(days=7)  # 7 days to respond
        
        access_request = NomineeAccessRequest.objects.create(
            nominee=nominee,
            user=nominee.user,
            reason=reason,
            description=description,
            expires_at=expires_at
        )
        
        # TODO: Send notification to user
        # send_access_request_notification(nominee.user, access_request)
        
        messages.success(request, f'Access request sent to {nominee.user.username}!')
        audit_logger.info(f"Access request created by nominee {request.user.username} for user {nominee.user.username}")
        
        return redirect('accounts:nominee_dashboard')
    
    context = {
        'nominee': nominee,
    }
    return render(request, 'accounts/request_vault_access.html', context)


@login_required
def nominee_documents(request, nominee_id):
    """List documents a nominee can access within a shared vault"""
    try:
        nominee = Nominee.objects.get(id=nominee_id, nominee_user=request.user, is_verified=True, is_active=True)
    except Nominee.DoesNotExist:
        messages.error(request, 'Nominee relationship not found.')
        return redirect('accounts:nominee_dashboard')

    documents = Document.objects.filter(user=nominee.user, is_accessible_by_nominee=True).order_by('-created_at')
    return render(request, 'accounts/nominee_documents.html', {
        'nominee': nominee,
        'documents': documents,
        'can_download': nominee.access_level == 'download',
    })


@login_required
def nominee_view_document(request, document_id):
    """View a single document shared with a nominee"""
    try:
        document = Document.objects.get(id=document_id, is_accessible_by_nominee=True)
    except Document.DoesNotExist:
        messages.error(request, 'Document not found or not available for nominee access.')
        return redirect('accounts:nominee_dashboard')

    nominee = Nominee.objects.filter(
        nominee_user=request.user,
        user=document.user,
        is_verified=True,
        is_active=True
    ).first()
    if not nominee:
        messages.error(request, 'You do not have access to this document.')
        return redirect('accounts:nominee_dashboard')

    return render(request, 'accounts/nominee_view_document.html', {
        'document': document,
        'nominee': nominee,
        'can_download': nominee.access_level == 'download',
    })


@login_required
def nominee_download_document(request, document_id):
    """Allow a nominee to download a shared document if their access level allows it"""
    try:
        document = Document.objects.get(id=document_id, is_accessible_by_nominee=True)
    except Document.DoesNotExist:
        messages.error(request, 'Document not found or not available for nominee download.')
        return redirect('accounts:nominee_dashboard')

    nominee = Nominee.objects.filter(
        nominee_user=request.user,
        user=document.user,
        is_verified=True,
        is_active=True
    ).first()
    if not nominee or nominee.access_level != 'download':
        messages.error(request, 'Download is not allowed for your access level.')
        return redirect('accounts:nominee_view_document', document_id=document.id)

    if not document.file or not document.file.path:
        messages.error(request, 'Document file is unavailable.')
        return redirect('accounts:nominee_view_document', document_id=document.id)

    try:
        response = FileResponse(open(document.file.path, 'rb'), as_attachment=True, filename=document.title)
        return response
    except FileNotFoundError:
        raise Http404('File not found.')

@login_required
@require_http_methods(["GET", "POST"])
def nominee_download_all_documents(request, nominee_id):
    """Allow a nominee to download selected or all shared documents as a ZIP file"""
    try:
        import io
        import zipfile
        from django.http import HttpResponse
        
        nominee = Nominee.objects.get(
            id=nominee_id,
            nominee_user=request.user,
            is_verified=True,
            is_active=True
        )
        
        if nominee.access_level != 'download':
            messages.error(request, 'Download is not allowed for your access level.')
            return redirect('accounts:nominee_documents', nominee_id=nominee.id)
            
        documents = Document.objects.filter(user=nominee.user, is_accessible_by_nominee=True)
        
        if request.method == 'POST':
            document_ids = request.POST.getlist('document_ids')
            if document_ids:
                documents = documents.filter(id__in=document_ids)
                
        if not documents.exists():
            messages.warning(request, 'No documents found to download.')
            return redirect('accounts:nominee_documents', nominee_id=nominee.id)
            
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for doc in documents:
                if doc.file and os.path.exists(doc.file.path):
                    file_ext = os.path.splitext(doc.file.name)[1]
                    safe_title = "".join([c for c in doc.title if c.isalpha() or c.isdigit() or c==' ' or c=='-']).rstrip()
                    filename = f"{safe_title}_{doc.id}{file_ext}"
                    category = doc.category if doc.category else 'Uncategorized'
                    arcname = os.path.join(category, filename)
                    zip_file.write(doc.file.path, arcname)
                    
        zip_buffer.seek(0)
        response = HttpResponse(zip_buffer, content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename="Shared_Vault_{nominee.user.username}.zip"'
        return response
        
    except Nominee.DoesNotExist:
        messages.error(request, 'Nominee access not found.')
        return redirect('accounts:nominee_dashboard')
    except Exception as e:
        logger.error(f"Bulk download error for nominee: {str(e)}")
        messages.error(request, 'Error generating download.')
        return redirect('accounts:nominee_dashboard')

@login_required
@require_http_methods(["GET", "POST"])
def nominee_add_nominee(request, nominee_id):
    """View for a nominee to add another nominee to the shared vault, if permitted."""
    try:
        # Verify current user is a nominee for this vault and has permission
        nominee_record = get_object_or_404(Nominee, id=nominee_id, nominee_user=request.user, can_add_nominees=True)
        vault_owner = nominee_record.user
        
        if request.method == 'POST':
            name = request.POST.get('name', '').strip()
            email = request.POST.get('email', '').strip()
            phone = request.POST.get('phone', '').strip()
            relationship = request.POST.get('relationship', '').strip()
            access_level = request.POST.get('access_level', '').strip()
            
            # Basic validations
            if not name or len(name) < 3:
                messages.error(request, 'Nominee name must be at least 3 characters!')
                return redirect('accounts:nominee_add_nominee', nominee_id=nominee_id)
                
            name = InputValidator.sanitize_text(name)
            email = InputValidator.validate_email(email)
            phone = InputValidator.validate_phone(phone)
            
            valid_levels = [choice[0] for choice in Nominee.ACCESS_LEVELS]
            if access_level not in valid_levels:
                messages.error(request, 'Invalid access level!')
                return redirect('accounts:nominee_add_nominee', nominee_id=nominee_id)
                
            # Check if already added to vault owner's vault
            if Nominee.objects.filter(user=vault_owner, nominee_email=email).exists():
                messages.error(request, 'This nominee is already added to the vault!')
                return redirect('accounts:nominee_add_nominee', nominee_id=nominee_id)
                
            # Create nominee for vault owner
            new_nominee = Nominee.objects.create(
                user=vault_owner,
                nominee_name=name,
                nominee_email=email,
                nominee_phone=phone,
                relationship=relationship,
                access_level=access_level,
                is_verified=False
            )
            
            request.session['nominee_data'] = {
                'nominee_id': new_nominee.id,
                'nominee_name': name,
                'nominee_email': email,
                'nominee_phone': phone,
                'adding_as_nominee': True, # Flag to know redirect later
            }
            
            # We must send an OTP to verify the email
            otp_result = create_otp(
                email=email,
                otp_type='nominee_email',
                nominee=new_nominee
            )
            
            if otp_result['success']:
                if send_otp_email(email, otp_result['otp_code'], 'nominee_email'):
                    request.session['nominee_verification_email'] = email
                    messages.success(request, f'Verification code sent to {escape(email)}. Please verify to complete nominee addition.')
                    # Redirecting to vault app's verify_nominee_email_otp
                    return redirect('vault:verify_nominee_email_otp')
                else:
                    new_nominee.delete()
                    messages.error(request, 'Error sending verification email.')
            else:
                new_nominee.delete()
                messages.error(request, 'Error sending verification code.')
                
        return render(request, 'vault/add_nominee.html', {
            'is_nominee_adding': True,
            'vault_owner': vault_owner,
            'nominee_id': nominee_id
        })
        
    except Exception as e:
        logger.error(f"Error in nominee_add_nominee: {str(e)}")
        messages.error(request, 'Error processing request.')
        return redirect('accounts:nominee_dashboard')
