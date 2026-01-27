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
import logging
import os
import subprocess
from .models import User, Nominee, OTPVerification
from .otp_utils import create_otp, verify_otp, send_otp_email, resend_otp, send_otp_phone
from vault.models import Vault
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
            password = request.POST.get('password', '')
            password2 = request.POST.get('password2', '')
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
            user = User.objects.create_user(
                username=reg_data['username'],
                email=reg_data['email'],
                password=reg_data['password'],
                phone=reg_data['phone'],
                user_type=reg_data['user_type'],
                email_verified=True,
                phone_verified=request.session.get('phone_verified', False)
            )
            
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
            
            # Attempt to authenticate
            user = authenticate(request, username=username, password=password)
            
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
                messages.success(request, f'Welcome back!')
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
                messages.error(request, 'Invalid username or password!')
                
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