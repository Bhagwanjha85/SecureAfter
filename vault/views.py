from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.db.models import Sum, Count, Q, F
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from django.utils.html import escape
import os
import logging
import zipfile
import io
from .models import Vault, Document, EmergencyInstructions, SiteStatistics
from accounts.models import Nominee
from accounts.otp_utils import create_otp, verify_otp, send_otp_email, resend_otp
from emergency.models import EmergencyTrigger, EmergencyAccess
from reminders.models import Reminder
from audit_logs.models import AuditLog
from core.security import InputValidator
import json

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

@login_required
def user_dashboard(request):
    """User dashboard with security"""
    try:
        # Get or create vault
        vault, created = Vault.objects.get_or_create(user=request.user)
        
        # Get statistics
        total_documents = Document.objects.filter(user=request.user).count()
        categories = Document.objects.filter(user=request.user).values('category').annotate(count=Count('id'))
        

        # Get recent documents (paginated)
        recent_documents = Document.objects.filter(user=request.user).order_by('-created_at')[:5]
        
        # Get nominees
        nominees = Nominee.objects.filter(user=request.user, is_active=True)
        
        # Get upcoming reminders
        upcoming_reminders = Reminder.objects.filter(
            user=request.user, 
            is_active=True, 
            is_sent=False
        ).order_by('reminder_date')[:5]
        
        # Get emergency triggers
        emergency_triggers = EmergencyTrigger.objects.filter(user=request.user, is_active=True)
        
        context = {
            'vault': vault,
            'total_documents': total_documents,
            'categories': categories,
            'recent_documents': recent_documents,
            'nominees': nominees,
            'upcoming_reminders': upcoming_reminders,
            'emergency_triggers': emergency_triggers,
            'last_login': request.user.last_login,
        }
        
        return render(request, 'dashboard/user_dashboard.html', context)
    
    except Exception as e:
        logger.error(f"Dashboard error for user {escape(request.user.username)}: {str(e)}")
        messages.error(request, 'Error loading dashboard. Please try again.')
        return redirect('accounts:login')

@login_required
def my_vault(request):
    """View user's vault with validation"""
    try:
        documents = Document.objects.filter(user=request.user)
        
        # Filter by category if provided (validate category choice)
        category = request.GET.get('category', '').strip()
        if category:
            valid_categories = [choice[0] for choice in Document.CATEGORY_CHOICES]
            if category in valid_categories:
                documents = documents.filter(category=category)
            else:
                logger.warning(f"Invalid category attempted: {escape(category)} by user {escape(request.user.username)}")
        
        # Pagination
        page = request.GET.get('page', 1)
        try:
            page = int(page)
            if page < 1:
                page = 1
        except ValueError:
            page = 1
        
        context = {
            'documents': documents.order_by('-created_at'),
            'categories': Document.CATEGORY_CHOICES,
            'selected_category': category,
            'page': page,
        }
        
        return render(request, 'vault/my_vault.html', context)
    
    except Exception as e:
        logger.error(f"My vault error: {str(e)}")
        messages.error(request, 'Error loading vault. Please try again.')
        return render(request, 'vault/my_vault.html', {'documents': [], 'categories': Document.CATEGORY_CHOICES})

@login_required
@require_http_methods(["GET", "POST"])
def upload_document(request):
    """Upload document with security validation"""
    if request.method == 'POST':
        try:
            title = request.POST.get('title', '').strip()
            category = request.POST.get('category', '').strip()
            description = request.POST.get('description', '').strip()
            file = request.FILES.get('file')
            accessible_by_nominee = request.POST.get('accessible_by_nominee') == 'on'
            
            # Validate inputs
            if not title or len(title) < 3:
                messages.error(request, 'Document title must be at least 3 characters!')
                return redirect('vault:upload_document')
            
            if len(title) > 255:
                messages.error(request, 'Document title is too long!')
                return redirect('vault:upload_document')
            
            # Sanitize inputs
            title = InputValidator.sanitize_text(title)
            description = InputValidator.sanitize_text(description)
            
            # Validate category
            valid_categories = [choice[0] for choice in Document.CATEGORY_CHOICES]
            if category not in valid_categories:
                messages.error(request, 'Invalid category selected!')
                return redirect('vault:upload_document')
            
            if not file:
                messages.error(request, 'Please select a file to upload!')
                return redirect('vault:upload_document')
            
            # Validate file
            ALLOWED_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'application/msword',
                           'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                           'text/plain', 'application/zip']
            
            InputValidator.validate_file_type(file, ALLOWED_TYPES)
            
            # Create document
            vault, created = Vault.objects.get_or_create(user=request.user)
            
            document = Document.objects.create(
                vault=vault,
                user=request.user,
                title=title,
                category=category,
                description=description,
                file=file,
                file_size=file.size,
                file_type=file.content_type,
                is_accessible_by_nominee=accessible_by_nominee
            )
            
            # Update vault statistics
            vault.total_documents = Document.objects.filter(user=request.user).count()
            vault.total_size = Document.objects.filter(user=request.user).aggregate(
                total=Sum('file_size')
            )['total'] or 0
            vault.save()
            
            # Log the upload
            AuditLog.objects.create(
                user=request.user,
                action='document_upload',
                description=f'Uploaded document: {escape(title)}',
                metadata={'document_id': document.id, 'category': category},
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            audit_logger.info(f"Document uploaded by {escape(request.user.username)}: {escape(title)}")
            messages.success(request, 'Document uploaded successfully!')
            return redirect('vault:my_vault')
        
        except ValidationError as e:
            messages.error(request, str(e))
        except Exception as e:
            logger.error(f"Document upload error: {str(e)}")
            messages.error(request, 'Error uploading document. Please try again.')
    
    return render(request, 'vault/upload_document.html')

@login_required
def view_document(request, document_id):
    """View document with access control"""
    try:
        # Verify user owns this document
        document = get_object_or_404(Document, id=document_id, user=request.user)
        
        # Log the view
        AuditLog.objects.create(
            user=request.user,
            action='document_view',
            description=f'Viewed document: {escape(document.title)}',
            metadata={'document_id': document.id},
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        audit_logger.info(f"Document viewed by {escape(request.user.username)}: {escape(document.title)}")
        
        context = {
            'document': document,
        }
        
        return render(request, 'vault/view_document.html', context)
    
    except Exception as e:
        logger.error(f"Document view error: {str(e)}")
        messages.error(request, 'Error viewing document.')
        return redirect('vault:my_vault')

@login_required
def download_document(request, document_id):
    """Download document with security checks"""
    try:
        # Verify user owns this document
        document = get_object_or_404(Document, id=document_id, user=request.user)
        
        # Log the download
        AuditLog.objects.create(
            user=request.user,
            action='document_download',
            description=f'Downloaded document: {escape(document.title)}',
            metadata={'document_id': document.id},
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        file_path = document.file.path
        if os.path.exists(file_path):
            # Sanitize filename for download
            safe_filename = escape(document.title)
            response = FileResponse(open(file_path, 'rb'))
            response['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
            response['Content-Type'] = document.file_type or 'application/octet-stream'
            
            audit_logger.info(f"Document downloaded by {escape(request.user.username)}: {escape(document.title)}")
            return response
        else:
            logger.error(f"File not found: {file_path}")
            messages.error(request, 'File not found.')
            return redirect('vault:my_vault')
    
    except Exception as e:
        logger.error(f"Document download error: {str(e)}")
        messages.error(request, 'Error downloading file.')
        return redirect('vault:my_vault')

@login_required
def download_all_documents(request):
    """Download all user documents as a ZIP file"""
    try:
        documents = Document.objects.filter(user=request.user)
        
        if not documents.exists():
            messages.warning(request, 'No documents to download.')
            return redirect('vault:my_vault')
            
        # Create in-memory ZIP
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for doc in documents:
                if doc.file and os.path.exists(doc.file.path):
                    # Structure: Category/Title_ID.ext
                    file_ext = os.path.splitext(doc.file.name)[1]
                    # Sanitize title for filename
                    safe_title = "".join([c for c in doc.title if c.isalpha() or c.isdigit() or c==' ' or c=='-']).rstrip()
                    filename = f"{safe_title}_{doc.id}{file_ext}"
                    
                    # Use category as folder
                    category = doc.category if doc.category else 'Uncategorized'
                    arcname = os.path.join(category, filename)
                    
                    zip_file.write(doc.file.path, arcname)
        
        # Log download
        AuditLog.objects.create(
            user=request.user,
            action='bulk_download',
            description='Downloaded all documents as ZIP',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        audit_logger.info(f"Bulk download by {escape(request.user.username)}")
        
        zip_buffer.seek(0)
        response = HttpResponse(zip_buffer, content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename="SecureAfter_Vault_{request.user.username}.zip"'
        return response
        
    except Exception as e:
        logger.error(f"Bulk download error: {str(e)}")
        messages.error(request, 'Error generating download.')
        return redirect('vault:my_vault')

@login_required
@require_http_methods(["GET", "POST"])
def delete_document(request, document_id):
    """Delete document with confirmation"""
    try:
        document = get_object_or_404(Document, id=document_id, user=request.user)
        
        if request.method == 'POST':
            title = document.title
            document.delete()
            
            # Update vault statistics
            vault = request.user.vault
            vault.total_documents = Document.objects.filter(user=request.user).count()
            vault.total_size = Document.objects.filter(user=request.user).aggregate(
                total=Sum('file_size')
            )['total'] or 0
            vault.save()
            
            # Log the deletion
            AuditLog.objects.create(
                user=request.user,
                action='document_delete',
                description=f'Deleted document: {escape(title)}',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            audit_logger.info(f"Document deleted by {escape(request.user.username)}: {escape(title)}")
            messages.success(request, 'Document deleted successfully!')
            return redirect('vault:my_vault')
        
        return render(request, 'vault/confirm_delete.html', {'document': document})
    
    except Exception as e:
        logger.error(f"Document delete error: {str(e)}")
        messages.error(request, 'Error deleting document.')
        return redirect('vault:my_vault')

@login_required
def emergency_settings(request):
    """Emergency settings view"""
    try:
        nominees = Nominee.objects.filter(user=request.user, is_active=True)
        triggers = EmergencyTrigger.objects.filter(user=request.user)
        
        context = {
            'nominees': nominees,
            'triggers': triggers,
        }
        
        return render(request, 'vault/emergency_settings.html', context)
    
    except Exception as e:
        logger.error(f"Emergency settings error: {str(e)}")
        messages.error(request, 'Error loading emergency settings.')
        return redirect('vault:user_dashboard')

@login_required
@require_http_methods(["GET", "POST"])
def add_nominee(request):
    """Add nominee with email and phone OTP verification"""
    if request.method == 'POST':
        try:
            name = request.POST.get('name', '').strip()
            email = request.POST.get('email', '').strip()
            phone = request.POST.get('phone', '').strip()
            relationship = request.POST.get('relationship', '').strip()
            access_level = request.POST.get('access_level', '').strip()
            
            # Validate inputs
            if not name or len(name) < 3:
                messages.error(request, 'Nominee name must be at least 3 characters!')
                return redirect('vault:add_nominee')
            
            # Sanitize inputs
            name = InputValidator.sanitize_text(name)
            email = InputValidator.validate_email(email)
            phone = InputValidator.validate_phone(phone)
            
            # Validate access level
            valid_levels = [choice[0] for choice in Nominee.ACCESS_LEVELS]
            if access_level not in valid_levels:
                messages.error(request, 'Invalid access level!')
                return redirect('vault:add_nominee')
            
            # Check if nominee already exists
            if Nominee.objects.filter(user=request.user, nominee_email=email).exists():
                messages.error(request, 'This nominee is already added!')
                return redirect('vault:add_nominee')
            
            # Create nominee in unverified state
            nominee = Nominee.objects.create(
                user=request.user,
                nominee_name=name,
                nominee_email=email,
                nominee_phone=phone,
                relationship=relationship,
                access_level=access_level,
                is_verified=False
            )
            
            # Store nominee data in session
            request.session['nominee_data'] = {
                'nominee_id': nominee.id,
                'nominee_name': name,
                'nominee_email': email,
                'nominee_phone': phone,
            }
            
            # Create OTP for email verification
            otp_result = create_otp(
                email=email,
                otp_type='nominee_email',
                nominee=nominee
            )
            
            if otp_result['success']:
                if send_otp_email(email, otp_result['otp_code'], 'nominee_email'):
                    request.session['nominee_verification_email'] = email
                    audit_logger.info(f"Nominee email OTP sent by {escape(request.user.username)} to {escape(email)}")
                    messages.success(request, f'Verification code sent to {escape(email)}. Please verify to complete nominee addition.')
                    return redirect('vault:verify_nominee_email_otp')
                else:
                    nominee.delete()
                    messages.error(request, 'Error sending verification email. Please check your email settings.')
            else:
                # Delete the nominee if OTP creation fails
                nominee.delete()
                messages.error(request, 'Error sending verification code. Please try again.')
                logger.error(f"Error creating OTP for nominee: {otp_result['message']}")
        
        except ValidationError as e:
            messages.error(request, str(e))
        except Exception as e:
            logger.error(f"Error adding nominee: {str(e)}")
            messages.error(request, 'Error adding nominee. Please try again.')
    
    return render(request, 'vault/add_nominee.html')


@login_required
@require_http_methods(["GET", "POST"])
def verify_nominee_email_otp(request):
    """Verify nominee email OTP"""
    if 'nominee_verification_email' not in request.session or 'nominee_data' not in request.session:
        messages.error(request, 'Invalid verification session. Please add nominee again.')
        return redirect('vault:add_nominee')
    
    email = request.session.get('nominee_verification_email')
    nominee_data = request.session.get('nominee_data')
    
    if request.method == 'POST':
        try:
            otp_code = request.POST.get('otp_code', '').strip()
            
            if not otp_code:
                messages.error(request, 'Please enter the verification code.')
                return render(request, 'vault/verify_nominee_email_otp.html', {'email': email})
            
            # Verify OTP
            otp_result = verify_otp(otp_code, email=email, otp_type='nominee_email')
            
            if otp_result['success']:
                request.session['nominee_email_verified'] = True
                audit_logger.info(f"Nominee email OTP verified by {escape(request.user.username)} for {escape(email)}")
                messages.success(request, 'Email verified! Now verify phone number.')
                return redirect('vault:verify_nominee_phone_otp')
            else:
                if otp_result.get('expired'):
                    messages.error(request, otp_result['message'])
                    return redirect('vault:add_nominee')
                elif otp_result.get('max_attempts_reached'):
                    messages.error(request, otp_result['message'])
                    return redirect('vault:add_nominee')
                else:
                    messages.error(request, otp_result['message'])
        
        except Exception as e:
            logger.error(f"Error verifying nominee email OTP: {str(e)}")
            messages.error(request, 'Error verifying code. Please try again.')
    
    return render(request, 'vault/verify_nominee_email_otp.html', {'email': email})


@login_required
@require_http_methods(["POST"])
def resend_nominee_email_otp(request):
    """Resend nominee email OTP"""
    if 'nominee_verification_email' not in request.session:
        messages.error(request, 'Invalid session. Please add nominee again.')
        return redirect('vault:add_nominee')
    
    email = request.session.get('nominee_verification_email')
    
    try:
        otp_result = resend_otp(email=email, otp_type='nominee_email')
        if otp_result['success']:
            audit_logger.info(f"Nominee email OTP resent by {escape(request.user.username)} to {escape(email)}")
            messages.success(request, 'Verification code resent. Please check your email.')
        else:
            messages.error(request, otp_result['message'])
    except Exception as e:
        logger.error(f"Error resending nominee email OTP: {str(e)}")
        messages.error(request, 'Error resending code. Please try again.')
    
    return redirect('vault:verify_nominee_email_otp')


@login_required
@require_http_methods(["GET", "POST"])
def verify_nominee_phone_otp(request):
    """Verify nominee phone OTP"""
    if 'nominee_email_verified' not in request.session or 'nominee_data' not in request.session:
        messages.error(request, 'Invalid verification session. Please add nominee again.')
        return redirect('vault:add_nominee')
    
    nominee_data = request.session.get('nominee_data')
    phone = nominee_data.get('nominee_phone')
    email = request.session.get('nominee_verification_email')
    
    if not phone:
        messages.error(request, 'No phone number found.')
        return redirect('vault:add_nominee')
    
    if request.method == 'POST':
        try:
            otp_code = request.POST.get('otp_code', '').strip()
            
            if not otp_code:
                messages.error(request, 'Please enter the verification code.')
                return render(request, 'vault/verify_nominee_phone_otp.html', {'phone': phone, 'email': email})
            
            # Verify OTP
            otp_result = verify_otp(otp_code, phone=phone, otp_type='nominee_phone')
            
            if otp_result['success']:
                request.session['nominee_phone_verified'] = True
                audit_logger.info(f"Nominee phone OTP verified by {escape(request.user.username)} for {phone}")
                messages.success(request, 'Phone verified! Completing nominee addition...')
                return redirect('vault:complete_nominee_verification')
            else:
                if otp_result.get('expired'):
                    messages.error(request, otp_result['message'])
                    return redirect('vault:add_nominee')
                elif otp_result.get('max_attempts_reached'):
                    messages.error(request, otp_result['message'])
                    return redirect('vault:add_nominee')
                else:
                    messages.error(request, otp_result['message'])
        
        except Exception as e:
            logger.error(f"Error verifying nominee phone OTP: {str(e)}")
            messages.error(request, 'Error verifying code. Please try again.')
    
    return render(request, 'vault/verify_nominee_phone_otp.html', {'phone': phone, 'email': email})


@login_required
@require_http_methods(["POST"])
def resend_nominee_phone_otp(request):
    """Resend nominee phone OTP"""
    if 'nominee_data' not in request.session:
        messages.error(request, 'Invalid session. Please add nominee again.')
        return redirect('vault:add_nominee')
    
    nominee_data = request.session.get('nominee_data')
    phone = nominee_data.get('nominee_phone')
    
    if not phone:
        messages.error(request, 'No phone number found.')
        return redirect('vault:add_nominee')
    
    try:
        otp_result = resend_otp(phone=phone, otp_type='nominee_phone')
        if otp_result['success']:
            audit_logger.info(f"Nominee phone OTP resent by {escape(request.user.username)} for {phone}")
            messages.success(request, 'Verification code resent to your phone.')
        else:
            messages.error(request, otp_result['message'])
    except Exception as e:
        logger.error(f"Error resending nominee phone OTP: {str(e)}")
        messages.error(request, 'Error resending code. Please try again.')
    
    return redirect('vault:verify_nominee_phone_otp')


@login_required
@require_http_methods(["GET"])
def complete_nominee_verification(request):
    """Complete nominee verification after both email and phone OTP verification"""
    if 'nominee_email_verified' not in request.session or 'nominee_phone_verified' not in request.session or 'nominee_data' not in request.session:
        messages.error(request, 'Invalid verification session. Please add nominee again.')
        return redirect('vault:add_nominee')
    
    try:
        nominee_data = request.session.get('nominee_data')
        nominee_id = nominee_data.get('nominee_id')
        
        # Update nominee to verified state
        nominee = Nominee.objects.get(id=nominee_id, user=request.user)
        nominee.is_verified = True
        nominee.email_verified = True
        nominee.phone_verified = True
        nominee.save(update_fields=['is_verified', 'email_verified', 'phone_verified'])
        
        # Log nominee verification
        AuditLog.objects.create(
            user=request.user,
            action='nominee_verified',
            description=f'Nominee verified: {escape(nominee.nominee_name)}',
            metadata={'nominee_id': nominee.id},
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Clear session data
        if 'nominee_data' in request.session:
            del request.session['nominee_data']
        if 'nominee_verification_email' in request.session:
            del request.session['nominee_verification_email']
        if 'nominee_email_verified' in request.session:
            del request.session['nominee_email_verified']
        if 'nominee_phone_verified' in request.session:
            del request.session['nominee_phone_verified']
        
        audit_logger.info(f"Nominee added and verified by {escape(request.user.username)}: {escape(nominee.nominee_name)}")
        messages.success(request, f'{escape(nominee.nominee_name)} has been added as a verified nominee!')
        return redirect('vault:emergency_settings')
    
    except Nominee.DoesNotExist:
        logger.error(f"Nominee not found for user {escape(request.user.username)}")
        messages.error(request, 'Nominee not found. Please try again.')
        return redirect('vault:add_nominee')
    except Exception as e:
        logger.error(f"Error completing nominee verification: {str(e)}")
        messages.error(request, 'Error completing nominee verification. Please try again.')
        return redirect('vault:add_nominee')

@login_required
@require_http_methods(["GET", "POST"])
def emergency_instructions(request):
    """Emergency instructions with security"""
    try:
        instructions, created = EmergencyInstructions.objects.get_or_create(user=request.user)
        
        if request.method == 'POST':
            # Sanitize all inputs
            emergency_message = InputValidator.sanitize_text(
                request.POST.get('emergency_message', ''), allow_html=True
            )
            medical_consent = InputValidator.sanitize_text(
                request.POST.get('medical_consent', ''), allow_html=True
            )
            family_guidance = InputValidator.sanitize_text(
                request.POST.get('family_guidance', ''), allow_html=True
            )
            additional_notes = InputValidator.sanitize_text(
                request.POST.get('additional_notes', ''), allow_html=True
            )
            
            instructions.emergency_message = emergency_message
            instructions.medical_consent = medical_consent
            instructions.family_guidance = family_guidance
            instructions.additional_notes = additional_notes
            instructions.save()
            
            # Log the update
            AuditLog.objects.create(
                user=request.user,
                action='emergency_instructions_update',
                description='Updated emergency instructions',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            audit_logger.info(f"Emergency instructions updated by {escape(request.user.username)}")
            messages.success(request, 'Emergency instructions updated successfully!')
            return redirect('vault:emergency_instructions')
        
        context = {
            'instructions': instructions,
        }
        
        return render(request, 'vault/emergency_instructions.html', context)
    
    except Exception as e:
        logger.error(f"Emergency instructions error: {str(e)}")
        messages.error(request, 'Error updating instructions. Please try again.')
        return redirect('vault:emergency_settings')