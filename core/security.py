"""
Security Utilities for LifeDocs
Input validation, sanitization, and secure operations
"""
import re
import logging
from urllib.parse import quote
from django.utils.html import escape
from django.core.exceptions import ValidationError
import bleach

logger = logging.getLogger('django.security')


class InputValidator:
    """Validate and sanitize user inputs to prevent injection attacks"""
    
    # Allowed tags and attributes for rich text (if needed)
    ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'li', 'ul', 'ol', 'blockquote']
    ALLOWED_ATTRIBUTES = {}
    
    @staticmethod
    def sanitize_text(text, allow_html=False):
        """
        Sanitize text input to prevent XSS attacks
        
        Args:
            text: Input text to sanitize
            allow_html: Whether to allow HTML tags (defaults to False)
        
        Returns:
            Sanitized text
        """
        if not text:
            return ''
        
        if allow_html:
            # Clean HTML but allow certain tags
            return bleach.clean(
                text,
                tags=InputValidator.ALLOWED_TAGS,
                attributes=InputValidator.ALLOWED_ATTRIBUTES,
                strip=True
            )
        else:
            # Remove all HTML tags
            return escape(str(text))
    
    @staticmethod
    def validate_email(email):
        """
        Validate email format
        
        Args:
            email: Email address to validate
        
        Returns:
            Validated email or raises ValidationError
        """
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, str(email)):
            raise ValidationError('Invalid email format')
        
        if len(email) > 254:
            raise ValidationError('Email address is too long')
        
        return email.lower().strip()
    
    @staticmethod
    def validate_phone(phone):
        """
        Validate phone number format
        
        Args:
            phone: Phone number to validate
        
        Returns:
            Validated phone number or raises ValidationError
        """
        # Remove common separators
        cleaned = re.sub(r'[\s\-\(\)\.]+', '', str(phone))
        
        # Check if it's a valid phone format (10-15 digits)
        if not re.match(r'^\+?1?\d{9,14}$', cleaned):
            raise ValidationError('Invalid phone number format')
        
        return cleaned
    
    @staticmethod
    def validate_username(username):
        """
        Validate username format
        
        Args:
            username: Username to validate
        
        Returns:
            Validated username or raises ValidationError
        """
        if len(username) < 3:
            raise ValidationError('Username must be at least 3 characters')
        
        if len(username) > 150:
            raise ValidationError('Username must be less than 150 characters')
        
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            raise ValidationError('Username can only contain letters, numbers, dots, hyphens and underscores')
        
        return username.strip()
    
    @staticmethod
    def validate_url(url):
        """
        Validate URL format
        
        Args:
            url: URL to validate
        
        Returns:
            Validated URL or raises ValidationError
        """
        url_pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
        
        if not re.match(url_pattern, str(url)):
            raise ValidationError('Invalid URL format')
        
        return url.strip()
    
    @staticmethod
    def validate_file_type(file_obj, allowed_types):
        """
        Validate file type based on MIME type
        
        Args:
            file_obj: File object from request
            allowed_types: List of allowed MIME types or extensions
        
        Returns:
            Validated file or raises ValidationError
        """
        if not file_obj:
            raise ValidationError('No file provided')
        
        # Check file size (max 5MB)
        if file_obj.size > 5 * 1024 * 1024:
            raise ValidationError('File size exceeds 5MB limit')
        
        # Check file type
        file_type = file_obj.content_type
        file_ext = file_obj.name.split('.')[-1].lower()
        
        if file_type not in allowed_types and file_ext not in allowed_types:
            raise ValidationError(f'File type {file_type} is not allowed')
        
        return file_obj
    
    @staticmethod
    def validate_password_strength(password):
        """
        Validate password strength
        
        Args:
            password: Password to validate
        
        Returns:
            Validated password or raises ValidationError
        """
        if len(password) < 12:
            raise ValidationError('Password must be at least 12 characters')
        
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain lowercase letters')
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain uppercase letters')
        
        if not re.search(r'[0-9]', password):
            raise ValidationError('Password must contain numbers')
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            raise ValidationError('Password must contain special characters')
        
        return password


class SQLInjectionPrevention:
    """
    Methods to prevent SQL injection attacks
    Django ORM already provides protection, but here are additional safeguards
    """
    
    @staticmethod
    def escape_search_query(query):
        """
        Escape search query to prevent SQL injection
        Django ORM uses parameterized queries, but this is an extra layer
        
        Args:
            query: Search query string
        
        Returns:
            Escaped query
        """
        # Replace dangerous characters with escaped versions
        dangerous_chars = ['%', '_', ';', '--', '/*', '*/', 'xp_', 'sp_']
        
        result = str(query)
        for char in dangerous_chars:
            if char in result.lower():
                logger.warning(f"Suspicious characters detected in search query: {query}")
                result = result.replace(char, '')
        
        return result.strip()
    
    @staticmethod
    def log_suspicious_query(query_string):
        """
        Log potentially suspicious queries
        """
        if any(dangerous in query_string.lower() for dangerous in ['union', 'select', 'insert', 'update', 'delete', 'drop']):
            logger.warning(f"Potentially malicious query detected: {query_string}")


class EncryptionUtility:
    """
    Encryption utilities for sensitive data
    """
    
    @staticmethod
    def encrypt_sensitive_data(data):
        """
        Encrypt sensitive data
        """
        from cryptography.fernet import Fernet
        from django.conf import settings
        
        # Use a key from settings or generate one
        key = getattr(settings, 'ENCRYPTION_KEY', Fernet.generate_key())
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(str(data).encode())
        
        return encrypted_data
    
    @staticmethod
    def decrypt_sensitive_data(encrypted_data):
        """
        Decrypt sensitive data
        """
        from cryptography.fernet import Fernet
        from django.conf import settings
        
        key = getattr(settings, 'ENCRYPTION_KEY', None)
        if not key:
            raise ValueError('Encryption key not configured')
        
        cipher_suite = Fernet(key)
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        
        return decrypted_data


class RequestValidator:
    """
    Validate HTTP requests for security
    """
    
    @staticmethod
    def validate_request_origin(request, allowed_origins):
        """
        Validate request origin to prevent CSRF and unauthorized access
        """
        origin = request.META.get('HTTP_ORIGIN', request.META.get('HTTP_REFERER', ''))
        
        if origin and origin not in allowed_origins:
            logger.warning(f"Request from unauthorized origin: {origin}")
            return False
        
        return True
    
    @staticmethod
    def validate_user_agent(request):
        """
        Check for suspicious user agents
        """
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        
        suspicious_patterns = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget']
        
        if any(pattern in user_agent for pattern in suspicious_patterns):
            logger.info(f"Non-browser user agent detected: {user_agent}")
            return False
        
        return True
