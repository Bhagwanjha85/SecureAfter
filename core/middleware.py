"""
Security Middleware for LifeDocs Application
Adds comprehensive security headers and request validation
"""
import logging
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

logger = logging.getLogger('django.security')
audit_logger = logging.getLogger('audit')


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers to all responses
    Protects against XSS, Clickjacking, MIME type sniffing
    """
    
    def process_response(self, request, response):
        # Content Security Policy
        if hasattr(settings, 'CSP_DEFAULT_SRC'):
            csp = f"default-src {' '.join(settings.CSP_DEFAULT_SRC)}; "
            csp += f"script-src {' '.join(settings.CSP_SCRIPT_SRC)}; "
            csp += f"style-src {' '.join(settings.CSP_STYLE_SRC)}; "
            csp += f"img-src {' '.join(settings.CSP_IMG_SRC)}; "
            csp += f"font-src {' '.join(settings.CSP_FONT_SRC)}; "
            csp += f"connect-src {' '.join(settings.CSP_CONNECT_SRC)}; "
            csp += f"frame-ancestors {' '.join(settings.CSP_FRAME_ANCESTORS)}; "
            response['Content-Security-Policy'] = csp
        
        # X-Content-Type-Options header
        response['X-Content-Type-Options'] = 'nosniff'
        
        # X-Frame-Options header
        response['X-Frame-Options'] = 'DENY'
        
        # X-XSS-Protection header
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer-Policy header
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions-Policy header
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Remove server info
        if 'Server' in response:
            del response['Server']
        
        if 'X-Powered-By' in response:
            del response['X-Powered-By']
        
        return response


class AuditLoggingMiddleware(MiddlewareMixin):
    """
    Log sensitive operations and potential security events
    """
    
    SENSITIVE_PATHS = ['/admin/', '/accounts/login', '/accounts/register', '/vault/']
    
    def process_request(self, request):
        # Log sensitive requests
        if any(request.path.startswith(path) for path in self.SENSITIVE_PATHS):
            audit_logger.info(
                f"Sensitive Request: {request.method} {request.path} from {self.get_client_ip(request)} "
                f"User: {request.user.username if request.user.is_authenticated else 'Anonymous'}"
            )
        
        return None
    
    def process_exception(self, request, exception):
        # Log security-related exceptions
        exception_type = type(exception).__name__
        
        if exception_type in ['PermissionDenied', 'SuspiciousOperation']:
            logger.warning(
                f"Security Exception: {exception_type} at {request.path} from {self.get_client_ip(request)}"
            )
        
        return None
    
    @staticmethod
    def get_client_ip(request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class RateLimitMiddleware(MiddlewareMixin):
    """
    Basic rate limiting to prevent brute force and DoS attacks
    """
    
    RATE_LIMIT_STORAGE = {}
    MAX_REQUESTS = 100
    WINDOW_SIZE = 3600  # 1 hour
    
    def process_request(self, request):
        client_ip = self.get_client_ip(request)
        current_time = __import__('time').time()
        
        # Clean old entries
        self.RATE_LIMIT_STORAGE = {
            ip: times for ip, times in self.RATE_LIMIT_STORAGE.items()
            if any(t > current_time - self.WINDOW_SIZE for t in times)
        }
        
        if client_ip not in self.RATE_LIMIT_STORAGE:
            self.RATE_LIMIT_STORAGE[client_ip] = []
        
        # Add current request
        self.RATE_LIMIT_STORAGE[client_ip].append(current_time)
        
        # Check rate limit
        recent_requests = [
            t for t in self.RATE_LIMIT_STORAGE[client_ip]
            if t > current_time - self.WINDOW_SIZE
        ]
        
        if len(recent_requests) > self.MAX_REQUESTS:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            from django.http import HttpResponse
            return HttpResponse('Too many requests', status=429)
        
        self.RATE_LIMIT_STORAGE[client_ip] = recent_requests
        return None
    
    @staticmethod
    def get_client_ip(request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
