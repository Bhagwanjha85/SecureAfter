from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

@require_http_methods(["GET"])
def home_view(request):
    """Home page view"""
    context = {
        'page_title': 'LifeDocs - Secure Document Management',
        'features': [
            {
                'icon': '🔐',
                'title': 'Secure Vault',
                'description': 'Store your important documents safely with encryption'
            },
            {
                'icon': '👥',
                'title': 'Trusted Nominees',
                'description': 'Add family members or trusted contacts with OTP verification'
            },
            {
                'icon': '📋',
                'title': 'Emergency Instructions',
                'description': 'Leave important instructions for your nominees'
            },
            {
                'icon': '🔔',
                'title': 'Smart Reminders',
                'description': 'Get reminders about important documents and deadlines'
            },
            {
                'icon': '📱',
                'title': 'Mobile Ready',
                'description': 'Access your vault anytime, anywhere from any device'
            },
            {
                'icon': '✅',
                'title': 'Peace of Mind',
                'description': 'Ensure your loved ones are protected and informed'
            },
        ]
    }
    return render(request, 'home.html', context)
