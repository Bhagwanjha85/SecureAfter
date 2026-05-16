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
                'icon': 'fas fa-lock',
                'title': 'Secure Vault',
                'description': 'Store your most important documents safely with military-grade encryption.'
            },
            {
                'icon': 'fas fa-users',
                'title': 'Trusted Nominees',
                'description': 'Securely assign family members or contacts who can access your vault.'
            },
            {
                'icon': 'fas fa-shield-heart',
                'title': 'Emergency Access',
                'description': 'Leave critical instructions and grant access automatically when it matters most.'
            },
        ]
    }
    return render(request, 'home.html', context)
