from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('verify-email-otp/', views.verify_email_otp, name='verify_email_otp'),
    path('resend-email-otp/', views.resend_email_otp, name='resend_email_otp'),
    path('verify-phone-otp/', views.verify_phone_otp, name='verify_phone_otp'),
    path('resend-phone-otp/', views.resend_phone_otp, name='resend_phone_otp'),
    path('complete-registration/', views.complete_registration, name='complete_registration'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('change-password/', views.change_password, name='change_password'),
    path('delete-account/', views.delete_account, name='delete_account'),
    
    # Password Reset URLs
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('verify-reset-otp/', views.verify_reset_otp_view, name='verify_reset_otp'),
    path('resend-reset-otp/', views.resend_reset_otp_view, name='resend_reset_otp'),
    path('reset-password-confirm/', views.reset_password_confirm_view, name='reset_password_confirm'),
    
    # =====================================================
    # SMART EMERGENCY TRIGGER SYSTEM URLs
    # =====================================================
    path('emergency-settings/', views.emergency_settings_view, name='emergency_settings'),
    path('check-in/', views.check_in_now, name='check_in'),
    path('emergency-status/', views.emergency_status_api, name='emergency_status_api'),
    
    # Nominee Access Request URLs
    path('access-requests/', views.nominee_access_requests_view, name='nominee_access_requests'),
    path('access-requests/respond/<int:request_id>/', views.respond_to_access_request, name='respond_to_access_request'),
    path('nominee-dashboard/', views.nominee_dashboard, name='nominee_dashboard'),
    path('nominee-documents/<int:nominee_id>/', views.nominee_documents, name='nominee_documents'),
    path('nominee-document/<int:document_id>/', views.nominee_view_document, name='nominee_view_document'),
    path('nominee-document/<int:document_id>/download/', views.nominee_download_document, name='nominee_download_document'),
    path('nominee-documents/<int:nominee_id>/download-all/', views.nominee_download_all_documents, name='nominee_download_all_documents'),
    path('request-vault-access/<int:nominee_id>/', views.request_vault_access, name='request_vault_access'),
    path('nominee-dashboard/add-nominee/<int:nominee_id>/', views.nominee_add_nominee, name='nominee_add_nominee'),
]