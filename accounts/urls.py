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
]