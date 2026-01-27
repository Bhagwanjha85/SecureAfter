from django.urls import path
from . import views

app_name = 'vault'

urlpatterns = [
    path('dashboard/', views.user_dashboard, name='user_dashboard'),
    path('my-vault/', views.my_vault, name='my_vault'),
    path('upload/', views.upload_document, name='upload_document'),
    path('document/<int:document_id>/', views.view_document, name='view_document'),
    path('document/<int:document_id>/download/', views.download_document, name='download_document'),
    path('download-all/', views.download_all_documents, name='download_all_documents'),
    path('document/<int:document_id>/delete/', views.delete_document, name='delete_document'),
    path('emergency-settings/', views.emergency_settings, name='emergency_settings'),
    path('emergency-settings/add-nominee/', views.add_nominee, name='add_nominee'),
    path('emergency-settings/verify-nominee-email-otp/', views.verify_nominee_email_otp, name='verify_nominee_email_otp'),
    path('emergency-settings/resend-nominee-email-otp/', views.resend_nominee_email_otp, name='resend_nominee_email_otp'),
    path('emergency-settings/verify-nominee-phone-otp/', views.verify_nominee_phone_otp, name='verify_nominee_phone_otp'),
    path('emergency-settings/resend-nominee-phone-otp/', views.resend_nominee_phone_otp, name='resend_nominee_phone_otp'),
    path('complete-nominee-verification/', views.complete_nominee_verification, name='complete_nominee_verification'),
    path('emergency-instructions/', views.emergency_instructions, name='emergency_instructions'),
]