# Generated migration for OTP Verification System

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        # Update User model - add email_verified, phone_verified and make phone unique
        migrations.AlterField(
            model_name='user',
            name='phone',
            field=models.CharField(blank=True, max_length=15, null=True, unique=True),
        ),
        
        migrations.AddField(
            model_name='user',
            name='email_verified',
            field=models.BooleanField(default=False),
        ),
        
        migrations.AddField(
            model_name='user',
            name='phone_verified',
            field=models.BooleanField(default=False),
        ),
        
        # Update Nominee model - add email_verified and phone_verified fields
        migrations.AddField(
            model_name='nominee',
            name='email_verified',
            field=models.BooleanField(default=False),
        ),
        
        migrations.AddField(
            model_name='nominee',
            name='phone_verified',
            field=models.BooleanField(default=False),
        ),
        
        # Create OTPVerification model
        migrations.CreateModel(
            name='OTPVerification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(blank=True, max_length=254, null=True)),
                ('phone', models.CharField(blank=True, max_length=15, null=True)),
                ('otp_code', models.CharField(max_length=6)),
                ('otp_type', models.CharField(
                    choices=[
                        ('registration_email', 'Registration Email'),
                        ('registration_phone', 'Registration Phone'),
                        ('nominee_email', 'Nominee Email'),
                        ('nominee_phone', 'Nominee Phone')
                    ],
                    max_length=20
                )),
                ('is_verified', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('attempts', models.IntegerField(default=0)),
                ('max_attempts', models.IntegerField(default=5)),
                ('nominee', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='otp_records', to='accounts.nominee')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='otp_records', to='accounts.user')),
            ],
            options={
                'db_table': 'otp_verifications',
            },
        ),
        
        # Add indexes to OTPVerification model
        migrations.AddIndex(
            model_name='otpverification',
            index=models.Index(fields=['email', 'otp_type'], name='otp_verification_email_type_idx'),
        ),
        
        migrations.AddIndex(
            model_name='otpverification',
            index=models.Index(fields=['phone', 'otp_type'], name='otp_verification_phone_type_idx'),
        ),
        
        migrations.AddIndex(
            model_name='otpverification',
            index=models.Index(fields=['is_verified', 'expires_at'], name='otp_verification_status_idx'),
        ),
        
        # Add ordering to OTPVerification model
        migrations.AlterModelOptions(
            name='otpverification',
            options={'ordering': ['-created_at']},
        ),
    ]
