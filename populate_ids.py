import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from accounts.models import User

users = User.objects.filter(unique_id__isnull=True)
count = 0
for u in users:
    u.save()  # The save method auto-generates the unique_id if not present
    count += 1

print(f"Successfully generated unique IDs for {count} existing users.")
