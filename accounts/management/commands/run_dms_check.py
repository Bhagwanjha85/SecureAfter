from django.core.management.base import BaseCommand
from accounts.tasks import run_dead_mans_switch_check


class Command(BaseCommand):
    help = 'Run the Dead Man\'s Switch check — sends warning/emergency emails to users and nominees'

    def handle(self, *args, **options):
        self.stdout.write('Running Dead Man\'s Switch check...')
        count = run_dead_mans_switch_check()
        self.stdout.write(self.style.SUCCESS(f'Done. Processed {count} user(s).'))
