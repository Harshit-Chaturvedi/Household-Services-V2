# celery_config.py

from celery import Celery
from celery.schedules import crontab  # For scheduling periodic tasks

def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['broker_url'], backend=app.config['result_backend'])
    celery.conf.update(app.config)

    celery.conf.timezone = 'Asia/Kolkata'  # Set your timezone
    
    # Setting up the periodic task scheduler
    celery.conf.beat_schedule = {
        'send-daily-reminders': {
            'task': 'tasks.send_daily_reminders',
            'schedule': 10,  # Runs daily at 8:00 AM
        },
        'generate-monthly-report': {
            'task': 'tasks.generate_monthly_report',
            'schedule': 10,  # Runs monthly on the 1st at 12:00 AM
        },
        'export-closed-requests': {
            'task': 'tasks.export_closed_requests',
            'schedule': 10,  # Runs daily at 11:00 PM
        },
    }

    return celery
