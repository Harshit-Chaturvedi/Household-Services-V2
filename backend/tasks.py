from celery import Celery
from models import db, User, Professional, ServiceRequest
import csv
import redis
from flask_mail import Message

celery = Celery(__name__)
celery.conf.broker_url = "redis://localhost:6379/0"
celery.conf.result_backend = "redis://localhost:6379/0"

redis_client = redis.Redis.from_url(celery.conf.broker_url)


@celery.task()
def send_daily_reminders():
    from app import mail, app  
    with app.app_context():
        pending_requests = ServiceRequest.query.filter_by(status='Pending').all()
        notified_professionals = set()
        
        for request in pending_requests:
            professional = Professional.query.filter_by(service=request.service.name).first()
            
            if professional and professional.user_id not in notified_professionals:
                user = User.query.get(professional.user_id)
                if user and user.email:  # Assuming User model has an 'email' field
                    msg = Message(
                        'Daily Reminder: Pending Service Requests',
                        sender=app.config['MAIL_DEFAULT_SENDER'],
                        recipients=[user.email]
                    )
                    msg.body = f"Dear {user.username},\n\nYou have pending service requests to attend to. Please check your dashboard for details.\n\nThank you!"
                    
                    try:
                        mail.send(msg)
                        print(f"✅ Email successfully sent to {user.email}")
                    except Exception as e:
                        print(f"❌ Failed to send email to {user.email}: {e}")
                
                redis_client.set(f"reminder:{professional.user_id}", "Reminder sent")
                notified_professionals.add(professional.user_id)
                
    return "Daily reminders sent"



@celery.task()
def generate_monthly_report():
    from app import app, mail
    import os

    with app.app_context():
        customers = User.query.filter_by(role='customer').all()
        for customer in customers:
            service_requests = ServiceRequest.query.filter_by(customer_id=customer.id).all()
            if not service_requests:
                continue

            filename = f"monthly_report_customer_{customer.id}.csv"
            
            with open(filename, "w", newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Service ID", "Status", "Request Date"])
                for sr in service_requests:
                    writer.writerow([sr.service_id, sr.status, sr.request_date])

            msg = Message(
                subject="Your Monthly Service Report",
                sender="a2zservices@gmail.com",
                recipients=[customer.email],  # make sure customer.email is valid
                body=f"Hi {customer.username},\n\nPlease find your monthly service request report attached."
            )

            with open(filename, "rb") as f:
                msg.attach(filename, "text/csv", f.read())

            mail.send(msg)
            print(f"Monthly report sent to {customer.username} ({customer.email})")

            os.remove(filename)

    return "Monthly reports generated and emailed"

#modified
@celery.task()
def export_closed_requests():
    from app import app, mail

    with app.app_context():
        closed_requests = ServiceRequest.query.filter_by(status='Completed').all()
        filename = "closed_requests.csv"

        with open(filename, "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Request ID", "Service ID", "Customer ID", "Professional ID", "Completion Date"])
            for request in closed_requests:
                writer.writerow([request.id, request.service_id, request.customer_id, request.professional_id, request.completion_date])

        msg = Message(
            subject="Closed Requests Report",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=["harshitchaturvedi4444@gmail.com"],
            body="Please find the attached report of completed service requests."
        )

        with open(filename, "rb") as f:
            msg.attach(filename, "text/csv", f.read())

        mail.send(msg)
        print(f"CSV exported and sent via email: {filename}")

    return filename

