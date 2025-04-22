from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from flask_migrate import Migrate
from sqlalchemy import or_
from models import db, User, Professional, Service, ServiceRequest
from werkzeug.utils import secure_filename
from datetime import datetime
from celery import Celery
from celery_config import make_celery
from flask_cors import CORS, cross_origin
from tasks import send_daily_reminders, generate_monthly_report, export_closed_requests
import redis
import os
import datetime
import csv




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///A-Z-services.sqlite3"
app.config['JWT_SECRET_KEY'] = 'Harshit'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REDIS_URL'] = "redis://localhost:6379/0"
app.config['broker_url'] = app.config['REDIS_URL']
app.config['result_backend'] = app.config['REDIS_URL']

app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USERNAME'] = None  # No authentication needed for MailHog
app.config['MAIL_PASSWORD'] = None  # No authentication needed for MailHog
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'admin@gmail.com'

# CORS(app, resources={r"/*": {"origins": "http://localhost:8080"}})
CORS(app,origins='http://localhost:8081',supports_credentials=True)
CORS(app,origins='http://localhost:8080',supports_credentials=True)
CORS(app, supports_credentials=True)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)



db.init_app(app) 
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
redis_client = redis.Redis.from_url(app.config['REDIS_URL'])

celery = make_celery(app)
mail = Mail(app)


@app.route('/send_test_email', methods=['POST'])
def send_test_email():
    subject = "Hello from MailHog!"
    recipients = ["harshitchaturvedi4444@gmail.com"]  # You can put any email here, MailHog will capture it.
    body = "This is a test email to check MailHog integration with Flask."

    msg = Message(subject=subject, recipients=recipients, body=body)
    
    try:
        mail.send(msg)
        return jsonify({"message": "Email sent successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# API Routes to Trigger Celery Tasks
@app.route('/trigger/daily_reminders', methods=['POST'])
@jwt_required()
def trigger_daily_reminders():
    user = get_jwt_identity()
    if user['role'] != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    send_daily_reminders.delay()
    return jsonify({'message': 'Daily reminders task triggered'})

@app.route('/trigger/monthly_report', methods=['POST'])
@jwt_required()
def trigger_monthly_report():
    user = get_jwt_identity()
    if user['role'] != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    generate_monthly_report.delay()
    return jsonify({'message': 'Monthly report generation triggered'})

@app.route('/trigger/export_closed_requests', methods=['POST'])
@jwt_required()
def trigger_export_closed_requests():
    user = get_jwt_identity()
    if user['role'] != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    export_closed_requests.delay()
    return jsonify({'message': 'Closed service request export triggered'})

# Utility function for file uploads
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




@app.route('/c_register', methods=['POST'])
def c_register():
    data = request.get_json()

    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'Email is already registered!'}), 400  

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        username=data['username'], 
        email=data['email'], 
        password=hashed_password, 
        role='customer', 
        phone_number=data['phone_number'], 
        address=data['address'], 
        pin_code=data['pincode']
    )    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'Customer registered successfully'})


@app.route('/sp_register', methods=['POST'])
def sp_register():
    data = request.form

    email = data.get('email')
    password = data.get('password')
    username = data.get('username')
    address = data.get('address')
    pincode = data.get('pincode')
    phone_num = data.get('phone_num')
    service_id = data.get('service')

    file = request.files.get('document')

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role='professional',
            phone_number=phone_num,
            address=address,
            pin_code=pincode
        )
        db.session.add(new_user)
        db.session.commit()

        user = User.query.filter_by(email=email).first()
        service = Service.query.get(service_id)

        if not service:
            return jsonify({'message': 'Selected service not found'}), 400

        new_professional = Professional(
            user_id=user.id,
            verification_status='pending',
            documents=filename,
            service=service.name
        )
        db.session.add(new_professional)
        db.session.commit()

        return jsonify({'message': 'Registration successful!'}), 201

    return jsonify({'message': 'Invalid file type. Only PDFs are allowed.'}), 400

@app.route('/services', methods=['GET'])
def get_services():
    services = Service.query.all()
    return jsonify([{'id': service.id, 'name': service.name} for service in services])


@app.route('/login', methods=['POST'])
@cross_origin()  # Allow CORS for this route
def login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'message': 'Missing email or password'}), 400
        
        print("Received login request:", data)  # Debugging

        user = User.query.filter_by(email=data['email']).first()
        if not user:
            return jsonify({'message': 'Invalid email or password'}), 401

        if not check_password_hash(user.password, data['password']):
            return jsonify({'message': 'Invalid email or password'}), 401

        if user.flagged:
            return jsonify({'message': 'Your account is flagged, you cannot login'}), 403

        if user.role == 'professional':
            professional = Professional.query.filter_by(user_id=user.id).first()
            if professional:
                if professional.verification_status == 'rejected':
                    return jsonify({'message': 'Your account is rejected by the admin, you cannot login'}), 403
                elif professional.verification_status == 'pending':
                    return jsonify({'message': 'Your account is pending admin approval'}), 403

        access_token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'access_token': access_token, 'role': user.role})

    except Exception as e:
        print("Error during login:", str(e))
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/logout', methods=['POST'])

def logout():
    return jsonify({"message": "Successfully logged out"}), 200


@app.route('/debug_token', methods=['GET'])
@jwt_required()
def debug_token():
    return jsonify(get_jwt_identity())  # Check what Vue.js is sending


@app.route('/admin', methods=['GET'])
@jwt_required()
def admin_dashboard():
    user_identity = get_jwt_identity()  # This might return a dictionary
    print(f"JWT Identity: {user_identity}")  # Debugging output

    # Ensure user_id is extracted properly
    if isinstance(user_identity, dict):
        user_id = user_identity.get("id")
    else:
        user_id = user_identity

    # Check if user_id is valid before querying the database
    if not user_id:
        return jsonify({'message': 'Invalid JWT identity'}), 400

    # Use SQLAlchemy 2.0 `db.session.get()`
    user = db.session.get(User, user_id)  # Use correct syntax

    if not user or user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    services = Service.query.all()
    professionals = Professional.query.filter(or_(Professional.verification_status == 'pending',Professional.verification_status == 'rejected')).all()
    service_requests = ServiceRequest.query.all()
    users_to_flag = User.query.filter(User.role.in_(['customer', 'service_professional'])).all()
    approved_sps = Professional.query.filter_by(verification_status="approved").all()
    print(professionals)
    return jsonify({
        'services': [{'id': s.id, 'name': s.name,'description': s.description,'base_price': str(s.base_price)} for s in services],
        'professionals': [{'id': p.id, 'service': p.service, 'status': p.verification_status,'name': p.user.username,'documents':p.documents} for p in professionals],
        'service_requests': [
            {
                'id': sr.id,
                'status': sr.status,
                'professionalName': sr.professional.user.username if sr.professional and sr.professional.user else None,
                'customerName': sr.customer.username if sr.customer else None,
                'service': sr.service.name if sr.service else None,
                'request_date': sr.request_date
            } for sr in service_requests
        ],
        'flaggable_users': [{'id': u.id, 'name': u.username, 'role': u.role, 'flagged': u.flagged} for u in users_to_flag] + 
                           [{'id': sp.user.id, 'name': sp.user.username, 'role': 'service_professional', 'flagged': sp.user.flagged} for sp in approved_sps],
        'approved_sps': [{'id': sp.user.id, 'name': sp.user.username, 'role': 'service_professional', 'flagged': sp.user.flagged} for sp in approved_sps]
    })


@app.route('/view_document/<filename>', methods=['GET'])
def view_document(filename):
    try:
        # Security check - prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return jsonify({'message': 'Invalid filename'}), 400
            
        return send_from_directory(
            app.config['UPLOAD_FOLDER'], 
            filename, 
            as_attachment=False,
            mimetype='application/pdf'  # Explicitly set PDF MIME type
        )
    except FileNotFoundError:
        return jsonify({'message': 'Document not found'}), 404



@app.route("/admin/flag_user/<int:user_id>", methods=["POST"])
@jwt_required()
def flag_user(user_id):
    user = User.query.get_or_404(user_id)
    user.flagged = True
    db.session.commit()
    return jsonify({'message': f'{user.username} has been flagged.'})

@app.route("/admin/unflag_user/<int:user_id>", methods=["POST"])
@jwt_required()
def unflag_user(user_id):
    user = User.query.get_or_404(user_id)
    user.flagged = False
    db.session.commit()
    return jsonify({'message': f'{user.username} has been unflagged.'})

@app.route('/approve_sp/<int:id>', methods=["POST"])
@jwt_required()
def approve_sp(id):
    sp = Professional.query.get_or_404(id)
    sp.verification_status = "approved"
    db.session.commit()
    return jsonify({'message': 'Service Professional approved.'})

@app.route('/reject_sp/<int:id>', methods=["POST"])
@jwt_required()
def reject_sp(id):
    sp = Professional.query.get_or_404(id)
    sp.verification_status = "rejected"
    db.session.commit()
    return jsonify({'message': 'Service Professional rejected.'})

@app.route('/admin_dashboard/new_service', methods=['POST'])
@jwt_required()
def new_service():
    user = get_jwt_identity()
    if user['role'] != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    data = request.get_json()
    try:
        new_service = Service(name=data['name'], description=data['description'], base_price=data['base_price'], created_by='admin')
        db.session.add(new_service)
        db.session.commit()
        return jsonify({'message': 'New service created successfully'})
    except Exception as e:
        db.session.rollback()
        print("Database Error:", str(e))  # Debugging
        return jsonify({'message': 'Database error', 'error': str(e)}), 500

    return jsonify({'message': 'New service created successfully'})

@app.route('/admin_dashboard/edit_service/<int:id>', methods=['PUT'])
@jwt_required()
def edit_service(id):
    user = get_jwt_identity()
    if user['role'] != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    service = Service.query.get_or_404(id)
    data = request.get_json()
    service.name = data['name']
    service.description = data['description']
    service.base_price = data['base_price']
    db.session.commit()
    return jsonify({'message': 'Service updated successfully'})

@app.route('/admin_dashboard/delete_service/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_service(id):
    user = get_jwt_identity()
    if user['role'] != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    service = Service.query.get_or_404(id)
    db.session.delete(service)
    db.session.commit()
    return jsonify({'message': 'Service deleted successfully'})

@app.route('/admin_dashboard/update_request_status/<int:id>', methods=['PUT'])
@jwt_required()
def update_request_status(id):
    user = get_jwt_identity()
    if user['role'] != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    service_request = ServiceRequest.query.get_or_404(id)
    data = request.get_json()
    service_request.status = data['status']
    db.session.commit()
    return jsonify({'message': 'Service request status updated'})


@app.route("/admin_search", methods=["GET"])
@jwt_required()
def admin_search():
    user = get_jwt_identity()
    if user["role"] != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    query = request.args.get("search", "").strip()
    if not query:
        return jsonify({"message": "Please enter a search term"}), 400

    services = Service.query.filter(Service.name.ilike(f"%{query}%")).all()
    professionals = Professional.query.filter(Professional.service.ilike(f"%{query}%")).all()
    requests = ServiceRequest.query.join(Service).filter(Service.name.ilike(f"%{query}%")).all()

    return jsonify({
        "services": [{"id": s.id, "name": s.name, "description": s.description, "base_price": s.base_price} for s in services],
        "professionals": [{"id": sp.id, "service": sp.service} for sp in professionals],
        "requests": [{"id": sr.id, "status": sr.status} for sr in requests]
    })


@app.route('/customer_search', methods=['GET'])
@jwt_required()
def customer_search():
    query = request.args.get('query', '')
    results = Service.query.filter(
        (Service.name.ilike(f"%{query}%")) | (Service.description.ilike(f"%{query}%"))
    ).all()
    return jsonify({'results': [{'id': s.id, 'name': s.name} for s in results]})

@app.route('/sp_search', methods=['GET'])
@jwt_required()
def sp_search():
    user = get_jwt_identity()
    professional = Professional.query.filter_by(user_id=user['id']).first()
    if not professional:
        return jsonify({'message': 'Professional profile not found'}), 404
    
    query = request.args.get('query', '')
    service_requests = ServiceRequest.query.join(User, ServiceRequest.customer_id == User.id).join(Service, ServiceRequest.service_id == Service.id).filter(
        ServiceRequest.professional_id == professional.id,
        (Service.name.ilike(f"%{query}%") | User.address.ilike(f"%{query}%") | User.pin_code.ilike(f"%{query}%"))
    ).all()
    
    return jsonify({'service_requests': [{'id': sr.id, 'customer': sr.customer.username, 'service': sr.service.name} for sr in service_requests]})

@app.route('/customer_dashboard', methods=['GET'])
@jwt_required()
def customer_dashboard():
    user = get_jwt_identity()
    user_data = User.query.get_or_404(user['id'])
    services = Service.query.all()
    service_history = ServiceRequest.query.filter_by(customer_id=user_data.id).all()
    return jsonify({
        'services': [{'id': s.id, 'name': s.name} for s in services],
        'service_history': [
            {
                'id': sh.id,
                'name': sh.service.name,
                'description': sh.service.description,
                'professional': sh.professional.user.username if sh.professional_id else "Pending",
                'professional_phone': sh.professional.user.phone_number if sh.professional_id else 'N/A',
                'status': sh.status,
                'request_date': sh.request_date.strftime('%Y-%m-%d'),
                'completion_date': sh.completion_date.strftime('%Y-%m-%d') if sh.completion_date else 'N/A',
                'rating': sh.rating,
                'feedback': sh.feedback
            } 
            for sh in service_history
        ]
    })

@app.route('/professional_dashboard', methods=['GET'])
@jwt_required()
def professional_dashboard():
    user = get_jwt_identity()
    professional = Professional.query.filter_by(user_id=user['id']).first()

    if not professional:
        return jsonify({'message': 'Professional profile not found'}), 404

    professional_service_name = professional.service

    request = ServiceRequest.query.join(Service).join(User, ServiceRequest.customer_id == User.id).filter(
        ServiceRequest.professional_id == None,
        professional_service_name == Service.name,
        User.flagged == False
    ).all()

    closed_requests = ServiceRequest.query.join(User, ServiceRequest.customer_id == User.id).filter(
        ServiceRequest.professional_id == professional.id,
        ServiceRequest.status.in_(['In Progress', 'Completed']),
        User.flagged == False
    ).all()

    return jsonify({
        'pending': [
            {
                'id': req.id,
                'service_name': req.service.name,
                'customer_name': req.customer.username,
                'request_date': req.request_date.strftime('%Y-%m-%d'),
                'status': req.status,
                'description': req.service.description,
                'phone_number': req.customer.phone_number,
                'pin_code': req.customer.pin_code,
                'address' : req.customer.address,
                
            } for req in request
        ],
        'closed': [
            {
                'id': req.id,
                'service_name': req.service.name,
                'customer_name': req.customer.username,
                'status': req.status,
                'completion_date': req.completion_date.strftime('%Y-%m-%d') if req.completion_date else 'N/A',
                'description': req.service.description,
                'phone_number': req.customer.phone_number,
                'request_date': req.request_date.strftime('%Y-%m-%d'),
                'pin_code': req.customer.pin_code,
            } for req in closed_requests
        ],
        'professional': {
            'id': professional.id,
            'service': professional.service,
            'username': professional.user.username
        }
    })

from datetime import datetime
@app.route('/book_service', methods=['POST'])
@jwt_required()
def book_service():
    data = request.get_json()
    service_id = data.get('service_id')
    user = get_jwt_identity()

    if not user:
        return jsonify({'message': 'User not found. Please log in.'}), 401

    customer_id = user['id']
    service = Service.query.get_or_404(service_id).first()
    request_date = datetime.now()

    new_request = ServiceRequest(
        customer_id=customer_id,
        service_id=service.id,
        request_date=request_date,
        status='Pending'
    )
    db.session.add(new_request)
    db.session.commit()

    professionals = Professional.query.filter_by(service=service.name).all()
    for professional in professionals:
        print(f"Notification sent to {professional.user.username}")

    access_token = create_access_token(identity={'id': user['id'], 'role': user['role']})
    return jsonify({'message': 'Service booked successfully!', 'access_token': access_token}), 201


@app.route('/service/<int:service_id>', methods=['GET'])
def service_details(service_id):
    service = Service.query.get_or_404(service_id)
    related_services = Service.query.filter_by(id=service_id).all()
    print(related_services)
    return jsonify({
        'service': {
            'id': service.id,
            'name': service.name,
            'description': service.description,
            'base_price': str(service.base_price)
        },
        'related': [
            {'id': rs.id, 'name': rs.name, 'description': rs.description, 'base_price': str(rs.base_price)}
            for rs in related_services
        ]
    })


@app.route('/accept_request', methods=['POST'])
@jwt_required()
def accept_request():
    user = get_jwt_identity()
    professional = Professional.query.filter_by(user_id=user['id']).first()
    if not professional:
        return jsonify({'message': 'Professional profile not found'}), 404
    
    data = request.get_json()
    service_request = ServiceRequest.query.get_or_404(data['request_id'])
    
    if service_request.status == 'Pending' and service_request.professional_id is None:
        service_request.professional_id = professional.id
        service_request.status = 'In Progress'
        db.session.commit()
        return jsonify({'message': 'Request accepted'})
    return jsonify({'message': 'Request is no longer available'}), 400

@app.route('/complete_request', methods=['POST'])
@jwt_required()
def complete_request():
    user = get_jwt_identity()
    professional = Professional.query.filter_by(user_id=user['id']).first()
    if not professional:
        return jsonify({'message': 'Professional profile not found'}), 404
    
    data = request.get_json()
    service_request = ServiceRequest.query.get_or_404(data['request_id'])
    
    if service_request.professional_id == professional.id:
        service_request.status = 'Completed'
        service_request.completion_date = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Service marked as completed'})
    return jsonify({'message': 'You cannot complete this service'}), 403

@app.route('/customer/profile', methods=['GET'])
@jwt_required()
def customer_profile():
    user = get_jwt_identity()
    user_id = user["id"] if isinstance(user, dict) else user
    customer = User.query.filter_by(id=user_id, role='customer').first()
    if not customer:
        return jsonify({'message': 'Customer profile not found'}), 404

    return jsonify({
        'id': customer.id,
        'username': customer.username,
        'email': customer.email,
        'phone_number': customer.phone_number,
        'address': customer.address,
        'pin_code': customer.pin_code
    })


@app.route('/customer/profile/edit', methods=['PUT'])
@jwt_required()
def edit_customer_profile():
    user = get_jwt_identity()
    user_id = user["id"] if isinstance(user, dict) else user

    customer = User.query.filter_by(id=user_id, role='customer').first()

    if not customer:
        return jsonify({'message': 'Customer profile not found'}), 404

    data = request.get_json()
    customer.username = data.get('username')
    customer.email = data.get('email')
    customer.phone_number = data.get('phone_number')
    customer.address = data.get('address')
    customer.pin_code = data.get('pin_code')

    db.session.commit()
    return jsonify({'message': 'Customer profile updated successfully'})


@app.route('/professional/profile', methods=['GET'])
@jwt_required()
def professional_profile():
    user = get_jwt_identity()
    user_id = user["id"] if isinstance(user, dict) else user
    professional = Professional.query.filter_by(user_id=user_id).first()
    if not professional:
        return jsonify({'message': 'Professional profile not found'}), 404

    return jsonify({
        'id': professional.id,
        'username': professional.user.username,
        'email': professional.user.email,
        'phone_number': professional.user.phone_number,
        'address': professional.user.address,
        'pin_code': professional.user.pin_code,
        'service': professional.service,
        'verification_status': professional.verification_status,
        'documents': professional.documents
    })


@app.route('/professional/profile/edit', methods=['PUT'])
@jwt_required()
def edit_professional_profile():
    user = get_jwt_identity()
    user_id = user["id"] if isinstance(user, dict) else user

    professional = Professional.query.filter_by(user_id=user_id).first()

    if not professional:
        return jsonify({'message': 'Professional profile not found'}), 404

    data = request.get_json()
    professional.user.username = data.get('username')
    professional.user.email = data.get('email')
    professional.user.phone_number = data.get('phone_number')
    professional.user.address = data.get('address')
    professional.user.pin_code = data.get('pin_code')
    professional.service = data.get('service')

    db.session.commit()
    return jsonify({'message': 'Professional profile updated successfully'})



@app.route('/sp_summary', methods=['GET'])
@jwt_required()
def sp_summary():
    user = get_jwt_identity()
    professional = Professional.query.filter_by(user_id=user['id']).first()
    if not professional:
        return jsonify({'message': 'Professional profile not found'}), 404
    
    total_requests = ServiceRequest.query.filter_by(professional_id=professional.id).count()
    completed_requests = ServiceRequest.query.filter_by(professional_id=professional.id, status='Completed').count()
    pending_requests = ServiceRequest.query.join(Service).filter(
        ServiceRequest.professional_id == None,
        Service.name == professional.service
    ).count()
    in_progress_requests = ServiceRequest.query.filter_by(professional_id=professional.id, status='In Progress').count()
    
    ratings = ServiceRequest.query.filter_by(professional_id=professional.id).with_entities(ServiceRequest.rating).all()
    rating_counts = {i: 0 for i in range(1, 6)}
    for rating in ratings:
        if rating[0]:  # Ignore null ratings
            rating_counts[rating[0]] += 1
    
    return jsonify({
        'service_overview': {
            'Total': total_requests,
            'Completed': completed_requests,
            'Pending': pending_requests,
            'In Progress': in_progress_requests
        },
        'ratings_distribution': rating_counts
    })

@app.route('/customer/summary', methods=['GET'])
@jwt_required()
def customer_summary():
    user = get_jwt_identity()
    customer = User.query.filter_by(id=user['id'], role='customer').first()

    if not customer:
        return jsonify({'message': 'Customer profile not found'}), 404

    service_requests = ServiceRequest.query.filter_by(customer_id=customer.id).all()

    if not service_requests:
        return jsonify({'message': 'No service requests found', 'summary': None})

    requested_count = sum(1 for req in service_requests if req.status == 'Pending')
    closed_count = sum(1 for req in service_requests if req.status == 'Completed')
    assigned_count = sum(1 for req in service_requests if req.status == 'In Progress')

    return jsonify({
        'summary': {
            'Requested': requested_count,
            'Closed': closed_count,
            'Assigned': assigned_count
        }
    })

@app.route('/admin_summary', methods=['GET'])
@jwt_required()
def admin_summary():
    return jsonify({'message': 'Admin summary endpoint'})

@app.route('/summary_chart/<chart_type>', methods=['GET'])
@jwt_required()
def summary_chart(chart_type):
    if chart_type == 'overall_ratings':
        data = db.session.query(
            ServiceRequest.professional_id,
            db.func.avg(ServiceRequest.rating).label('average_rating')
        ).filter(ServiceRequest.rating.isnot(None)).group_by(ServiceRequest.professional_id).all()

        print("Overall Ratings Data:", data)  # Debugging line

        return jsonify({
            'overall_ratings': [{'professional_id': sp_id, 'average_rating': avg} for sp_id, avg in data]
        }), 200

    elif chart_type == 'requests':
        data = db.session.query(ServiceRequest.status, db.func.count(ServiceRequest.id)).group_by(ServiceRequest.status).all()

        print("Service Requests Data:", data)  

        request_summary = {status: count for status, count in data}

        return jsonify({
            'request_summary': request_summary
        }), 200

    return jsonify({'message': 'Invalid chart type'}), 400


@app.route('/edit_service_request/<int:request_id>', methods=['PUT'])
@jwt_required()
def edit_service_request(request_id):
    user = get_jwt_identity()

    service_request = ServiceRequest.query.get_or_404(request_id)

    if service_request.status != 'In Progress':
        return jsonify({'message': 'Only "In Progress" requests can be edited.'}), 400

    data = request.get_json()
    new_status = data.get('status')
    rating = data.get('rating')
    feedback = data.get('feedback')

    if new_status == 'Completed':
        service_request.completion_date = datetime.utcnow()

    service_request.status = new_status
    service_request.rating = rating
    service_request.feedback = feedback

    db.session.commit()
    return jsonify({'message': 'Service request updated successfully.'})



if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True)