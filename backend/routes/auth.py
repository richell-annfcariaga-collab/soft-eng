import os
import numpy as np
import cv2
import re
import smtplib
import pyotp  # Requires: pip install pyotp
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from backend.models import db, User, SignupRequest, ResetRequest, Room, Report, Course
from datetime import datetime, timedelta

# --- EMAIL CONFIGURATION (UPDATE THESE) ---
# For Gmail, you need an "App Password" if 2FA is on.
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USERNAME = 'facilitydamagereportingsystemm@gmail.com'  # <--- REPLACE THIS
MAIL_PASSWORD = 'cxbx ohca ifrm oyay'     # <--- REPLACE THIS
MAIL_SENDER = MAIL_USERNAME

# 🧠 Load DNN face detection model once (OpenCV SSD)
model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
prototxt_path = os.path.join(model_dir, "deploy.prototxt")
weights_path = os.path.join(model_dir, "res10_300x300_ssd_iter_140000.caffemodel")

face_net = None
try:
    face_net = cv2.dnn.readNetFromCaffe(prototxt_path, weights_path)
    print("✅ Face detection model loaded successfully.")
except Exception as e:
    print(f"⚠️ Failed to load face detection model: {e}")

def is_human_face_dnn(image_bytes):
    """Detect a real human face using OpenCV DNN model."""
    if not face_net:
        return False
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if image is None:
            return False
        (h, w) = image.shape[:2]
        blob = cv2.dnn.blobFromImage(cv2.resize(image, (300, 300)), 1.0,
                                     (300, 300), (104.0, 177.0, 123.0))
        face_net.setInput(blob)
        detections = face_net.forward()
        for i in range(detections.shape[2]):
            confidence = detections[0, 0, i, 2]
            if confidence > 0.6:
                return True
        return False
    except Exception as e:
        print(f"Face detection error: {e}")
        return False

def send_otp_email(to_email, otp_code, purpose="Verification"):
    """Sends an OTP via SMTP."""
    try:
        msg = MIMEMultipart()
        msg['From'] = MAIL_SENDER
        msg['To'] = to_email
        msg['Subject'] = f"{purpose} OTP - Facility Reporting System"

        body = f"""
        <html>
          <body>
            <h2>{purpose} One-Time Password</h2>
            <p>Your OTP code is: <b style="font-size: 24px; color: #006A6A;">{otp_code}</b></p>
            <p>This code is valid for 5 minutes.</p>
            <p>If you did not request this, please ignore this email.</p>
          </body>
        </html>
        """
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"✅ OTP sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Email Failed: {e}")
        return False

auth_bp = Blueprint('auth_bp', __name__)

# --- NEW: COURSE ROUTES ---

@auth_bp.route('/courses', methods=['GET'])
def get_courses_public():
    """Public endpoint for signup dropdown"""
    courses = Course.query.order_by(Course.abbreviation.asc()).all()
    return jsonify([{'id': c.id, 'abbreviation': c.abbreviation, 'full_name': c.full_name} for c in courses])

@auth_bp.route('/admin/courses', methods=['GET'])
@jwt_required()
def get_courses_admin():
    claims = get_jwt()
    if claims.get('role') != 'admin': return jsonify({'error': 'Admins only'}), 403
    courses = Course.query.order_by(Course.abbreviation.asc()).all()
    return jsonify([{'id': c.id, 'abbreviation': c.abbreviation, 'full_name': c.full_name} for c in courses])

@auth_bp.route('/admin/courses', methods=['POST'])
@jwt_required()
def add_course():
    claims = get_jwt()
    if claims.get('role') != 'admin': return jsonify({'error': 'Admins only'}), 403
    data = request.get_json() or {}
    abbr = data.get('abbreviation', '').strip().upper()
    full = data.get('full_name', '').strip()
    
    if not abbr or not full: return jsonify({'error': 'Both abbreviation and full name required'}), 400
    if Course.query.filter_by(abbreviation=abbr).first(): return jsonify({'error': 'Course abbreviation already exists'}), 409
    
    db.session.add(Course(abbreviation=abbr, full_name=full))
    db.session.commit()
    return jsonify({'message': 'Course added'}), 201

@auth_bp.route('/admin/courses/<int:cid>', methods=['PUT'])
@jwt_required()
def update_course(cid):
    claims = get_jwt()
    if claims.get('role') != 'admin': return jsonify({'error': 'Admins only'}), 403
    course = Course.query.get_or_404(cid)
    data = request.get_json() or {}
    
    if 'abbreviation' in data: course.abbreviation = data['abbreviation'].strip().upper()
    if 'full_name' in data: course.full_name = data['full_name'].strip()
    
    db.session.commit()
    return jsonify({'message': 'Course updated'}), 200

@auth_bp.route('/admin/courses/<int:cid>', methods=['DELETE'])
@jwt_required()
def delete_course(cid):
    claims = get_jwt()
    if claims.get('role') != 'admin': return jsonify({'error': 'Admins only'}), 403
    course = Course.query.get_or_404(cid)
    db.session.delete(course)
    db.session.commit()
    return jsonify({'message': 'Course deleted'}), 200

# --- EXISTING ROUTES (MODIFIED FOR OTP) ---

@auth_bp.route('/signup', methods=['POST'])
def signup_request():
    last_name = request.form.get('last_name')
    first_name = request.form.get('first_name')
    email = request.form.get('email')
    idno = request.form.get('idno')
    cp = request.form.get('cp', '')
    course = request.form.get('course') 
    password = request.form.get('password')
    photo = request.files.get('photo')

    if not (last_name and first_name and email and idno and password and photo and course):
        return jsonify({'error': 'Missing fields'}), 400
    
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,12}$', password or ''):
        return jsonify({'error': 'Password must be 8-12 characters long and include uppercase, lowercase, and numbers only.'}), 400

    if not email.lower().endswith('@isu.edu.ph'):
        return jsonify({'error': 'Only @isu.edu.ph emails are allowed'}), 400

    if User.query.filter_by(idno=idno).first() or SignupRequest.query.filter_by(idno=idno).first():
        return jsonify({'error': 'ID number already exists'}), 409

    filename = secure_filename(photo.filename or '')
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    if ext not in current_app.config.get('ALLOWED_EXT', {'png','jpg','jpeg'}):
        return jsonify({'error': 'Invalid file type. Use png/jpg/jpeg'}), 400

    image_bytes = photo.read()
    if not is_human_face_dnn(image_bytes):
        return jsonify({'error': 'No human face detected. Please upload a clear face photo.'}), 400

    out_name = f"{idno}_{int(datetime.utcnow().timestamp())}.{ext}"
    out_path = os.path.join(current_app.config['UPLOAD_FOLDER'], out_name)
    with open(out_path, 'wb') as f:
        f.write(image_bytes)

    # --- OTP GENERATION ---
    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret, interval=300) # 5 Minutes Validity
    otp_code = totp.now()

    sr = SignupRequest(
        last_name=last_name,
        first_name=first_name,
        email=email,
        idno=idno,
        cp=cp,
        course=course,
        password=generate_password_hash(password),
        photo=out_name,
        created_at=datetime.utcnow(),
        otp_secret=otp_secret,       # Save Secret
        is_email_verified=False      # Not yet verified
    )
    db.session.add(sr)
    db.session.commit()

    # Send Email
    email_sent = send_otp_email(email, otp_code, "Signup")
    if not email_sent:
         # Optional: Cleanup if email fails, or just let user retry
         pass

    # Return special status to frontend
    return jsonify({
        'message': 'OTP Sent', 
        'require_otp': True, 
        'req_id': sr.id,
        'email': email
    }), 201

@auth_bp.route('/verify_signup_otp', methods=['POST'])
def verify_signup_otp():
    data = request.get_json() or {}
    req_id = data.get('req_id')
    otp_input = data.get('otp')

    sr = SignupRequest.query.get(req_id)
    if not sr:
        return jsonify({'error': 'Request not found'}), 404

    totp = pyotp.TOTP(sr.otp_secret, interval=300)
    if totp.verify(otp_input):
        sr.is_email_verified = True
        db.session.commit()
        return jsonify({'message': 'Email Verified! Request sent to Admin.'}), 200
    else:
        return jsonify({'error': 'Invalid or Expired OTP'}), 400


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    idno = data.get('idno')
    password = data.get('password')
    if not (idno and password):
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(idno=idno).first()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    if user.locked_until and datetime.utcnow() < user.locked_until:
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() // 60)
        return jsonify({'error': f'Account locked. Try again in {remaining} minute(s).'}), 403

    if not check_password_hash(user.password, password):
        if user.failed_attempts is None: user.failed_attempts = 0
        user.failed_attempts += 1

        if user.failed_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=5)
            user.failed_attempts = 0 
            db.session.commit()
            return jsonify({'error': 'Too many failed attempts. Try again after 5 minutes.'}), 403

        db.session.commit()
        return jsonify({'error': f'Invalid password. Attempts left: {5 - user.failed_attempts}'}), 401

    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()

    if user.status != 'approved':
        return jsonify({'error': 'Account not approved yet'}), 403

    full_name = f"{user.last_name}, {user.first_name}" if hasattr(user, 'last_name') else getattr(user, 'name', 'Unknown')

    token = create_access_token(
        identity=str(user.id),
        additional_claims={'role': user.role, 'name': full_name}
    )

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'role': user.role,
        'name': full_name,
        'photo': user.photo 
    }), 200

@auth_bp.route('/reset_password', methods=['POST'])
def reset_password_request():
    data = request.get_json() or {}
    idno = data.get('idno')
    newPassword = data.get('newPassword')

    if not (idno and newPassword):
        return jsonify({'error':'Missing fields'}), 400

    # --- ADDED: PASSWORD STRENGTH CHECK (Matches Signup Logic) ---
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,12}$', newPassword or ''):
        return jsonify({'error': 'Password must be 8-12 characters long and include uppercase, lowercase, and numbers only.'}), 400

    user = User.query.filter_by(idno=idno).first()
    if not user:
        # Security: Don't reveal user doesn't exist
        return jsonify({'error': 'Account not found. Reset request rejected.'}), 404

    # Generate OTP
    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret, interval=300)
    otp_code = totp.now()

    rr = ResetRequest(
        last_name=user.last_name,
        first_name=user.first_name,
        email=user.email,
        idno=idno,
        new_password=generate_password_hash(newPassword),
        created_at=datetime.utcnow(),
        otp_secret=otp_secret,
        is_email_verified=False
    )
    db.session.add(rr)
    db.session.commit()

    send_otp_email(user.email, otp_code, "Password Reset")

    return jsonify({
        'message': 'OTP Sent', 
        'require_otp': True, 
        'req_id': rr.id,
        'email': user.email
    }), 201

@auth_bp.route('/verify_reset_otp', methods=['POST'])
def verify_reset_otp():
    data = request.get_json() or {}
    req_id = data.get('req_id')
    otp_input = data.get('otp')

    rr = ResetRequest.query.get(req_id)
    if not rr:
        return jsonify({'error': 'Request not found'}), 404

    totp = pyotp.TOTP(rr.otp_secret, interval=300)
    if totp.verify(otp_input):
        rr.is_email_verified = True
        db.session.commit()
        return jsonify({'message': 'OTP Verified! Reset Request sent to Admin.'}), 200
    else:
        return jsonify({'error': 'Invalid or Expired OTP'}), 400

# ================= ADMIN ROUTES (FILTERED) =================

@auth_bp.route('/admin/signup_requests', methods=['GET'])
@jwt_required()
def get_signup_requests():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error':'Admins only'}), 403
    
    # FILTER: Only show verified email requests
    reqs = SignupRequest.query.filter_by(is_email_verified=True).order_by(SignupRequest.created_at.desc()).all()
    
    return jsonify([
        {
            'id': r.id,
            'name': f"{r.last_name}, {r.first_name}",
            'first_name': r.first_name,
            'last_name': r.last_name,
            'email': r.email,
            'idno': r.idno,
            'cp': r.cp,
            'course': r.course,
            'photo': f"/uploads/{r.photo}" if r.photo else None,
            'created_at': r.created_at.isoformat()
        } for r in reqs
    ]), 200

@auth_bp.route('/admin/approve_signup/<int:req_id>', methods=['POST'])
@jwt_required()
def approve_signup(req_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error':'Admins only'}), 403
    req = SignupRequest.query.get_or_404(req_id)
    
    user = User(
        last_name=req.last_name,
        first_name=req.first_name,
        email=req.email,
        idno=req.idno,
        cp=req.cp,
        course=req.course,
        password=req.password,
        role='reporter',
        status='approved',
        photo=req.photo
    )
    db.session.add(user)
    db.session.delete(req)
    db.session.commit()
    return jsonify({'message':'Signup approved and user created'}), 200
    
@auth_bp.route('/admin/reject_signup/<int:req_id>', methods=['POST'])
@jwt_required()
def reject_signup(req_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403
    req = SignupRequest.query.get(req_id)
    if not req:
        return jsonify({'error': 'Signup request not found'}), 404
    
    if req.photo:
        try:
            os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'], req.photo))
        except: pass

    db.session.delete(req)
    db.session.commit()
    return jsonify({'message': 'Signup request rejected and removed'}), 200

@auth_bp.route('/admin/reset_requests', methods=['GET'])
@jwt_required()
def get_reset_requests():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error':'Admins only'}), 403
    
    # FILTER: Only show verified email requests
    reqs = ResetRequest.query.filter_by(is_email_verified=True).order_by(ResetRequest.created_at.desc()).all()
    
    return jsonify([
        {
            'id': r.id,
            'name': f"{r.last_name}, {r.first_name}",
            'email': r.email,
            'idno': r.idno,
            'created_at': r.created_at.isoformat()
        } for r in reqs
    ]), 200

@auth_bp.route('/admin/reject_reset/<int:req_id>', methods=['POST'])
@jwt_required()
def reject_reset(req_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403
    req = ResetRequest.query.get(req_id)
    if not req:
        return jsonify({'error': 'Reset request not found'}), 404
    db.session.delete(req)
    db.session.commit()
    return jsonify({'message': 'Password reset request rejected'}), 200

@auth_bp.route('/admin/approve_reset/<int:req_id>', methods=['POST'])
@jwt_required()
def approve_reset(req_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error':'Admins only'}), 403
    req = ResetRequest.query.get_or_404(req_id)
    user = User.query.filter_by(idno=req.idno).first()
    if not user:
        return jsonify({'error':'User not found'}), 404
    user.password = req.new_password
    db.session.delete(req)
    db.session.commit()
    return jsonify({'message':'Password reset approved'}), 200

@auth_bp.route('/admin/users', methods=['GET'])
@jwt_required()
def list_users():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403

    users = User.query.order_by(User.last_name.asc()).all()
    return jsonify([
        {
            'id': u.id,
            'last_name': u.last_name,
            'first_name': u.first_name,
            'email': u.email,
            'idno': u.idno,
            'cp': u.cp,
            'course': u.course,
            'role': u.role,
            'status': u.status,
            'photo': f"/uploads/{u.photo}" if u.photo else None
        } for u in users
    ]), 200

@auth_bp.route('/admin/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_detail(user_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403

    u = User.query.get_or_404(user_id)
    return jsonify({
        'id': u.id,
        'last_name': u.last_name,
        'first_name': u.first_name,
        'email': u.email,
        'idno': u.idno,
        'cp': u.cp,
        'course': u.course,
        'role': u.role,
        'status': u.status,
        'photo': f"/uploads/{u.photo}" if u.photo else None
    }), 200

@auth_bp.route('/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403

    data = request.get_json() or {}
    user = User.query.get_or_404(user_id)

    for field in ['last_name', 'first_name', 'email', 'idno', 'cp', 'course', 'role', 'status']:
        if field in data:
            setattr(user, field, data[field])

    db.session.commit()
    return jsonify({'message': 'User updated successfully'}), 200

@auth_bp.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403

    user = User.query.get_or_404(user_id)

    try:
        if user.photo:
            photo_path = os.path.join(current_app.config['UPLOAD_FOLDER'], user.photo)
            if os.path.exists(photo_path):
                os.remove(photo_path)

        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User and photo deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Delete user failed: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500

@auth_bp.route('/admin/rooms', methods=['GET'])
@jwt_required()
def get_rooms():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403
    rooms = Room.query.order_by(Room.name.asc()).all()
    return jsonify([{'id': r.id, 'name': r.name} for r in rooms]), 200

@auth_bp.route('/admin/rooms', methods=['POST'])
@jwt_required()
def add_room():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Room name is required'}), 400
    if Room.query.filter_by(name=name).first():
        return jsonify({'error': 'Room already exists'}), 409
    room = Room(name=name)
    db.session.add(room)
    db.session.commit()
    return jsonify({'message': 'Room added successfully'}), 201

@auth_bp.route('/admin/rooms/<int:room_id>', methods=['PUT'])
@jwt_required()
def update_room(room_id):
    """NEW: Edit Room Name"""
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403
    
    room = Room.query.get_or_404(room_id)
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    
    if not name:
        return jsonify({'error': 'Room name cannot be empty'}), 400
        
    existing = Room.query.filter(Room.name == name, Room.id != room_id).first()
    if existing:
        return jsonify({'error': 'Room name already exists'}), 409
        
    room.name = name
    db.session.commit()
    return jsonify({'message': 'Room updated successfully'}), 200

@auth_bp.route('/admin/rooms/<int:room_id>', methods=['DELETE'])
@jwt_required()
def delete_room(room_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403
    room = Room.query.get_or_404(room_id)
    db.session.delete(room)
    db.session.commit()
    return jsonify({'message': 'Room deleted successfully'}), 200

@auth_bp.route('/rooms', methods=['GET'])
@jwt_required(optional=True)
def get_rooms_public():
    rooms = Room.query.all()
    return jsonify([{'id': r.id, 'name': r.name} for r in rooms])

@auth_bp.route('/admin/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403
    pending_count = Report.query.filter_by(status='Pending').count()
    return jsonify({'pending': pending_count}), 200