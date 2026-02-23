from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(100))
    first_name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    idno = db.Column(db.String(50), unique=True)
    cp = db.Column(db.String(20))
    course = db.Column(db.String(100))
    password = db.Column(db.String(200))
    role = db.Column(db.String(20), default='reporter')   # 'admin' or 'reporter'
    status = db.Column(db.String(20), default='pending')  # 'pending' or 'approved'
    photo = db.Column(db.String(255), nullable=True) 
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    reports = db.relationship('Report', backref='user', lazy=True)

class SignupRequest(db.Model):
    __tablename__ = 'signup_requests'
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(100))
    first_name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    idno = db.Column(db.String(50))
    cp = db.Column(db.String(20))
    course = db.Column(db.String(100))
    password = db.Column(db.String(200))
    photo = db.Column(db.String(255), nullable=True) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # --- NEW OTP FIELDS ---
    otp_secret = db.Column(db.String(32), nullable=True)
    is_email_verified = db.Column(db.Boolean, default=False)


class ResetRequest(db.Model):
    __tablename__ = 'reset_requests'
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(100))
    first_name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    idno = db.Column(db.String(50))
    new_password = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # --- NEW OTP FIELDS ---
    otp_secret = db.Column(db.String(32), nullable=True)
    is_email_verified = db.Column(db.Boolean, default=False)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(100))
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    transaction_no = db.Column(db.String(32), nullable=True)

class ArchivedReport(db.Model):
    __tablename__ = 'archived_reports'
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(120))
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    repaired_at = db.Column(db.DateTime, default=datetime.utcnow)

class Room(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    abbreviation = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)