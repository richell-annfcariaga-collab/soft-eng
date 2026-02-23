import os
import pymysql
pymysql.install_as_MySQLdb()

from datetime import datetime, timedelta
from flask import Flask, render_template, send_from_directory, jsonify
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask import send_from_directory
from backend.config import Config
from backend.models import db, User
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash

# Get the parent directory (where your frontend files are)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

app = Flask(
    __name__,
    static_folder=BASE_DIR,        # serve static files from parent
    template_folder=BASE_DIR       # templates also in parent
)

# Load configuration
app.config.from_object(Config)

# JSON / CORS tweaks
app.config['JSON_AS_ASCII'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
CORS(app, supports_credentials=True)

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# set safe max size (e.g. 2.5 MB)
app.config['MAX_CONTENT_LENGTH'] = 2.5 * 1024 * 1024  # bytes
ALLOWED_EXT = {'png','jpg','jpeg'}

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# Ensure JWT identity is preserved (we will store identity as user id, put role/name into claims)
@jwt.user_identity_loader
def user_identity_lookup(identity):
    return identity

# Called when token is invalid (malformed/etc). Respond with 401 for consistency.
@jwt.invalid_token_loader
def invalid_token_callback(err):
    return jsonify({'error': 'Invalid token'}), 401

# Called when no token present
@jwt.unauthorized_loader
def missing_token_callback(err):
    return jsonify({'error': 'Authorization token required'}), 401

# Called when token is expired
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

# Register blueprints (import after JWT/DB init to avoid circular imports)
from backend.routes.auth import auth_bp
from backend.routes.api import api_bp

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(api_bp, url_prefix='/api')

# Create DB/tables and default admin when app starts
with app.app_context():
    db.create_all()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    try:
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            print("👑 Creating default admin account...")
            admin = User(
                # FIXED: Use first_name and last_name instead of 'name'
                first_name='System',
                last_name='Administrator',
                email='admin@example.com',
                idno='admin',
                password=generate_password_hash('admin123'),
                role='admin',
                status='approved'
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Default admin created: idno=admin password=admin123")
    except OperationalError:
        # Happens when running migrations before schema updates
        print("⚠️ Skipping admin check — database schema not ready (probably migrating).")
    except Exception as e:
        print(f"⚠️ Skipping admin creation due to error: {e}")



# Serve the main page
@app.route('/')
def index():
    # CHANGE THIS: from 'login.html' to 'index.html'
    return render_template('index.html')

# Serve any other frontend file (HTML, CSS, JS)
@app.route('/<path:filename>')
def serve_frontend(filename):
    return send_from_directory(BASE_DIR, filename)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == "_main_":
    app.run(debug=True)
print("🔑 JWT SECRET:", app.config["JWT_SECRET_KEY"])