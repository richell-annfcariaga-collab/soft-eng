import numpy as np
import json
import zipfile
import google.generativeai as genai
import io
from PIL import Image
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from sklearn.cluster import KMeans
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from backend.models import db, Report, User, Room, Course, SignupRequest, ResetRequest
from datetime import datetime
import os
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm, inch
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import letter, landscape, portrait
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from flask import send_file 
from flask_jwt_extended import decode_token
from io import BytesIO 
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
genai.configure(api_key="AIzaSyDB9PeLbcvbZH_B7MbZgVcUnkzpnuwZcbg")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
api_bp = Blueprint('api_bp', __name__)

@api_bp.route('/reports', methods=['GET'])
@jwt_required()
def list_reports():
    claims = get_jwt()
    user_id = get_jwt_identity()

    # Admin sees all reports, Reporters see only theirs
    if claims.get('role') == 'admin':
        reports = Report.query.order_by(Report.created_at.desc()).all()
    else:
        reports = Report.query.filter_by(user_id=user_id).order_by(Report.created_at.desc()).all()

    out = []
    for r in reports:
        reporter = User.query.get(r.user_id)
        out.append({
            'id': r.id,
            'transaction_no': r.transaction_no,
            'user': f"{reporter.last_name}, {reporter.first_name}" if reporter else 'Unknown',
            'user_id': r.user_id,
            'location': r.location,
            'description': r.description,
            'status': r.status,
            'created_at': r.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify(out), 200

@api_bp.route('/reports', methods=['POST'])
@jwt_required()
def create_report():
    data = request.get_json() or {}
    if not (data.get('location') and data.get('desc')):
        return jsonify({'error': 'Missing fields'}), 400

    user_id = get_jwt_identity()

    new_report = Report(
        location=data['location'],
        description=data['desc'],
        user_id=user_id,
        status='Pending'
    )
    db.session.add(new_report)
    db.session.commit()

    # Generate transaction number
    date = datetime.now().strftime("%Y%m%d")
    new_report.transaction_no = f"TR-{date}-{str(new_report.id).zfill(4)}"
    db.session.commit()

    return jsonify({'message': 'Report created', 'id': new_report.id}), 201

@api_bp.route('/reports/<int:rid>', methods=['PUT'])
@jwt_required()
def update_report(rid):
    """Admin Status Update Endpoint"""
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error':'Admins only'}), 403
    data = request.get_json() or {}
    r = Report.query.get_or_404(rid)
    if 'status' in data:
        r.status = data['status']
    db.session.commit()
    return jsonify({'message':'Updated'}), 200

# --- NEW: Reporter Edit Endpoint ---
@api_bp.route('/reports/<int:rid>/edit', methods=['PUT'])
@jwt_required()
def edit_report_by_owner(rid):
    """Allow reporters to edit their own report while status == 'Pending'."""
    user_id = int(get_jwt_identity())
    r = Report.query.get_or_404(rid)

    # Only owner can edit
    if r.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    # Only pending allowed
    if r.status != 'Pending':
        return jsonify({'error': 'Cannot edit processed reports'}), 403

    data = request.get_json() or {}
    if 'location' in data:
        r.location = data['location']
    if 'description' in data:
        r.description = data['description']

    db.session.commit()
    return jsonify({'message': 'Report updated successfully'}), 200

@api_bp.route('/reports/analyze_image', methods=['POST'])
@jwt_required()
def analyze_report_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
        
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        img = Image.open(file)
        
       
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        prompt = """
        You are a Facility Maintenance Expert. 
        Analyze this image and provide a concise, technical description of the damage or issue shown. 
        Focus on the object, the type of damage (broken, leaking, burnt, etc.), and potential cause if visible.
        Do not say "The image shows...". Just describe the issue directly.
        Example: "Cracked monitor screen on the top left corner." or "Leaking water pipe under the sink."
        """
        
        response = model.generate_content([prompt, img])
        description = response.text.strip()
        
        return jsonify({'description': description}), 200

    except Exception as e:
        print(f"Image Analysis Error: {e}")
        return jsonify({'description': 'Could not analyze image. Please describe manually.'}), 500

# --- UPDATED: Delete Endpoint (Admin + Owner Pending) ---
@api_bp.route('/reports/<int:rid>', methods=['DELETE'])
@jwt_required()
def delete_report(rid):
    claims = get_jwt()
    user_id = int(get_jwt_identity())
    r = Report.query.get_or_404(rid)

    is_admin = claims.get('role') == 'admin'
    is_owner = r.user_id == user_id

    if is_admin:
        pass # Admin can delete anything
    elif is_owner:
        if r.status != 'Pending':
             return jsonify({'error': 'Cannot delete processed reports'}), 403
    else:
        return jsonify({'error':'Unauthorized'}), 403

    db.session.delete(r)
    db.session.commit()
    return jsonify({'message':'Deleted'}), 200

@api_bp.route('/reports/mine', methods=['GET'])
@jwt_required()
def list_my_reports():
    user_id = get_jwt_identity()
    reports = Report.query.filter_by(user_id=user_id).order_by(Report.created_at.desc()).all()
    return jsonify([
        {
            'id': r.id,
            'transaction_no': r.transaction_no,
            'location': r.location,
            'description': r.description,
            'status': r.status,
            'created_at': r.created_at.isoformat()
        }
        for r in reports
    ]), 200

# --- PDF Export ---

# --- PROFESSIONAL PDF EXPORT (Corporate Design) ---

@api_bp.route('/reports/export_pdf', methods=['POST'])
@jwt_required()
def export_reports_pdf():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({"error": "Admins only"}), 403

    # 1. GET PRINTER NAME
    # We retrieve the 'name' claim we saved during login (in auth.py)
    printer_name = claims.get('name', 'Authorized Admin')

    # 2. Get IDs
    data = request.get_json() or {}
    report_ids = data.get('ids', [])
    if not report_ids:
        return jsonify({"error": "No reports selected"}), 400

    # 3. Fetch & Sort Data
    reports_db = Report.query.filter(Report.id.in_(report_ids)).all()
    reports_map = {r.id: r for r in reports_db}
    ordered_reports = []
    for rid in report_ids:
        if rid in reports_map:
            ordered_reports.append(reports_map[rid])

    # 4. Setup PDF Buffer
    buffer = BytesIO()
    
    # --- CUSTOM HEADER & FOOTER FUNCTION ---
    def add_header_footer(canvas, doc):
        canvas.saveState()
        
        # A. TOP HEADER BAR (Teal Background)
        canvas.setFillColor(colors.HexColor('#006A6A'))
        canvas.rect(0, 10.5*inch, 8.5*inch, 0.5*inch, fill=1, stroke=0)
        
        # B. LOGO
        logo_path = os.path.join(current_app.config['UPLOAD_FOLDER'], "isulogo.png")
        if os.path.exists(logo_path):
            canvas.drawImage(logo_path, 40, 10.3*inch, width=40, height=40, mask='auto')

        # C. TITLE
        canvas.setFont("Helvetica-Bold", 16)
        canvas.setFillColor(colors.white)
        canvas.drawString(90, 10.65*inch, "Computer Laboratory Facility Report")
        
        # D. FOOTER (Updated with Printed By)
        # Gray line
        canvas.setStrokeColor(colors.lightgrey)
        canvas.line(40, 50, 570, 50)
        
        # Text Info
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.gray)
        
        # Line 1: System Name
        canvas.drawString(40, 38, "Generated by Facility Reporting System")
        
        # Line 2: Printed By (NEW)
        canvas.drawString(40, 26, f"Printed by: {printer_name}")
        
        # Page Number (Right Aligned)
        page_num = canvas.getPageNumber()
        canvas.drawRightString(570, 35, f"Page {page_num}")
        
        canvas.restoreState()

    # 5. Document Config
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=portrait(letter),
        rightMargin=40, leftMargin=40, 
        topMargin=80, bottomMargin=60
    )
    
    elements = []
    styles = getSampleStyleSheet()

    # --- METADATA SECTION ---
    date_str = datetime.now().strftime("%B %d, %Y")
    time_str = datetime.now().strftime("%I:%M %p")
    
    meta_style = ParagraphStyle('Meta', parent=styles['Normal'], fontSize=9, textColor=colors.gray)
    
    meta_data = [
        [Paragraph(f"<b>Date:</b> {date_str}", meta_style), 
         Paragraph(f"<b>Time:</b> {time_str}", meta_style),
         Paragraph(f"<b>Total Records:</b> {len(ordered_reports)}", meta_style)]
    ]
    
    meta_table = Table(meta_data, colWidths=[200, 150, 150])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 15),
    ]))
    elements.append(meta_table)

    # --- MAIN DATA TABLE ---
    headers = ["ID", "Reporter", "Location", "Description", "Status"]
    h_style = ParagraphStyle('H', parent=styles['Normal'], fontSize=9, textColor=colors.white, alignment=1)
    
    data = [[Paragraph(f"<b>{h}</b>", h_style) for h in headers]]
    b_style = ParagraphStyle('B', parent=styles['Normal'], fontSize=9, leading=11)
    
    for r in ordered_reports:
        u = User.query.get(r.user_id)
        reporter = f"{u.last_name}, {u.first_name}" if u else "Unknown"
        
        if r.status == 'Pending': status_col = "#EA9C10"
        elif r.status == 'Repaired': status_col = "#006D31"
        else: status_col = "#006A6A"
        
        status_cell = Paragraph(f"<b><font color='{status_col}'>{r.status}</font></b>", b_style)
        
        data.append([
            Paragraph(r.transaction_no.split('-')[-1], b_style),
            Paragraph(reporter, b_style),
            Paragraph(r.location, b_style),
            Paragraph(r.description, b_style),
            status_cell
        ])

    t = Table(data, colWidths=[40, 110, 80, 240, 70])
    
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8F9F9')]),
        ('LINEBELOW', (0,0), (-1,0), 2, colors.HexColor('#006A6A')),
        ('LINEBELOW', (0,1), (-1,-1), 0.5, colors.HexColor('#e5e7e9')),
    ]))
    
    elements.append(t)

    # 6. Build
    doc.build(elements, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    buffer.seek(0)
    
    return send_file(
        buffer, 
        as_attachment=True, 
        download_name=f"Report_{datetime.now().strftime('%Y-%m-%d')}.pdf", 
        mimetype='application/pdf'
    )

@api_bp.route('/reports/download_pdf', methods=['GET'])
def download_reports_pdf():
    token = request.args.get("token", None)
    if not token:
        return jsonify({"error": "Authorization token required"}), 401

    try:
        decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    file_path = os.path.join(BASE_DIR, "..", "generated_reports.pdf")
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    return send_file(file_path, as_attachment=True)

# ==========================================
#  BACKUP & RECOVERY SYSTEM
# ==========================================

@api_bp.route('/admin/backup', methods=['GET'])
@jwt_required()
def backup_system():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403

    try:
        # 1. Serialize Database Data
        data = {
            'rooms': [{'id': r.id, 'name': r.name} for r in Room.query.all()],
            'courses': [{'id': c.id, 'abbreviation': c.abbreviation, 'full_name': c.full_name} for c in Course.query.all()],
            'users': [{
                'id': u.id, 'last_name': u.last_name, 'first_name': u.first_name, 
                'email': u.email, 'idno': u.idno, 'cp': u.cp, 'course': u.course, 
                'password': u.password, 'role': u.role, 'status': u.status, 
                'photo': u.photo
            } for u in User.query.all()],
            'reports': [{
                'id': r.id, 'location': r.location, 'description': r.description,
                'status': r.status, 'created_at': r.created_at.isoformat(),
                'user_id': r.user_id, 'transaction_no': r.transaction_no
            } for r in Report.query.all()],
            'signup_requests': [{
                'id': s.id, 'last_name': s.last_name, 'first_name': s.first_name,
                'email': s.email, 'idno': s.idno, 'course': s.course, 'photo': s.photo
            } for s in SignupRequest.query.all()]
        }

        # 2. Create ZIP File in Memory
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add JSON Data
            zf.writestr('database.json', json.dumps(data, indent=4))
            
            # Add Uploaded Images
            upload_folder = current_app.config['UPLOAD_FOLDER']
            if os.path.exists(upload_folder):
                for root, dirs, files in os.walk(upload_folder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Add file to zip, preserving structure relative to upload folder
                        arcname = os.path.join('uploads', file)
                        zf.write(file_path, arcname)

        memory_file.seek(0)
        
        filename = f"System_Backup_{datetime.now().strftime('%Y-%m-%d_%H%M')}.zip"
        return send_file(
            memory_file,
            download_name=filename,
            as_attachment=True,
            mimetype='application/zip'
        )

    except Exception as e:
        print(f"Backup Error: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/admin/recover', methods=['POST'])
@jwt_required()
def recover_system():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # 1. Clear Existing Database (Order matters to prevent Foreign Key errors)
        # Delete children first, then parents
        Report.query.delete()
        SignupRequest.query.delete()
        ResetRequest.query.delete()
        User.query.delete()
        Room.query.delete()
        Course.query.delete()
        db.session.commit()

        # 2. Extract Zip
        with zipfile.ZipFile(file, 'r') as zf:
            # Restore Photos
            upload_folder = current_app.config['UPLOAD_FOLDER']
            for member in zf.infolist():
                if member.filename.startswith('uploads/'):
                    # Strip 'uploads/' prefix to save directly into folder
                    filename = os.path.basename(member.filename)
                    if filename: # Skip directories
                        source = zf.open(member)
                        target = open(os.path.join(upload_folder, filename), "wb")
                        with source, target:
                            target.write(source.read())

            # Restore Database
            if 'database.json' in zf.namelist():
                data = json.loads(zf.read('database.json'))
                
                # Insert independent tables first
                for r in data.get('rooms', []):
                    db.session.add(Room(id=r['id'], name=r['name']))
                
                for c in data.get('courses', []):
                    db.session.add(Course(id=c['id'], abbreviation=c['abbreviation'], full_name=c['full_name']))
                
                db.session.commit() # Commit parents

                # Insert Users
                for u in data.get('users', []):
                    new_user = User(
                        id=u['id'], last_name=u['last_name'], first_name=u['first_name'],
                        email=u['email'], idno=u['idno'], cp=u['cp'], course=u['course'],
                        password=u['password'], role=u['role'], status=u['status'], photo=u['photo']
                    )
                    db.session.add(new_user)
                
                db.session.commit() # Commit users

                # Insert Dependent Tables
                for rep in data.get('reports', []):
                    new_rep = Report(
                        id=rep['id'], location=rep['location'], description=rep['description'],
                        status=rep['status'], user_id=rep['user_id'], transaction_no=rep['transaction_no'],
                        created_at=datetime.fromisoformat(rep['created_at'])
                    )
                    db.session.add(new_rep)

                for s in data.get('signup_requests', []):
                    db.session.add(SignupRequest(
                        id=s['id'], last_name=s['last_name'], first_name=s['first_name'],
                        email=s['email'], idno=s['idno'], course=s['course'], photo=s['photo']
                    ))

                db.session.commit()

        return jsonify({'message': 'System recovered successfully!'}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Recovery Error: {e}")
        return jsonify({'error': f"Recovery failed: {str(e)}"}), 500

# ==========================================
#  AI & ANALYTICS EXTENSION 
# ==========================================

def get_nlp_model():
    """
    Creates a 'Knowledge Base' for the computer to understand facility terms.
    """
    # ENHANCED & BALANCED TRAINING DATA
    # Strategy: 
    # 1. We put "action verbs" (explode, broken, leak) in EVERY category they apply to.
    # 2. We keep the line counts equal (3 lines per category) to prevent bias.
    
    training_data = [
        # 1. IT / Computer 
        # Nouns: monitor, cpu, internet. Verbs: explode, smoke, crash.
        ('mouse keyboard monitor cpu screen laptop printer scanner webcam hardware', 'IT/Computer'),
        ('internet wifi network connection slow lagging offline ethernet lan signal', 'IT/Computer'),
        ('software system crash boot error blue screen freeze update virus glitch', 'IT/Computer'),
        ('monitor exploded smoke overheat burning smell sparks hot cpu fire', 'IT/Computer'), 
        
        # 2. Furniture 
        # Nouns: chair, table. Verbs: broken, wobble, collapse.
        ('chair table desk seat bench sofa cabinet drawer cupboard upholstery', 'Furniture'),
        ('leg broken wobble loose hinge door knob lock handle shelf rack', 'Furniture'),
        ('glass whiteboard chalkboard curtain blind fabric tear scratch wood collapse', 'Furniture'),
        ('furniture damage broken seat smashed fabric torn destroyed', 'Furniture'),

        # 3. Electrical 
        # Nouns: light, outlet. Verbs: explode, smoke, flicker.
        ('light bulb switch outlet breaker lamp fluorescent led dim flicker', 'Electrical'),
        ('aircon ac cooling fan electric heat voltage power generator wire', 'Electrical'),
        ('extension cord spark smoke blackout fuse circuit shock battery explode fire', 'Electrical'),
        ('power outage no electricity burnt wire smell sparks dangerous', 'Electrical'),
        
        # 4. Plumbing 
        # Nouns: water, pipe. Verbs: leak, burst, flood.
        ('water faucet pipe leak drip hose sink basin lavatory toilet', 'Plumbing'),
        ('flush drain clog overflow sewage smell pressure pump valve burst', 'Plumbing'),
        ('bathroom restroom cr urinal bidet shower sprinkler puddle moisture flood', 'Plumbing'),
        ('water damage leaking pipe broken faucet overflow flood', 'Plumbing'),
        
        # 5. Infrastructure 
        # Nouns: floor, wall. Verbs: crack, smash, hole.
        ('floor tile ceiling roof wall paint crack hole cement concrete', 'Infrastructure'),
        ('window door frame stair handrail step ramp hallway corridor gate', 'Infrastructure'),
        ('vandalism graffiti dirt mess trash garbage debris pest termite smash', 'Infrastructure'),
        ('broken window cracked floor damaged wall door jam stuck', 'Infrastructure'),

        # 6. Other / General
        # Vague words only. 
        ('unknown weird strange ghost noise mystery investigation', 'Other'),
        ('general maintenance checkup inspection cleaning required', 'Other'),
        ('lost found assistance inquiry question support help', 'Other'),
        ('miscellaneous concern query info request feedback', 'Other')
    ]

    X = [text for text, label in training_data]
    y = [label for text, label in training_data]

    # CONFIGURATION EXPLANATION:
    # 1. stop_words='english': Ignores "the", "is", "a".
    # 2. ngram_range=(1, 2): Reads "Monitor" (1) AND "Monitor Exploded" (2).
    # 3. alpha=0.1: Makes the model "aggressive". It trusts the training data heavily 
    #    instead of smoothing it out. This is better for small datasets.
    model = make_pipeline(
        TfidfVectorizer(stop_words='english', ngram_range=(1, 2)), 
        MultinomialNB(alpha=0.1)
    )
    model.fit(X, y)
    return model

@api_bp.route('/analytics/ai-dashboard', methods=['GET'])
@jwt_required()
def get_ai_dashboard_data():
    try:
        reports = Report.query.all()
        category_counts = {}

        if reports:
            model = get_nlp_model()
            descriptions = [r.description for r in reports]
            predictions = model.predict(descriptions)

            unique, counts = np.unique(predictions, return_counts=True)
            for cat, count in zip(unique, counts):
                category_counts[cat] = int(count)

        rooms_with_reports = db.session.query(Report.location).distinct().all()
        room_data = []
        now = datetime.utcnow()

        for r in rooms_with_reports:
            loc = r.location
            pending_reports = Report.query.filter_by(location=loc, status='Pending').all()
            pending_count = len(pending_reports)
            
            avg_days = 0.0
            if pending_count > 0:
                total_seconds = 0
                for pr in pending_reports:
                    delta = now - pr.created_at
                    total_seconds += delta.total_seconds()
                avg_days = (total_seconds / 86400) / pending_count
            
            # Hybrid Status Logic based on user thresholds
            # Critical: >= 15 pending OR >= 5 avg days
            # Warning: >= 5 pending OR >= 2 avg days
            status = 'Healthy'
            if pending_count >= 15 or avg_days >= 5.0:
                status = 'Critical'
            elif pending_count >= 5 or avg_days >= 2.0:
                status = 'Warning'

            room_data.append({
                'name': loc,
                'features': [pending_count, avg_days],
                'status_label': status
            })

        clusters = []
        if len(room_data) >= 1:
            raw_features = np.array([item['features'] for item in room_data])
            
            # Use Scaler to balance Pending Count vs Avg Days for Clustering
            scaler = MinMaxScaler()
            scaled_features = scaler.fit_transform(raw_features)

            k = 3 if len(room_data) >= 3 else len(room_data)
            kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
            kmeans.fit(scaled_features) 
            
            for i, item in enumerate(room_data):
                clusters.append({
                    'room': item['name'],
                    'x': int(item['features'][0]),
                    'y': round(item['features'][1], 1),
                    'status': item['status_label'] 
                })

        return jsonify({
            'categories': category_counts,
            'clusters': clusters
        }), 200

    except Exception as e:
        print(f"AI Error: {e}")
        return jsonify({'categories': {}, 'clusters': []}), 200

@api_bp.route('/reports/<int:rid>/analyze', methods=['POST'])
@jwt_required()
def analyze_report_ai(rid):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admins only'}), 403

    report = Report.query.get_or_404(rid)
    
    try:
        model = genai.GenerativeModel('gemini-2.5-flash') 
        
        prompt = f"""
        Act as a Senior Facility Maintenance Expert in the Philippines. Analyze this report:
        Location: {report.location}
        Issue Description: {report.description}

        Provide a prescriptive analysis in strict JSON format with these keys:
        1. "diagnosis": A technical assessment of what went wrong.
        2. "steps": An array of specific, actionable repair steps.
        3. "cost": Estimated cost range in Philippine Peso (PHP).
        4. "time": Estimated repair duration (hours/days).
        5. "priority": Recommended priority (Low, Medium, High).
        
        Keep the tone professional, concise, and technical.
        """

        response = model.generate_content(prompt)
        
        # Clean up response to ensure valid JSON parsing
        import json
        text_response = response.text.replace('```json', '').replace('```', '').strip()
        analysis = json.loads(text_response)
        
        return jsonify(analysis), 200

    except Exception as e:
        print(f"AI Analysis Error: {e}")
        # Return a fallback JSON so the UI shows something useful instead of crashing
        return jsonify({
            'diagnosis': 'AI Service Connection Failed',
            'steps': ['Please check API Key configuration.', 'Ensure google-generativeai library is updated.'],
            'cost': 'N/A',
            'time': 'N/A',
            'priority': 'High'
        }), 200