import random
from app import app, db
from backend.models import Room, Report, User
from datetime import datetime, timedelta

# Configuration
NUM_ROOMS = 10
TOTAL_REPORTS = 60

def seed_database():
    with app.app_context():
        print("🌱 Seeding Database...")

        # 1. Create/Ensure Admin exists (so reports have a user)
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            print("❌ No admin user found. Please run the app once to create the default admin.")
            return
        
        # 2. Create Rooms (Mixed Types)
        room_names = [
            "Computer Lab 1", "Computer Lab 2", 
            "Lecture Hall A", "Lecture Hall B", 
            "Science Lab", "Faculty Room", 
            "Library", "Clinic", "Gymnasium", "Room 303"
        ]
        
        db_rooms = []
        for name in room_names:
            r = Room.query.filter_by(name=name).first()
            if not r:
                r = Room(name=name)
                db.session.add(r)
            db_rooms.append(r)
        db.session.commit()
        
        # Reload rooms to get IDs
        rooms = Room.query.all()

        # 3. Generate Reports with "Storytelling" Logic
        descriptions = [
            "Monitor not turning on", "Chair leg broken", "Aircon leaking water", 
            "No internet connection", "Light bulb flickering", "Table scratched",
            "Door knob jammed", "Window crack", "Projector overheating", "Mouse missing"
        ]

        for _ in range(TOTAL_REPORTS):
            # Pick a random room
            target_room = random.choice(rooms)
            
            # LOGIC: Force "Computer Lab 1" to be Critical (High Pending)
            if target_room.name == "Computer Lab 1":
                status = "Pending" # Always broken
            
            # LOGIC: Force "Lecture Hall A" to be Warning (Busy but fixed)
            elif target_room.name == "Lecture Hall A":
                status = random.choice(["Repaired", "Repaired", "Pending"]) # Mostly fixed
                
            # LOGIC: Others are random mix
            else:
                status = random.choice(["Pending", "In Progress", "Repaired"])

            # Create Report
            report = Report(
                location=target_room.name,
                description=random.choice(descriptions),
                status=status,
                user_id=admin.id,
                created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30)),
                transaction_no=f"TR-AUTO-{random.randint(1000,9999)}"
            )
            db.session.add(report)

        db.session.commit()
        print(f"✅ Successfully added {TOTAL_REPORTS} reports across {len(rooms)} rooms.")
        print("🚀 Restart your server and check the Admin Dashboard!")

if __name__ == '__main__':
    seed_database()