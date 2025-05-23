from datetime import datetime
from io import BytesIO
import io
import sqlite3
from flask import Flask, jsonify, render_template, Response, request, redirect, send_file, session, url_for, send_from_directory
from detection import generate_frames
from database import db, Intrusion, initialize_user, User
from collections import defaultdict
from reportlab.lib.pagesizes import A4, letter
from reportlab.pdfgen import canvas
from werkzeug.security import check_password_hash, generate_password_hash
import csv
import cv2
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///intrusions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
initialize_user(app)
DB_PATH = 'instance/intrusions.db'

camera = None
current_source = 0

app.secret_key = 'supersecretkey'


def list_available_cameras(max_index=5):
    available = []
    for index in range(max_index):
        cap = cv2.VideoCapture(index)
        if cap.read()[0]:
            available.append(index)
        cap.release()
    return available


def set_camera(source):
    global camera
    if camera:
        camera.release()
    camera = cv2.VideoCapture(source)

available_cameras = list_available_cameras()
# set_camera(current_source)

@app.before_request
def require_login():
    allowed_routes = ['index', 'login', 'get_security_question', 'verify_answer', 'static']
    if request.endpoint not in allowed_routes and not session.get('logged_in'):
        return redirect(url_for('index'))
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    
    if not session.get("logged_in"):
        return redirect(url_for("index"))
    
    car_count = Intrusion.query.filter(Intrusion.vehicle_type.in_(["Car", "Truck"])).count()
    motorcycle_count = Intrusion.query.filter_by(vehicle_type="Motorcycle").count()
    bus_count = Intrusion.query.filter(Intrusion.vehicle_type.in_(["Bus", "Jeep"])).count()

    return render_template('app.html',
                           current_source=current_source,
                           available_cameras=available_cameras,
                           car_count=car_count,
                           motorcycle_count=motorcycle_count,
                           bus_count=bus_count)



@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(current_source), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/change_camera', methods=['POST'])
def change_camera():
    global current_source
    new_source = int(request.form.get("camera_index"))
    current_source = new_source
    set_camera(current_source)
    return redirect(url_for('dashboard'))

@app.route('/settings')
def settings():
    if not session.get("logged_in"):
        return redirect(url_for("index"))
    
    return render_template('settings.html')


@app.route('/intrusions/<path:subpath>')
def serve_intrusion_image(subpath):
    
    return send_from_directory('intrusion_screenshots', subpath)


def get_intrusions_by_vehicle_types(vehicle_types, title, pageTitle):
    if not session.get("logged_in"):
        return redirect(url_for("index"))

    # Get selected date from query string or default to today
    selected_date_str = request.args.get("filter_date")
    if selected_date_str:
        try:
            selected_date = datetime.strptime(selected_date_str, "%Y-%m-%d").date()
        except ValueError:
            selected_date = datetime.today().date()
    else:
        selected_date = datetime.today().date()
        selected_date_str = selected_date.strftime("%Y-%m-%d")

    # Filter intrusions for that specific date
    intrusions = Intrusion.query.filter(
        Intrusion.vehicle_type.in_(vehicle_types),
        db.func.date(Intrusion.timestamp) == selected_date
    ).order_by(Intrusion.timestamp.desc()).all()

    grouped_images = defaultdict(list)
    for intrusion in intrusions:
        abs_path = os.path.join(os.getcwd(), intrusion.image_path)
        if os.path.exists(abs_path):
            time_str = intrusion.timestamp.strftime("%I:%M %p")  # e.g., 02:30 PM
            url_path = intrusion.image_path.replace("\\", "/").replace("intrusion_screenshots/", "")
            grouped_images[time_str].append(url_path)

    return render_template(
        "intrusions.html",
        title=title,
        grouped_images=grouped_images,
        selected_date=selected_date_str,
        active_page=pageTitle,
    )




@app.route('/cars')
def show_cars():
    return get_intrusions_by_vehicle_types(["Car", "Truck"], "Private Vehicles (Cars and Trucks)", "cars")

@app.route('/motorcycles')
def show_motorcycles():
    return get_intrusions_by_vehicle_types(["Motorcycle"], "Motorcycles", "motorcycles")

@app.route('/public')
def show_public_vehicles():
    return get_intrusions_by_vehicle_types(["Bus", "Jeep"], "Public Utility Vehicles", "public")

@app.route('/api/intrusion_counts')
def intrusion_counts():
    car_count = Intrusion.query.filter(Intrusion.vehicle_type.in_(["Car", "Truck"])).count()
    motorcycle_count = Intrusion.query.filter_by(vehicle_type="Motorcycle").count()
    bus_count = Intrusion.query.filter(Intrusion.vehicle_type.in_(["Bus", "Jeep"])).count()

    return jsonify({
        'car': car_count,
        'motorcycle': motorcycle_count,
        'bus': bus_count
    })


@app.route('/generate_report', methods=['POST'])
def generate_report():
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')

    if not start_date or not end_date:
        return "Missing date fields", 400
    
    if start_date > end_date:
        return "Start date cannot be after end date.", 400


    # Format the input dates
    start = datetime.strptime(start_date, '%Y-%m-%d')
    end = datetime.strptime(end_date, '%Y-%m-%d')

    # Query the database
    conn = sqlite3.connect('instance/intrusions.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT vehicle_type, COUNT(*) FROM intrusion
        WHERE DATE(timestamp) BETWEEN ? AND ?
        GROUP BY vehicle_type
    """, (start_date, end_date))
    summary_data = cursor.fetchall()

    cursor.execute("""
        SELECT timestamp, vehicle_type FROM intrusion
        WHERE DATE(timestamp) BETWEEN ? AND ?
        ORDER BY timestamp
    """, (start_date, end_date))
    detailed_data = cursor.fetchall()
    conn.close()

    # Create PDF
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, height - 50, "Intrusion Report")
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, height - 70, f"Date Range: {start_date} to {end_date}")

    y = height - 110
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Summary")
    y -= 20

    pdf.setFont("Helvetica", 12)
    if summary_data:
        for vtype, count in summary_data:
            pdf.drawString(60, y, f"{vtype}: {count} intrusion(s)")
            y -= 20
    else:
        pdf.drawString(60, y, "No intrusion data available.")
        y -= 20

    y -= 20
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Detailed Logs")
    y -= 20

    pdf.setFont("Helvetica", 10)
    if detailed_data:
        for ts, vtype in detailed_data:
            entry = f"{ts} — {vtype}"
            pdf.drawString(60, y, entry[:90])
            y -= 15
            if y < 50:
                pdf.showPage()
                y = height - 50
    else:
        pdf.drawString(60, y, "No detailed logs available for this range.")

    pdf.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name='intrusion_report.pdf', mimetype='application/pdf')


def get_user():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, password, security_question, security_answer FROM user WHERE id = 1")
    user = cur.fetchone()
    conn.close()
    return user

@app.route("/change_password", methods=["POST"])
def change_password():
    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password") 

    user = get_user()
    if not check_password_hash(user[1], old_password):
        return jsonify({"success": False, "message": "Incorrect old password"}), 400

    new_hash = generate_password_hash(new_password)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE user SET password = ? WHERE id = 1", (new_hash,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Password changed successfully"})

@app.route("/change_security_question", methods=["POST"])
def change_security_question():
    data = request.json
    new_question = data.get("new_question")
    new_answer = data.get("new_answer")
    new_answer_hash = generate_password_hash(new_answer)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE user SET security_question = ?, security_answer = ? WHERE id = 1",
                 (new_question, new_answer_hash))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Security question updated successfully"})

UPLOAD_FOLDER = 'Backups'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/backup", methods=["GET"])
def backup_intrusions():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM intrusion")
    rows = cursor.fetchall()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"intrusion_backup_{timestamp}.csv"
    filepath = os.path.join("Backups", filename)

    with open(filepath, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["id", "timestamp", "vehicle_type", "image_path"])
        writer.writerows(rows)

    conn.close()
    return send_file(filepath, as_attachment=True)


@app.route('/restore', methods=['POST'])
def restore_intrusions():
    if 'file' not in request.files:
        return 'No file part', 400

    file = request.files['file']

    if file.filename == '':
        return 'No selected file', 400

    if not file.filename.endswith('.csv'):
        return 'Invalid file format. Please upload a CSV file.', 400

    try:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)

        restored = 0
        for row in reader:
            img = row['image_path']
            existing = Intrusion.query.filter_by(image_path=img).first()
            if existing:
                continue  # Skip if image_path already exists

            timestamp = datetime.strptime(row['timestamp'], '%Y-%m-%d %H:%M:%S.%f')

            intrusion = Intrusion(
                timestamp=timestamp,
                vehicle_type=row['vehicle_type'],
                image_path=img
            )
            db.session.add(intrusion)
            restored += 1

        db.session.commit()
        return f"Successfully restored {restored} new intrusion(s).", 200

    except Exception as e:
        db.session.rollback()
        return f"An error occurred during restore: {str(e)}", 500


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.first()
    if not user:
        return jsonify({"success": False, "message": "No user found."})

    if check_password_hash(user.password, data.get("password")):
        session["logged_in"] = True
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": "Incorrect password."})
    
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/get_security_question")
def get_security_question():
    user = User.query.first()
    if user:
        return jsonify({"question": user.security_question})
    return jsonify({"question": "Unavailable"})

@app.route("/verify_answer", methods=["POST"])
def verify_answer():
    data = request.json
    user = User.query.first()
    if not user:
        return jsonify({"success": False, "message": "No user found."})

    if check_password_hash(user.security_answer, data.get("answer")):
        session["logged_in"] = True
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": "Incorrect answer."})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)
