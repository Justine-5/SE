from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

class Intrusion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    vehicle_type = db.Column(db.String(50), nullable=False)
    image_path = db.Column(db.String(255), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(255), nullable=False)
    security_question = db.Column(db.String(255), nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)

def initialize_user(app):
    with app.app_context():
        db.create_all()
        
        if not User.query.first():
            default_password = generate_password_hash("admin123")
            default_question = "What is your favorite color?"
            default_answer = generate_password_hash("blue")

            admin = User(
                password=default_password,
                security_question=default_question,
                security_answer=default_answer
            )
            db.session.add(admin)
            db.session.commit()
