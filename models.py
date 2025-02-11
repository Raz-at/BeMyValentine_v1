from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.String(200), primary_key=True)
    sender_id = db.Column(db.String(200))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=False, nullable=False)
    email_to = db.Column(db.String(100))
    email_from = db.Column(db.String(100))
    response = db.Column(db.String(100))
    message = db.Column(db.String)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)