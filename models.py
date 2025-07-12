from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class URL(db.Model):
    __tablename__ = 'urls'
    
    id = db.Column(db.Integer, primary_key=True)
    short_code = db.Column(db.String(50), unique=True, nullable=False, index=True)
    original_url = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.Float, nullable=False)
    expire_at = db.Column(db.Float, nullable=True)
    clicks = db.Column(db.Integer, default=0)
    password = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f'<URL {self.short_code}>'
    
    def to_dict(self):
        return {
            'short_code': self.short_code,
            'original_url': self.original_url,
            'created_at': self.created_at,
            'expire_at': self.expire_at,
            'clicks': self.clicks,
            'password': self.password,
            'user_id': self.user_id
        }

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Analytics(db.Model):
    __tablename__ = 'analytics'
    
    id = db.Column(db.Integer, primary_key=True)
    short_code = db.Column(db.String(50), nullable=False, index=True)
    timestamp = db.Column(db.String(50), nullable=False)
    ip = db.Column(db.String(45), nullable=True)
    region = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Analytics {self.short_code} - {self.timestamp}>'
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'ip': self.ip,
            'region': self.region,
            'country': self.country,
            'user_agent': self.user_agent
        }