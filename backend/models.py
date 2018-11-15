from backend import db
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin
from flask import current_app
from datetime import datetime


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(127), nullable=False)
    email = db.Column(db.String(63), unique=True, nullable=False)
    password = db.Column(db.String(63), nullable=False)
    gt_id = db.Column(db.Integer, unique=True, nullable=False)
    isAdmin = db.Column(db.Boolean, nullable=False, default=False)
    isMaster = db.Column(db.Boolean, nullable=False, default=False)
    isActive = db.Column(db.Boolean, nullable=False, default=False)

    def get_auth_token(self, expires_seconds=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expires_seconds)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def get_reset_token(self, expires_seconds=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_seconds)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"{self.id}"


class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requesterID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    helperID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    topic = db.Column(db.String(127), nullable=False, default="Not Provided")
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now)
    help_status = db.Column(db.Integer, nullable=False, default=0)
    assigned_status = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"{self.id}"


class CheckInSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now)
    completion = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"{self.id}"