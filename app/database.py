from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from datetime import datetime
import uuid

db = SQLAlchemy()

def dockerdb():
    return "mysql+pymysql://fasttdatabase:fasttdb@FASTTDB:3306/fasttdb"

engine = create_engine(dockerdb())

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True) 
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    address = db.Column(db.String(255))

    targets = db.relationship("Target", back_populates="user")

class Target(db.Model):
    __tablename__ = 'targets'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255))
    domain = db.Column(db.String(255))
    status = db.Column(db.String(50))
    note = db.Column(db.String(255))
    added_on = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_progress = db.Column(db.Integer, default=0)
    scan_error = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', back_populates='targets')

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)    
    vulnerability_type = db.Column(db.String(50), nullable=True) 
    details = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    cvss_score = db.Column(db.String(50), nullable=False)
    endpoint = db.Column(db.String(255), nullable=False)
    scan_name = db.Column(db.String(255), nullable=False)
    full_description = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    cwe_code = db.Column(db.String(255), nullable=True) 
    cve_code = db.Column(db.String(50), nullable=True)
    cvss_metrics = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Vulnerability {self.name}>"

def get_vulnerabilities(scan_name):
    vulnerabilities = Vulnerability.query.filter_by(scan_name=scan_name).all()
    return [
        {
            'id': vuln.id,
            'name': vuln.name,
            'details': vuln.details,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'endpoint': vuln.endpoint,
            'created_at': vuln.created_at.isoformat() if vuln.created_at else None
        } 
        for vuln in vulnerabilities
    ]

def check_user():
    return User.query.count() > 0
