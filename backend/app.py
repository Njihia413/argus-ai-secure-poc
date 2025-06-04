import json
import hashlib
import math
import secrets
import requests
from datetime import datetime, timedelta, timezone
import uuid

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
import os

from flask_sqlalchemy.session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import base64

# Import WebAuthn related libraries
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, UserVerificationRequirement, \
    AuthenticatorAttachment, CollectedClientData, AttestationObject, PublicKeyCredentialDescriptor, \
    PublicKeyCredentialType, AuthenticatorData
from fido2.utils import websafe_decode, websafe_encode
from fido2 import cbor

from sqlalchemy import func, case, MetaData

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/argus_ai_secure_poc'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Use 'Strict' in production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SESSION_TYPE'] = 'redis'  # Or 'filesystem', 'sqlalchemy', etc.
Session(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# User model renamed to Users and with additional fields including role
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    national_id = db.Column(db.Integer, unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    middle_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='user')
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

    # User timezone for risk-based authentication
    timezone = db.Column(db.String(50), default='UTC')
    last_login_time = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    successful_login_attempts = db.Column(db.Integer, default=0)  # Track successful logins
    failed_login_attempts = db.Column(db.Integer, default=0)  # Track failed logins
    total_login_attempts = db.Column(db.Integer, default=0,
        info={'computed': 'successful_login_attempts + failed_login_attempts'})  # Total of both

    # Security key related fields
    has_security_key = db.Column(db.Boolean, nullable=False, default=False)
    total_login_attempts = db.Column(db.Integer, default=0)  # Track total successful logins
    account_locked = db.Column(db.Boolean, nullable=False, default=False)  # Track if account is locked
    locked_time = db.Column(db.DateTime(timezone=True), nullable=True)  # When the account was locked
    unlocked_by = db.Column(db.String(100), nullable=True)  # Admin username who unlocked
    unlocked_time = db.Column(db.DateTime(timezone=True), nullable=True)  # When account was unlocked
    security_key_status = db.Column(db.String(20), nullable=True)

    # WebAuthn related fields
    credential_id = db.Column(db.String(250), unique=True, nullable=True)
    public_key = db.Column(db.Text, nullable=True)
    sign_count = db.Column(db.Integer, default=0)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Reset failed login attempts
    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        db.session.commit()

    def increment_successful_attempts(self):
        """Increment successful login attempts and update total"""
        self.successful_login_attempts += 1
        self.total_login_attempts = self.successful_login_attempts + self.failed_login_attempts
        db.session.commit()

    def unlock_account(self, admin_username):
        """Unlock a locked account and record who unlocked it"""
        self.account_locked = False
        self.failed_login_attempts = 0
        self.unlocked_by = admin_username
        self.unlocked_time = datetime.now(timezone.utc)
        db.session.commit()

    # Increment failed login attempts
    def increment_failed_attempts(self):
        """Increment failed login attempts and update total"""
        self.failed_login_attempts += 1
        self.total_login_attempts = self.successful_login_attempts + self.failed_login_attempts
        
        if self.failed_login_attempts >= 5: # Lock on the 5th failed attempt
            self.account_locked = True
            self.locked_time = datetime.now(timezone.utc)
            self.unlocked_by = None
            self.unlocked_time = None
        db.session.commit()

    # Check if account is locked
    def is_account_locked(self):
        """Check if account is locked and return boolean"""
        return self.account_locked

    def get_lock_details(self):
        """Get detailed information about account lock status"""
        if not self.account_locked:
            return {
                "locked": False
            }

        details = {
            "locked": True,
            "lockedTime": self.locked_time.isoformat() if self.locked_time else None,
            "failedAttempts": self.failed_login_attempts
        }

        if self.unlocked_by:
            # unlocked_by now stores the username directly
            details.update({
                "unlockedBy": {
                    "username": self.unlocked_by
                },
                "unlockedTime": self.unlocked_time.isoformat() if self.unlocked_time else None
            })

        return details

    def update_security_key_status(self):
        """Update the security key status based on the user's security keys"""
        # Check for active keys
        active_keys = SecurityKey.query.filter_by(
            user_id=self.id,
            is_active=True
        ).count()

        # Check for inactive keys
        inactive_keys = SecurityKey.query.filter_by(
            user_id=self.id,
            is_active=False
        ).count()

        # Update status based on findings
        if active_keys > 0:
            self.security_key_status = 'active'
            self.has_security_key = True
        elif inactive_keys > 0:
            self.security_key_status = 'inactive'
            self.has_security_key = True
        else:
            self.security_key_status = None
            self.has_security_key = False

        return self

# Update WebAuthnChallenge model to reference Users instead of User
class WebAuthnChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    challenge = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expired = db.Column(db.Boolean, default=False)
    is_second_factor = db.Column(db.Boolean, default=False)


class AuthenticationSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    password_verified = db.Column(db.Boolean, default=False)
    security_key_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc) + timedelta(minutes=15))
    session_token = db.Column(db.String(100), unique=True, default=lambda: str(uuid.uuid4()))
    client_binding = db.Column(db.String(255))
    binding_nonce = db.Column(db.String(100))
    risk_score = db.Column(db.Integer, default=0)
    requires_additional_verification = db.Column(db.Boolean, default=False)
    last_used = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class AuthenticationAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.String(255))
    device_type = db.Column(db.String(50))  # New column for device type
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    success = db.Column(db.Boolean, default=False)
    auth_type = db.Column(db.String(50))
    risk_score = db.Column(db.Integer, default=0)
    location = db.Column(db.String(255))
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('Users', backref=db.backref('auth_attempts', lazy=True))


# Audit logs for security keys
class SecurityKeyAudit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    security_key_id = db.Column(db.Integer, db.ForeignKey('security_key.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # register, deactivate, activate, reassign
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    performed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    previous_state = db.Column(db.JSON)
    new_state = db.Column(db.JSON)

    # Relationships
    security_key = db.relationship('SecurityKey', backref=db.backref('audit_logs', lazy=True))
    user = db.relationship('Users', foreign_keys=[user_id], backref=db.backref('security_key_audit_logs', lazy=True))
    actor = db.relationship('Users', foreign_keys=[performed_by])

# SecurityKey model
class SecurityKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    credential_id = db.Column(db.String(250), unique=True, nullable=True)  
    public_key = db.Column(db.Text, nullable=True)  
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    last_used = db.Column(db.DateTime(timezone=True), nullable=True)
    deactivated_at = db.Column(db.DateTime(timezone=True), nullable=True)
    deactivation_reason = db.Column(db.String(100), nullable=True)

    # Security key details
    model = db.Column(db.String(100), nullable=True)
    type = db.Column(db.String(100), nullable=True)
    serial_number = db.Column(db.String(100), nullable=True)
    pin = db.Column(db.String(500), nullable=True)
    product_id = db.Column(db.String(100), nullable=True)
    vendor_id = db.Column(db.String(100), nullable=True)
    
    # Relationships
    user = db.relationship('Users', backref=db.backref('security_keys', lazy=True))


# Configure WebAuthn
rp = PublicKeyCredentialRpEntity(name="Athens AI", id="localhost")
server = Fido2Server(rp)


# Helper Functions for Security Enhancements

# Function to detect device type from user agent
def detect_device_type(user_agent):
    """Detect device type from user agent string"""
    user_agent = user_agent.lower()

    # Mobile devices
    if any(device in user_agent for device in ['iphone', 'ipad', 'android', 'mobile', 'phone', 'tablet']):
        if 'tablet' in user_agent or 'ipad' in user_agent:
            return 'Tablet'
        return 'Mobile'

    # Desktop OS detection
    if 'windows' in user_agent:
        return 'Windows PC'
    if 'macintosh' in user_agent or 'mac os' in user_agent:
        return 'Mac'
    if 'linux' in user_agent:
        return 'Linux'

    # Default to Desktop if no specific device detected
    return 'Desktop'


def get_public_ip():
    """Get the actual public IP address"""
    try:
        # Use ipify API to get public IP
        response = requests.get('https://api.ipify.org?format=json')
        if response.status_code == 200:
            return response.json().get('ip')
    except Exception as e:
        print(f"Error getting public IP: {str(e)}")
    return None


def get_location_from_ip(ip_address):
    """Get detailed location information from IP address"""
    try:
        # If it's localhost, try to get the public IP
        if ip_address in ('127.0.0.1', 'localhost', '::1'):
            public_ip = get_public_ip()
            if public_ip:
                ip_address = public_ip

        # Try ip-api.com first for detailed info
        response = requests.get(
            f'http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,district')
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                location_parts = []

                # Add district/neighborhood/area if available
                if data.get('district'):
                    location_parts.append(data['district'])

                # Add city
                if data.get('city'):
                    location_parts.append(data['city'])

                # Add region/state
                if data.get('regionName'):
                    location_parts.append(data['regionName'])

                # Add country
                if data.get('country'):
                    location_parts.append(data['country'])

                if location_parts:
                    return ", ".join(location_parts)

        # Fallback to ipapi.co with more detailed location info
        response = requests.get(f'https://ipapi.co/{ip_address}/json/')
        if response.status_code == 200:
            data = response.json()
            location_parts = []

            # Try to get neighborhood or area name
            if data.get('neighbourhood'):
                location_parts.append(data['neighbourhood'])
            elif data.get('postal'):  # Use postal area as fallback for neighborhood
                location_parts.append(data['postal'])

            # Add city
            if data.get('city'):
                location_parts.append(data['city'])

            # Add region
            if data.get('region'):
                location_parts.append(data['region'])

            # Add country
            if data.get('country_name'):
                location_parts.append(data['country_name'])

            if location_parts:
                return ", ".join(location_parts)

        return "Unknown Location"
    except Exception as e:
        print(f"Error getting location from IP: {str(e)}")
        return "Unknown Location"


# Function to generate binding data
def generate_binding_data(request):
    # Collect data that identifies this specific connection
    user_agent = request.headers.get('User-Agent', '')
    remote_addr = request.remote_addr
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    accept_language = request.headers.get('Accept-Language', '')

    # Use secure random data as additional entropy
    nonce = secrets.token_hex(16)

    # Combine and hash the data
    binding_string = f"{user_agent}|{remote_addr}|{forwarded_for}|{accept_language}|{nonce}"
    binding_hash = hashlib.sha256(binding_string.encode()).hexdigest()

    return binding_hash, nonce


# Function to validate token binding
def validate_token_binding(session_token, binding_nonce, request):
    print(f"Validating token: {session_token[:8]}... nonce: {binding_nonce[:8]}...")

    # Check if this is direct security key authentication
    data = request.get_json() or {}
    direct_security_key_auth = data.get('directSecurityKeyAuth', False)

    if direct_security_key_auth:
        print("Direct security key authentication detected - bypassing token validation")
        # For direct security key auth, skip token validation completely
        return True

    # Find the session as normal
    auth_session = AuthenticationSession.query.filter_by(session_token=session_token).first()
    if not auth_session:
        print("No session found with this token")
        # Show available tokens for debugging
        recent_sessions = AuthenticationSession.query.order_by(
            AuthenticationSession.created_at.desc()
        ).limit(5).all()
        print(f"Recent sessions: {len(recent_sessions)}")
        for s in recent_sessions:
            print(f"- Token: {s.session_token[:8]}... for user_id: {s.user_id}")
        return False

    print(f"Found session for user_id: {auth_session.user_id}")

    # Check if session is expired - with proper timezone handling
    now = datetime.now(timezone.utc)

    # Make sure expires_at has timezone info
    expires_at = auth_session.expires_at
    if expires_at and not expires_at.tzinfo:
        # If expires_at doesn't have timezone info, assume it's UTC
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if now > expires_at:
        print(f"Session expired at {expires_at}")
        return False

    # For development purposes, use simpler binding validation
    user_agent = request.headers.get('User-Agent', '')
    simplified_binding = hashlib.sha256(f"{user_agent}|{binding_nonce}".encode()).hexdigest()

    # Log binding information for debugging
    print(f"Original stored binding: {auth_session.client_binding[:15]}...")
    print(f"Simplified binding: {simplified_binding[:15]}...")

    # Use the simplified binding comparison
    result = secrets.compare_digest(auth_session.client_binding, simplified_binding)
    if not result:
        print(f"Binding validation failed (but continuing for development purposes)")
        # For development, we're returning True even on binding mismatch
        return True

    return True


# Method to update last_used
def update_last_used(self):
    """Update the last_used timestamp to current time with timezone"""
    self.last_used = datetime.now(timezone.utc)
    db.session.commit()


# Function to assess risk for risk-based authentication
def assess_risk(user_id, request):
    # Get user's authentication history
    user = Users.query.get(user_id)
    if not user:
        return 100  # High risk if user not found

    # Start with a base risk score - start at 30 for first-time logins
    risk_score = 30
    print(f"Risk: Starting with base score of 30 for all logins")

    # Get current time
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # 1. Check IP address history
    current_ip = request.remote_addr
    ip_history = AuthenticationAttempt.query.filter(
        AuthenticationAttempt.user_id == user_id,
        AuthenticationAttempt.ip_address == current_ip,
        AuthenticationAttempt.success == True,
        AuthenticationAttempt.timestamp >= today_start  # Only consider today's logins
    ).count()

    if ip_history == 0:
        # New IP address for today
        risk_score += 30
        print(f"Risk: +30 for new IP address {current_ip} today")

    # 2. Check for failed attempts today
    recent_failed_attempts = AuthenticationAttempt.query.filter(
        AuthenticationAttempt.user_id == user_id,
        AuthenticationAttempt.success == False,
        AuthenticationAttempt.timestamp >= today_start  # Only consider today's failed attempts
    ).count()

    # Each failed attempt adds 15 to risk score (no cap)
    failed_risk = recent_failed_attempts * 15
    risk_score += failed_risk
    if failed_risk > 0:
        print(f"Risk: +{failed_risk} for {recent_failed_attempts} failed attempts today")

    # 3. Check for unusual timing
    user_timezone = user.timezone or 'UTC'  # Assuming you store user's timezone
    current_hour = now.hour
    if current_hour < 6 or current_hour > 22:  # Outside normal hours
        risk_score += 10
        print(f"Risk: +10 for unusual hour ({current_hour})")

    # 4. Check device history (for today only)
    current_user_agent = request.headers.get('User-Agent', '')
    device_history = AuthenticationAttempt.query.filter(
        AuthenticationAttempt.user_id == user_id,
        AuthenticationAttempt.user_agent == current_user_agent,
        AuthenticationAttempt.success == True,
        AuthenticationAttempt.timestamp >= today_start  # Only consider today's successful logins
    ).count()

    if device_history == 0:
        # New device today
        risk_score += 20
        print(f"Risk: +20 for new device today")

    # 5. Check location (for today only)
    # Get last successful login from today
    last_login_today = AuthenticationAttempt.query.filter(
        AuthenticationAttempt.user_id == user_id,
        AuthenticationAttempt.success == True,
        AuthenticationAttempt.timestamp >= today_start
    ).order_by(AuthenticationAttempt.timestamp.desc()).first()

    if last_login_today and last_login_today.ip_address != current_ip:
        risk_score += 15
        print(f"Risk: +15 for location change today")

        # Check for rapid authentication from different locations (within the last hour)
        time_since_last_login = now - last_login_today.timestamp
        if time_since_last_login < timedelta(hours=1):
            risk_score += 25
            print(f"Risk: +25 for rapid location change (within the last hour)")

    final_score = min(risk_score, 100)  # Cap at 100
    print(f"Final risk score: {final_score}")
    return final_score


# Add this new endpoint to your app.py file

@app.route('/api/risk-score-trend', methods=['GET'])
def get_risk_score_trend():
    try:
        # Get auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')

        # Verify auth session
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid auth token'}), 401

        now = datetime.now(timezone.utc)

        try:
            # Group authentication attempts by day and calculate average risk score
            # Removed the current_month_start filter to get all-time data
            results = db.session.query(
                func.date(AuthenticationAttempt.timestamp).label('date'),
                func.avg(
                    case(
                        (AuthenticationAttempt.risk_score.isnot(None), AuthenticationAttempt.risk_score),
                        else_=0
                    )
                ).label('avg_risk_score'),
                func.count(AuthenticationAttempt.id).label('attempt_count')
            ).group_by(
                func.date(AuthenticationAttempt.timestamp)
            ).order_by(
                func.date(AuthenticationAttempt.timestamp)
            ).all()

            # Debug the query results
            print(f"Found {len(results)} days with risk data")
            for row in results:
                print(f"Date: {row.date}, Avg Score: {row.avg_risk_score}, Count: {row.attempt_count}")

            # Format data for the chart with better type handling
            risk_trend = []
            for date, avg_score, count in results:
                formatted_date = date.strftime('%b %d')
                try:
                    # Explicitly convert to float and round to 1 decimal place
                    avg_risk_score = round(float(avg_score), 1) if avg_score is not None else 0
                except (ValueError, TypeError):
                    print(f"Error converting risk score for {date}: {avg_score}")
                    avg_risk_score = 0

                risk_trend.append({
                    'name': formatted_date,
                    'riskScore': avg_risk_score,
                    'attemptCount': count
                })

            # If no results, provide empty data with current date
            if not risk_trend:
                today = now.strftime('%b %d')
                risk_trend.append({
                    'name': today,
                    'riskScore': 0,
                    'attemptCount': 0
                })

            return jsonify({'riskTrend': risk_trend})

        except Exception as db_error:
            print(f"Database error in risk trend calculation: {str(db_error)}")
            import traceback
            print(traceback.format_exc())

            # Return graceful fallback with current date
            today = now.strftime('%b %d')
            return jsonify({'riskTrend': [{
                'name': today,
                'riskScore': 0,
                'attemptCount': 0
            }]})

    except Exception as e:
        print(f"Error fetching risk score trend: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': 'Failed to fetch risk score trend'}), 500



# Simple route to test if the server is running
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'message': 'Athens AI Auth Server Running'})


# Updated route for user registration with first and last name and role (only accessible to admins)
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    # Check if all required fields are provided
    if not data or not data.get('username') or not data.get('password') or \
            not data.get('firstName') or not data.get('lastName') or \
            not data.get('nationalId') or not data.get('email'):
        return jsonify(
            {'error': 'Missing required fields (firstName, lastName, username, password, nationalId, or email)'}), 400

    # Validate national ID
    try:
        national_id = int(data.get('nationalId'))
        if len(str(national_id)) != 8:
            return jsonify({'error': 'National ID must be exactly 8 digits'}), 400
    except ValueError:
        return jsonify({'error': 'National ID must be a number'}), 400

    # Get the admin's auth token for authorization
    admin_token = request.headers.get('Authorization')
    if not admin_token:
        return jsonify({'error': 'Admin authorization required'}), 401

    # Verify the admin token
    admin_token = admin_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=admin_token).first()

    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401

    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    if Users.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409

    # Set role (default to 'user' unless specifically set to another valid role)
    valid_roles = ['user', 'admin', 'security_officer', 'auditor', 'manager', 'developer', 'analyst', 'guest']
    role = data.get('role', 'user')
    if role not in valid_roles:
        role = 'user'  # Ensure only valid roles

    user = Users(
        first_name=data['firstName'],
        middle_name=data.get('middlename'),
        last_name=data['lastName'],
        username=data['username'],
        email=data['email'],
        national_id=national_id,
        role=role
    )
    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    return jsonify({
        'message': 'User registered successfully',
        'user': {
            'id': user.id,
            'username': user.username,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'role': user.role
        }
    }), 201


def get_active_users():
    return Users.query.filter_by(is_deleted=False).all()


# Add a new route to get all users (admin only)
@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        # Find the admin session
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({'error': 'Admin authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

        if not auth_session:
            return jsonify({'error': 'Invalid admin token'}), 401

        # Get the admin user
        admin_user = Users.query.get(auth_session.user_id)
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        # Use the filtered query to exclude soft-deleted users
        users = Users.query.filter_by(is_deleted=False).all()

        # Now update login attempts with the current active state
        user_list = []

        for user in users:
            # Only update attempts for non-deleted users
            failed_attempts = AuthenticationAttempt.query.filter(
                AuthenticationAttempt.user_id == user.id,
                AuthenticationAttempt.success == False,
                AuthenticationAttempt.is_deleted == False,
                AuthenticationAttempt.auth_type == 'password'
            ).count()

            successful_attempts = AuthenticationAttempt.query.filter(
                AuthenticationAttempt.user_id == user.id,
                AuthenticationAttempt.success == True,
                AuthenticationAttempt.is_deleted == False,
                AuthenticationAttempt.auth_type == 'password'
            ).count()

            # Count active and inactive security keys for this user
            active_keys = SecurityKey.query.filter_by(
                user_id=user.id,
                is_active=True
            ).count()

            inactive_keys = SecurityKey.query.filter_by(
                user_id=user.id,
                is_active=False
            ).count()

            # Determine security key status
            security_key_status = None
            if active_keys > 0:
                security_key_status = "active"
            elif inactive_keys > 0:
                security_key_status = "inactive"
            else:
                security_key_status = None

            # Total key count (both active and inactive)
            total_key_count = active_keys + inactive_keys

            # Log user security key info for debugging
            print(f"User {user.username}: active_keys={active_keys}, inactive_keys={inactive_keys}, "
                  f"status={security_key_status}, total={total_key_count}")

            user_list.append({
                'id': user.id,
                'nationalId': user.national_id,
                'username': user.username,
                'firstName': user.first_name,
                'middlename': user.middle_name,
                'lastName': user.last_name,
                'email': user.email,
                'role': user.role,
                'hasSecurityKey': total_key_count > 0,  # True if user has any keys (active or inactive)
                'securityKeyCount': total_key_count,  # Total number of keys
                'securityKeyStatus': security_key_status,  # 'active', 'inactive', or null
                'lastLogin': user.last_login_time.isoformat() if user.last_login_time else None,
                'loginAttempts': successful_attempts, # successful_login_attempts in db
                'failedAttempts': failed_attempts,
                'deletedAt': user.deleted_at.isoformat() if user.deleted_at else None,
                # Added fields:
                'account_locked': user.account_locked,
                'timezone': user.timezone,
                'last_login_ip': user.last_login_ip,
                'total_login_attempts': user.total_login_attempts, # This uses the DB column
                'locked_time': user.locked_time.isoformat() if user.locked_time else None,
                'unlocked_by': user.unlocked_by,
                'unlocked_time': user.unlocked_time.isoformat() if user.unlocked_time else None
            })

        return jsonify({'users': user_list})

    except Exception as e:
        print(f"Error in get_users: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': 'An error occurred while retrieving users'}), 500

# User details endpoint
@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # Existing authentication checks...
    auth_token = request.headers.get('Authorization')
    auth_token = auth_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    # Find user, ensuring they are not soft-deleted
    user = Users.query.filter_by(id=user_id, is_deleted=False).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get login attempts
    failed_attempts = AuthenticationAttempt.query.filter(
        AuthenticationAttempt.user_id == user.id,
        AuthenticationAttempt.success == False,
        AuthenticationAttempt.is_deleted == False,
        AuthenticationAttempt.auth_type == 'password'
    ).count()

    successful_attempts = AuthenticationAttempt.query.filter(
        AuthenticationAttempt.user_id == user.id,
        AuthenticationAttempt.success == True,
        AuthenticationAttempt.is_deleted == False,
        AuthenticationAttempt.auth_type == 'password'
    ).count()

    # Count active security keys for this user
    security_key_count = SecurityKey.query.filter_by(
        user_id=user.id,
        is_active=True
    ).count()

    return jsonify({
        'user': {
            'id': user.id,
            'nationalId': user.national_id,
            'username': user.username,
            'firstName': user.first_name,
            'middlename': user.middle_name,
            'lastName': user.last_name,
            'email': user.email,
            'role': user.role,
            'securityKeyStatus': user.security_key_status, # Added
            'account_locked': user.account_locked, # Added
            'locked_time': user.locked_time.isoformat() if user.locked_time else None, # Added
            'timezone': user.timezone, # Added
            'last_login_ip': user.last_login_ip, # Added
            'total_login_attempts': user.total_login_attempts, # Added
            'unlocked_by': user.unlocked_by, # Added
            'unlocked_time': user.unlocked_time.isoformat() if user.unlocked_time else None, # Added
            'hasSecurityKey': security_key_count > 0,
            'securityKeyCount': security_key_count,
            'lastLogin': user.last_login_time.isoformat() if user.last_login_time else None,
            'loginAttempts': successful_attempts,
            'failedAttempts': failed_attempts,
            'deletedAt': user.deleted_at.isoformat() if user.deleted_at else None
        }
    })


# Get security keys for a user
@app.route('/api/users/<int:user_id>/security-keys', methods=['GET'])
def get_user_security_keys(user_id):
    # Verify admin token and authorization
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({'error': 'Admin authorization required'}), 401

    # Verify the admin token
    auth_token = auth_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401

    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    # Get the user's security keys
    keys = SecurityKey.query.filter_by(user_id=user_id).order_by(SecurityKey.created_at.desc()).all()

    keys_list = []
    for key in keys:
        # Format the credential ID for display (first 6 chars)
        display_id = key.credential_id[:6] + '...' if key.credential_id else 'Unknown'

        keys_list.append({
            'id': key.id,
            'credentialId': key.credential_id,
            'isActive': key.is_active,
            'createdAt': key.created_at.isoformat(),
            'lastUsed': key.last_used.isoformat() if key.last_used else None,
            'model': key.model,
            'type': key.type,
            'serialNumber': key.serial_number
        })

    return jsonify({'securityKeys': keys_list})


@app.route('/api/security-keys/all', methods=['GET'])
def get_all_security_keys():
   # Verify admin token and authorization
   auth_token = request.headers.get('Authorization')
   if not auth_token:
       return jsonify({'error': 'Admin authorization required'}), 401

   auth_token = auth_token.replace('Bearer ', '')
   auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

   if not auth_session:
       return jsonify({'error': 'Invalid admin token'}), 401

   admin_user = Users.query.get(auth_session.user_id)
   if not admin_user or admin_user.role != 'admin':
       return jsonify({'error': 'Admin privileges required'}), 403

   try:
       keys = db.session.query(
           SecurityKey.id,
           SecurityKey.model,
           SecurityKey.type,
           SecurityKey.serial_number,
           SecurityKey.is_active,
           SecurityKey.created_at,
           SecurityKey.last_used,
           Users.username
       ).join(Users, Users.id == SecurityKey.user_id).order_by(SecurityKey.created_at.desc()).all()

       keys_list = []
       for key_data in keys:
           keys_list.append({
               'id': key_data.id,
               'model': key_data.model,
               'type': key_data.type,
               'serialNumber': key_data.serial_number,
               'status': 'active' if key_data.is_active else 'inactive', # Derived status
               'registeredOn': key_data.created_at.isoformat() if key_data.created_at else None,
               'lastUsed': key_data.last_used.isoformat() if key_data.last_used else 'Never',
               'username': key_data.username
           })
       
       return jsonify({'securityKeys': keys_list})

   except Exception as e:
       print(f"Error fetching all security keys: {str(e)}")
       import traceback
       print(traceback.format_exc())
       return jsonify({'error': 'Failed to fetch all security keys'}), 500

@app.route('/api/security-keys/<int:key_id>', methods=['GET'])
def get_security_key_details(key_id):
   # Verify admin token and authorization
   auth_token = request.headers.get('Authorization')
   if not auth_token:
       return jsonify({'error': 'Admin authorization required'}), 401

   auth_token = auth_token.replace('Bearer ', '')
   auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

   if not auth_session:
       return jsonify({'error': 'Invalid admin token'}), 401

   admin_user = Users.query.get(auth_session.user_id)
   if not admin_user or admin_user.role != 'admin':
       return jsonify({'error': 'Admin privileges required'}), 403

   try:
       key = db.session.query(
           SecurityKey.id,
           SecurityKey.model,
           SecurityKey.type,
           SecurityKey.serial_number,
           SecurityKey.is_active,
           SecurityKey.created_at,
           SecurityKey.last_used,
           SecurityKey.deactivated_at,
           SecurityKey.deactivation_reason,
           SecurityKey.credential_id, # Added for completeness
           SecurityKey.public_key,    # Added for completeness
           SecurityKey.sign_count,    # Added for completeness
           Users.username,
           Users.id.label('user_id'),
           Users.first_name,
           Users.last_name
       ).join(Users, Users.id == SecurityKey.user_id).filter(SecurityKey.id == key_id).first()

       if not key:
           return jsonify({'error': 'Security key not found'}), 404

       key_details = {
           'id': key.id,
           'model': key.model,
           'type': key.type,
           'serialNumber': key.serial_number,
           'status': 'active' if key.is_active else 'inactive',
           'isActive': key.is_active, # Keep boolean for logic
           'registeredOn': key.created_at.isoformat() if key.created_at else None,
           'lastUsed': key.last_used.isoformat() if key.last_used else 'Never',
           'deactivatedAt': key.deactivated_at.isoformat() if key.deactivated_at else None,
           'deactivationReason': key.deactivation_reason,
           'credentialId': key.credential_id,
           'publicKey': key.public_key,
           'signCount': key.sign_count,
           'user': {
               'id': key.user_id,
               'username': key.username,
               'firstName': key.first_name,
               'lastName': key.last_name,
           }
       }
       
       # Fetch audit logs for this specific key
       audit_logs_query = SecurityKeyAudit.query.filter_by(security_key_id=key_id).order_by(SecurityKeyAudit.timestamp.desc()).all()
       audit_logs = []
       for log in audit_logs_query:
           audit_logs.append({
               'id': log.id,
               'action': log.action,
               'details': log.details,
               'timestamp': log.timestamp.isoformat(),
               'performedBy': {
                   'id': log.actor.id,
                   'username': log.actor.username
               },
               'previousState': log.previous_state,
               'newState': log.new_state
           })
       
       key_details['auditLogs'] = audit_logs

       return jsonify({'securityKey': key_details})

   except Exception as e:
       print(f"Error fetching security key details for key ID {key_id}: {str(e)}")
       import traceback
       print(traceback.format_exc())
       return jsonify({'error': f'Failed to fetch security key details: {str(e)}'}), 500

# Add this new route to delete a security key
@app.route('/api/security-keys/<int:key_id>', methods=['DELETE'])
def delete_security_key(key_id):
    # Verify admin token and authorization (keeping your existing code)
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({'error': 'Admin authorization required'}), 401

    # Verify the admin token
    auth_token = auth_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401

    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    # Find the security key
    key = SecurityKey.query.get(key_id)
    if not key:
        return jsonify({'error': 'Security key not found'}), 404

    # Get the user before deleting the key
    user = Users.query.get(key.user_id)
    if not user:
        return jsonify({'error': 'Associated user not found'}), 404

    try:
        # First, handle the associated audit logs
        # Option 1: Delete the audit logs
        SecurityKeyAudit.query.filter_by(security_key_id=key_id).delete()
        
        # Option 2 (Alternative): Or create a special "DELETED_KEY" record to maintain audit history
        # Uncomment the following code and comment the line above if you prefer this approach
        '''
        for audit in SecurityKeyAudit.query.filter_by(security_key_id=key_id).all():
            audit.security_key_id = -1  # Use a special ID for deleted keys
            audit.details += " (Key was subsequently deleted)"
        '''
        
        # Then delete the key
        db.session.delete(key)

        # Count remaining keys after deletion
        remaining_keys = SecurityKey.query.filter_by(user_id=user.id).count()
        remaining_active_keys = SecurityKey.query.filter_by(
            user_id=user.id,
            is_active=True
        ).count()

        # Update user's security key status
        if remaining_keys == 0:
            # No keys left
            user.has_security_key = False
            user.security_key_status = None
            # Clear the credential_id and public_key if this was the last key
            user.credential_id = None
            user.public_key = None
            user.sign_count = 0
        else:
            # Still has keys
            user.has_security_key = True
            user.security_key_status = 'active' if remaining_active_keys > 0 else 'inactive'

        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Security key deleted successfully',
            'user': {
                'id': user.id,
                'hasSecurityKey': user.has_security_key,
                'securityKeyStatus': user.security_key_status,
                'remainingKeys': remaining_keys,
                'remainingActiveKeys': remaining_active_keys
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting security key: {str(e)}")
        return jsonify({'error': 'Failed to delete security key'}), 500


# Activate/deactivate a security key
@app.route('/api/security-keys/<int:key_id>/deactivate-status', methods=['POST'])
def deactivate_security_key_status(key_id):
    """Toggle a security key's active status with security checks.
    
    Security measures:
    - Only admins can toggle other users' keys
    - Cannot activate a previously deactivated key
    - Only one active key allowed per user
    """
    # Verify admin token and authorization
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({'error': 'Admin authorization required'}), 401

    # Verify the admin token
    auth_token = auth_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401

    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    # Find the security key
    key = SecurityKey.query.get(key_id)
    if not key:
        return jsonify({'error': 'Security key not found'}), 404

    print(f"[DEACTIVATE_KEY] Initial key state for ID {key_id}: is_active={key.is_active}, reason='{key.deactivation_reason}'")
    
    reason_from_payload = request.json.get('reason') if request.json else "REQUEST_JSON_IS_NONE"
    print(f"[DEACTIVATE_KEY] Reason from request payload for key ID {key_id}: '{reason_from_payload}'")

    # If trying to activate a deactivated key
    if not key.is_active and key.last_used:
        return jsonify({
            'error': 'Cannot reactivate key',
            'detail': 'Previously deactivated keys cannot be reactivated for security reasons'
        }), 400

    # If activating a key, check if user already has another active key
    if not key.is_active:  # If we're activating the key (current key.is_active is False, about to become True)
        other_active_key = SecurityKey.query.filter_by(
            user_id=key.user_id,
            is_active=True
        ).filter(SecurityKey.id != key_id).first() # Exclude the current key itself if it's somehow in this state
        if other_active_key:
            return jsonify({
                'error': 'Active key exists',
                'detail': 'User already has an active security key. Deactivate existing key before activating another.'
            }), 400

    # Create an audit log entry first
    previous_state = {
        'is_active': key.is_active, # This is the state *before* toggle
        'deactivated_at': key.deactivated_at.isoformat() if key.deactivated_at else None,
        'deactivation_reason': key.deactivation_reason # This is the reason *before* update
    }
    print(f"[DEACTIVATE_KEY] Previous state for audit for key ID {key_id}: {previous_state}")

    # Toggle the status and set deactivation details
    key.is_active = not key.is_active # key.is_active is now the new state
    
    # When deactivating, set deactivation details
    if not key.is_active: # This means the key was active, and is now being made inactive
        key.deactivated_at = datetime.now(timezone.utc)
        key.deactivation_reason = reason_from_payload # Use the captured reason from request
        print(f"[DEACTIVATE_KEY] Deactivating key ID {key_id}. Set deactivation_reason to: '{key.deactivation_reason}'")
    else: # This means the key was inactive, and is now being made active
        key.deactivated_at = None
        key.deactivation_reason = None
        print(f"[DEACTIVATE_KEY] Activating key ID {key_id}. Cleared deactivation_reason.")

    new_state = {
        'is_active': key.is_active, # This is the new state *after* toggle
        'deactivated_at': key.deactivated_at.isoformat() if key.deactivated_at else None,
        'deactivation_reason': key.deactivation_reason # This is the new reason *after* update
    }
    print(f"[DEACTIVATE_KEY] New state for audit for key ID {key_id}: {new_state}")

    # Create audit log
    audit_log = SecurityKeyAudit(
        security_key_id=key.id,
        user_id=key.user_id,
        action='deactivate' if not key.is_active else 'activate',
        details=f"Security key {'deactivated' if not key.is_active else 'activated'} by admin",
        performed_by=admin_user.id,
        previous_state=previous_state,
        new_state=new_state
    )
    db.session.add(audit_log)

    # Ensure created_at has timezone info
    if key.created_at and not key.created_at.tzinfo:
        key.created_at = key.created_at.replace(tzinfo=timezone.utc)

    # Ensure last_used has timezone info if it exists
    if key.last_used and not key.last_used.tzinfo:
        key.last_used = key.last_used.replace(tzinfo=timezone.utc)

    # Now compare the timezone-aware timestamps
    if key.last_used and key.created_at and key.last_used < key.created_at:
        # If last_used is before created_at, it's invalid, so reset it
        key.last_used = None  # Reset invalid last_used time

    # Get the user that owns this key
    user = Users.query.get(key.user_id)

    # Update the user's security key status
    if user:
        # Check for any other active keys
        other_active_keys = SecurityKey.query.filter_by(
            user_id=user.id,
            is_active=True
        ).filter(SecurityKey.id != key.id).count()

        # Update user's security_key_status
        if key.is_active or other_active_keys > 0:
            user.security_key_status = 'active'
            user.has_security_key = True
        else:
            # Check if they have any inactive keys
            inactive_keys = SecurityKey.query.filter_by(
                user_id=user.id,
                is_active=False
            ).count()

            if inactive_keys > 0:
                user.security_key_status = 'inactive'
                user.has_security_key = True  # Users with inactive keys still have keys
            else:
                user.security_key_status = None
                user.has_security_key = False

    # Commit all changes
    db.session.commit()

    return jsonify({
        'message': f"Security key {'activated' if key.is_active else 'deactivated'} successfully",
        'key': {
            'id': key.id,
            'isActive': key.is_active
        },
        'user': {
            'id': user.id if user else None,
            'securityKeyStatus': user.security_key_status if user else None,
            'hasSecurityKey': user.has_security_key if user else False
        }
    })

# Update security key details
@app.route('/api/security-keys/<int:key_id>', methods=['PUT'])
def update_security_key(key_id):
    # Verify admin token and authorization
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({'error': 'Admin authorization required'}), 401

    # Verify the admin token
    auth_token = auth_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401

    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    # Get the request data
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request data is required'}), 400

    # Check required fields
    required_fields = ['model', 'type', 'serialNumber']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    # Find the security key
    key = SecurityKey.query.get(key_id)
    if not key:
        return jsonify({'error': 'Security key not found'}), 404

    # Update the fields
    key.model = data['model']
    key.type = data['type']
    key.serial_number = data['serialNumber']
    
    # Only update PIN if provided and not empty
    if 'pin' in data and data['pin']:
        key.pin = generate_password_hash(data['pin'])

    db.session.commit()

    return jsonify({
        'message': 'Security key updated successfully',
        'key': {
            'id': key.id,
            'model': key.model,
            'type': key.type,
            'serialNumber': key.serial_number
        }
    })


@app.route('/api/security-keys/details', methods=['POST'])
def save_security_key_details():
    # Verify admin token and authorization
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({'error': 'Admin authorization required'}), 401

    # Verify the admin token
    auth_token = auth_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()

    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401

    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    data = request.get_json()
    required_fields = ['userId', 'model', 'type', 'serialNumber', 'pin']

    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Store the details in the auth session instead of Flask session
    auth_session.client_binding = json.dumps({
        'user_id': data['userId'],
        'model': data['model'],
        'type': data['type'],
        'serial_number': data['serialNumber'],
        'pin': data['pin']
    })
    db.session.commit()

    return jsonify({'message': 'Security key details saved successfully'}), 200

@app.route('/api/security-keys/<int:key_id>/reset', methods=['POST'])
def reset_security_key(key_id):
    # Authentication checks (keep your existing code)
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({'error': 'Admin authorization required'}), 401
    
    # Verify the admin token
    auth_token = auth_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401
    
    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    # Find the security key
    key = SecurityKey.query.get(key_id)
    if not key:
        return jsonify({'error': 'Security key not found'}), 404
        
    # Check if key has already been reset
    if not key.credential_id and key.deactivation_reason == "Reset by admin":
        return jsonify({'error': 'Key has already been reset'}), 400
    
    try:
        # Create audit log entry for reset
        previous_state = {
            'pin': 'REDACTED' if key.pin else None,
            'is_active': key.is_active,
            'deactivated_at': key.deactivated_at.isoformat() if key.deactivated_at else None,
            'deactivation_reason': key.deactivation_reason,
            'credential_id': key.credential_id,
            'public_key': key.public_key,
            'sign_count': key.sign_count
        }

        # Reset the database record
        key.pin = None
        
        # Mark as inactive for reassignment
        key.is_active = False
        # DO NOT update deactivated_at here; it's set during explicit deactivation.
        # DO NOT update deactivation_reason here; it's set during explicit deactivation.
        
        # Clear credential if needed
        key.credential_id = None
        key.public_key = None
        key.sign_count = 0

        new_state = {
            'pin': None,
            'is_active': key.is_active,
            'deactivated_at': key.deactivated_at.isoformat(),
            'deactivation_reason': key.deactivation_reason,
            'credential_id': key.credential_id,
            'public_key': key.public_key,
            'sign_count': key.sign_count
        }

        # Create audit log
        audit_log = SecurityKeyAudit(
            security_key_id=key.id,
            user_id=key.user_id,
            action='reset',
            details=f"Security key reset by admin for reassignment",
            performed_by=admin_user.id,
            previous_state=previous_state,
            new_state=new_state
        )
        db.session.add(audit_log)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Security key reset successfully',
            'key': {
                'id': key.id,
                'isActive': key.is_active
            }
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting security key: {str(e)}")
        return jsonify({'error': f'Failed to reset security key: {str(e)}'}), 500


@app.route('/api/security-keys/<int:key_id>/reassign', methods=['POST'])
def reassign_security_key(key_id):
    # Authentication checks
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({'error': 'Admin authorization required'}), 401
    
    # Verify the admin token
    auth_token = auth_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401
    
    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    # Find the security key
    key = SecurityKey.query.get(key_id)
    if not key:
        return jsonify({'error': 'Security key not found'}), 404
    
    # Get new user ID from request
    data = request.get_json()
    new_user_id = data.get('new_user_id')
    
    if not new_user_id:
        return jsonify({'error': 'New user ID is required'}), 400
    
    # Check if key is ready for reassignment
    if key.is_active:
        return jsonify({'error': 'Security key must be reset before reassignment'}), 400
    
    try:
        # Get the current owner and new owner
        current_owner = Users.query.get(key.user_id)
        new_owner = Users.query.get(new_user_id)
        
        if not new_owner:
            return jsonify({'error': 'New user not found'}), 404

        # Check if the new owner already has an active security key
        existing_active_key = SecurityKey.query.filter_by(user_id=new_owner.id, is_active=True).first()
        if existing_active_key:
            return jsonify({'error': 'New user already has an active security key. Cannot reassign.'}), 400
        
        # Update the key record
        # Create an audit log entry
        previous_state = {
            'user_id': key.user_id,
            'credential_id': key.credential_id,
            'public_key': key.public_key,
            'sign_count': key.sign_count,
            'deactivated_at': key.deactivated_at.isoformat() if key.deactivated_at else None,
            'deactivation_reason': key.deactivation_reason,
            'last_used': key.last_used.isoformat() if key.last_used else None
        }

        key.user_id = new_user_id
        
        # Clear credentials (will be re-registered by new user)
        key.credential_id = None
        key.public_key = None
        key.sign_count = 0
        key.pin = None
        
        # Update metadata
        key.deactivated_at = None
        key.deactivation_reason = None
        key.last_used = None

        new_state = {
            'user_id': key.user_id,
            'credential_id': key.credential_id,
            'public_key': key.public_key,
            'sign_count': key.sign_count,
            'deactivated_at': key.deactivated_at.isoformat() if key.deactivated_at else None,
            'deactivation_reason': key.deactivation_reason,
            'last_used': key.last_used.isoformat() if key.last_used else None
        }

        # Create audit log
        audit_log = SecurityKeyAudit(
            security_key_id=key.id,
            user_id=new_user_id,  # This will be the new user
            action='reassign',
            details=f"Security key reassigned from {current_owner.username if current_owner else 'unknown'} to {new_owner.username}",
            performed_by=admin_user.id,
            previous_state=previous_state,
            new_state=new_state
        )
        db.session.add(audit_log)
        
        db.session.commit()
        
        # Update both users' security key status
        if current_owner:
            current_owner.update_security_key_status()
        
        new_owner.update_security_key_status()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Security key reassigned from {current_owner.username if current_owner else "unknown"} to {new_owner.username}',
            'key': {
                'id': key.id,
                'userId': new_user_id
            }
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error reassigning security key: {str(e)}")
        return jsonify({'error': f'Failed to reassign security key: {str(e)}'}), 500


# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Please enter all required fields'}), 400

    identifier = data.get('username')
    user = None

    # Try to find user by national ID if it's a number
    try:
        national_id = int(identifier)
        user = Users.query.filter_by(national_id=national_id).first()
    except ValueError:
        # If not a number, try email
        user = Users.query.filter_by(email=identifier).first()

    # If no user found by national ID or email, check if they exist by username
    if not user:
        user_by_username = Users.query.filter_by(username=identifier).first()
        if user_by_username:
            return jsonify({'error': 'Invalid credentials. Please try again'}), 401
        return jsonify({'error': 'Invalid credentials. Please try again'}), 401

    # Get location from IP
    ip_address = request.remote_addr
    location = get_location_from_ip(ip_address)

    # Assess risk before creating the authentication attempt
    risk_score = assess_risk(user.id, request)

    # Create a new authentication attempt record
    user_agent = request.headers.get('User-Agent', '')
    auth_attempt = AuthenticationAttempt(
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        device_type=detect_device_type(user_agent),
        auth_type='password',
        location=location,
        risk_score=risk_score,  # Store the risk score in the attempt
        success=False  # Will update to True if successful
    )
    db.session.add(auth_attempt)

    # Verify password
    if not user.check_password(data['password']):
        # Password failed. auth_attempt.success is already False by default.
        # Increment failed attempts. This method also handles locking if the threshold is met and commits changes.
        user.increment_failed_attempts() # This commits the user object and auth_attempt via its own commit.
        
        # After incrementing and potentially locking, check the lock status.
        if user.is_account_locked():
            # db.session.commit() # Not needed here, increment_failed_attempts handles its commit.
            return jsonify({
                'error': 'Account is temporarily locked due to too many failed attempts. Please contact an administrator to unlock your account.',
                'accountLocked': True,
                'failedAttempts': user.failed_login_attempts # Include current failed attempts count
            }), 401
        else:
            # Account is not locked, but password was wrong.
            # db.session.commit() # Not needed here, increment_failed_attempts handles its commit.
            return jsonify({'error': 'Invalid credentials. Please try again'}), 401

    # Password is correct - update attempt to successful
    auth_attempt.success = True
    # Commit the successful auth_attempt here, as increment_failed_attempts was not called.
    db.session.commit()

    # Increment successful and total login attempts
    user.increment_successful_attempts()

    # Update login history
    user.last_login_time = datetime.now(timezone.utc)
    user.last_login_ip = request.remote_addr

    # Clean up any existing authentication sessions for this user
    AuthenticationSession.query.filter_by(user_id=user.id).delete()
    db.session.commit()

    # Generate binding data for token binding
    binding_hash, binding_nonce = generate_binding_data(request)

    # Create new authentication session with password verified
    auth_session = AuthenticationSession(
        user_id=user.id,
        password_verified=True,
        security_key_verified=False,
        client_binding=binding_hash,
        binding_nonce=binding_nonce,
        risk_score=risk_score,
        requires_additional_verification=risk_score > 50
    )
    db.session.add(auth_session)
    db.session.commit()

    # Update has_security_key status
    if user.credential_id and not user.has_security_key:
        user.has_security_key = True
        db.session.commit()

    # Get current security key status
    has_security_key = user.has_security_key or False

    # Add user role to the response
    response_data = {
        'message': 'Password verified',
        'user_id': user.id,
        'firstName': user.first_name,
        'lastName': user.last_name,
        'role': user.role,
        'has_security_key': has_security_key,
        'auth_token': auth_session.session_token,
        'binding_nonce': binding_nonce,
        'risk_score': risk_score,
        'requires_additional_verification': risk_score > 50
    }

    if not has_security_key:
        # User needs to register a security key first
        response_data[
            'message'] = 'Password verified, but you need to register a security key to fully access your account'
        return jsonify(response_data), 200
    else:
        # User has a security key, so they need to use it as a second factor
        response_data['message'] = 'Password verified. Please complete authentication with your security key'
        return jsonify(response_data), 200


# WebAuthn registration endpoints
# Helper functions for base64url encoding/decoding
def base64url_to_bytes(base64url):
    """Convert base64url to bytes."""
    base64_str = base64url.replace('-', '+').replace('_', '/')
    padding = '=' * ((4 - len(base64_str) % 4) % 4)  # Correct padding
    return base64.b64decode(base64_str + padding)


def bytes_to_base64url(bytes_data):
    """Convert bytes to base64url."""
    # Standard base64 encode
    base64_str = base64.b64encode(bytes_data).decode('utf-8')

    # Convert to URL-safe
    return base64_str.replace('+', '-').replace('/', '_').rstrip('=')


@app.route('/api/webauthn/register/begin', methods=['POST'])
def webauthn_register_begin():
    data = request.get_json()
    username = data.get('username')
    auth_token = data.get('auth_token')
    binding_nonce = data.get('binding_nonce')
    force_registration = data.get('forceRegistration', False)  # Add this parameter
    
    print(f"Registration begin request: username={username}, force_registration={force_registration}")

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Check if user exists
    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # If auth token provided, validate binding
    if auth_token and binding_nonce:
        # Find the session
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session or auth_session.user_id != user.id:
            return jsonify({'error': 'Invalid session'}), 400

        # Regenerate the binding hash
        recalculated_binding, _ = generate_binding_data(request)
        binding_hash = hashlib.sha256(f"{recalculated_binding}|{binding_nonce}".encode()).hexdigest()

        # Validate binding
        if not auth_session.validate_binding(binding_hash):
            return jsonify({'error': 'Invalid session binding'}), 400

        # Update the session last used timestamp
        auth_session.update_last_used()

    # Get all existing credential IDs from the database
    # This is for the excludeCredentials parameter to prevent
    # registering the same security key multiple times
    all_credentials = []
    
    # Only gather exclude credentials if we're not forcing registration
    if not force_registration:
        print("Getting existing credentials to exclude them")
        users_with_credentials = Users.query.filter(Users.credential_id.isnot(None)).all()

        for existing_user in users_with_credentials:
            try:
                credential_id = websafe_decode(existing_user.credential_id)
                all_credentials.append(
                    PublicKeyCredentialDescriptor(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        id=credential_id
                    )
                )
            except Exception as e:
                print(f"Error decoding credential ID: {e}")
                continue
    else:
        print("Force registration enabled - not excluding any existing credentials")

    # Prepare registration options
    user_entity = PublicKeyCredentialUserEntity(
        id=str(user.id).encode('utf-8'),
        name=username,
        display_name=f"{user.first_name} {user.last_name}"  # Use full name for display_name
    )

    # Get registration data from the server
    registration_data, state = server.register_begin(
        user_entity,
        credentials=all_credentials,  # This will be empty if force_registration is true
        user_verification=UserVerificationRequirement.PREFERRED,
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM
    )

    # Extract the challenge bytes from the state
    challenge_bytes = state  # In newer versions of the library, state is the challenge itself

    # Ensure we have the challenge in bytes format
    if isinstance(state, dict) and 'challenge' in state:
        challenge_bytes = state['challenge']

    # Verify challenge_bytes is in bytes format
    if not isinstance(challenge_bytes, bytes):
        challenge_bytes = bytes(challenge_bytes) if hasattr(challenge_bytes, '__bytes__') else str(
            challenge_bytes).encode('utf-8')

    # Print information about the challenge (using ASCII-safe characters only)
    print("Challenge details:")
    print(f"- Type: {type(challenge_bytes).__name__}")
    print(f"- Length: {len(challenge_bytes)} bytes")
    print(f"- Preview: {challenge_bytes[:10].hex()}")

    # Clear any existing challenges for this user
    WebAuthnChallenge.query.filter_by(user_id=user.id, expired=False).update({"expired": True})
    db.session.commit()

    # Create base64 representation of the challenge for storage
    challenge_base64 = base64.b64encode(challenge_bytes).decode('utf-8')

    # Create new challenge record
    new_challenge = WebAuthnChallenge(
        user_id=user.id,
        challenge=challenge_base64
    )
    db.session.add(new_challenge)
    db.session.commit()

    # Convert the same challenge to base64url for the client
    challenge_base64url = base64.b64encode(challenge_bytes).decode('utf-8').replace('+', '-').replace('/', '_').rstrip(
        '=')

    # Also encode the user ID as base64url for the client
    user_id_bytes = str(user.id).encode('utf-8')
    user_id_base64url = base64.b64encode(user_id_bytes).decode('utf-8').replace('+', '-').replace('/', '_').rstrip('=')

    # Prepare exclude credentials list for client
    exclude_credentials = []
    if not force_registration:
        for cred in all_credentials:
            exclude_credentials.append({
                'type': 'public-key',
                'id': websafe_encode(cred.id)
            })

    # Return the publicKey options as expected by the WebAuthn API
    return jsonify({
        'publicKey': {
            'rp': {
                'name': rp.name,
                'id': rp.id
            },
            'user': {
                'id': user_id_base64url,
                'name': username,
                'displayName': f"{user.first_name} {user.last_name}"  # Use full name for display
            },
            'challenge': challenge_base64url,
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},  # ES256
                {'type': 'public-key', 'alg': -257}  # RS256
            ],
            'timeout': 60000,
            'excludeCredentials': exclude_credentials,  # Will be empty if force_registration is true
            'authenticatorSelection': {
                'authenticatorAttachment': 'cross-platform',
                'userVerification': 'preferred',
                'requireResidentKey': False,  # Don't require resident keys
            },
            'attestation': 'none'
        },
        'registrationToken': new_challenge.id,  # Send the challenge ID as a token
        'forceRegistration': force_registration  # Include in response for debugging
    })


@app.route('/api/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    print("\n=================== REGISTER COMPLETE REQUEST ===================")

    data = request.get_json()
    print("Request data:", data)

    username = data.get('username')
    auth_token = data.get('auth_token')
    binding_nonce = data.get('binding_nonce')
    force_registration = data.get('forceRegistration', False)
    keyId = data.get('keyId')  # Get the key ID if provided
    
    print(f"Registration complete request: username={username}, force_registration={force_registration}, keyId={keyId}")

    # Get security key details
    model = data.get('model')
    type_ = data.get('type')
    serial_number = data.get('serialNumber')
    pin = data.get('pin')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Determine the actor_id (who is performing this registration)
    # 'user' is the user for whom the key is being registered.
    
    actor_id = user.id  # Default to the target user (for self-registration scenarios)
    admin_performing_action = None # Will hold the admin User object if identified from header

    print(f"[REGISTER_COMPLETE] Initial actor_id set to target user.id: {user.id} for user '{user.username}'. force_registration={force_registration}")

    # Attempt to identify an admin from the Authorization header
    header_auth_token_str = request.headers.get('Authorization')
    if header_auth_token_str and header_auth_token_str.startswith('Bearer '):
        cleaned_header_token = header_auth_token_str.replace('Bearer ', '')
        header_session = AuthenticationSession.query.filter_by(session_token=cleaned_header_token).first()
        if header_session:
            potential_admin_from_header = Users.query.get(header_session.user_id)
            if potential_admin_from_header and potential_admin_from_header.role == 'admin':
                admin_performing_action = potential_admin_from_header
                actor_id = admin_performing_action.id  # This is the admin performing the action
                print(f"[REGISTER_COMPLETE] Admin actor (ID: {actor_id}, Username: {admin_performing_action.username}) identified from Authorization header.")
            elif potential_admin_from_header: # User in header is not an admin
                 print(f"[REGISTER_COMPLETE] User (ID: {potential_admin_from_header.id}, Role: {potential_admin_from_header.role}) found in Authorization header, but is not an admin.")
            else: # No user found for the session token in header
                print(f"[REGISTER_COMPLETE] No user found for session token in Authorization header.")
        else: # No session found for the token in header
            print(f"[REGISTER_COMPLETE] No session found for token in Authorization header.")
    else: # No Authorization: Bearer token in header
        print(f"[REGISTER_COMPLETE] No 'Authorization: Bearer ...' token found in headers.")

    # If force_registration is true (re-register), an admin MUST be the actor identified from the Authorization header.
    if force_registration:
        if not admin_performing_action:
            print(f"[REGISTER_COMPLETE] AUDIT FAIL: force_registration=True for user '{user.username}', but no admin actor was identified from the Authorization header. This is an admin-driven flow and requires admin authentication via header.")
            return jsonify({'error': 'Admin authorization token in header is required for re-registering a key.'}), 403
        # If admin_performing_action is set, actor_id is already correctly the admin's ID.
        print(f"[REGISTER_COMPLETE] AUDIT: Re-registration flow for user '{user.username}'. Actor is Admin ID: {actor_id} (Username: {admin_performing_action.username}).")
    else: # Not force_registration (this is an initial registration)
        if admin_performing_action:
            # An admin is in the header. This could be an admin registering their *own* first key,
            # or an admin initiating the *first* key registration for another user.
            # In both these cases, the admin from the header is the correct actor.
            print(f"[REGISTER_COMPLETE] AUDIT: Initial registration. Admin actor (ID: {actor_id}, Username: {admin_performing_action.username}) present in header. Target user: '{user.username}'.")
        else:
            # No admin in header, this is a true self-registration by the target user.
            # actor_id remains user.id (the target user).
            print(f"[REGISTER_COMPLETE] AUDIT: Initial self-registration for user '{user.username}'. Actor is Target User ID: {actor_id}.")
    
    # The `auth_token` variable (from `data.get('auth_token')`) is used for binding validation if present.
    # It is NOT used to determine the `actor_id` for audit logging in `force_registration` cases.
    # The `auth_token` from the body is distinct from the `header_auth_token_str` from `request.headers.get('Authorization')`.
    # `auth_token` here is the variable defined at the start of the function from `data.get('auth_token')`.
    if binding_nonce and auth_token and not validate_token_binding(auth_token, binding_nonce, request):
        return jsonify({'error': 'Invalid session or connection during token binding validation'}), 400

    challenge_record = db.session.query(WebAuthnChallenge).filter(
        WebAuthnChallenge.user_id == user.id,
        WebAuthnChallenge.expired == False
    ).order_by(WebAuthnChallenge.created_at.desc()).first()

    if not challenge_record:
        return jsonify({'error': 'Registration session expired or not found'}), 400

    stored_challenge_base64 = challenge_record.challenge
    challenge_bytes = base64.b64decode(stored_challenge_base64)

    print(f"Retrieved challenge from DB (Base64): {stored_challenge_base64}")
    print(f"Challenge bytes (Hex): {challenge_bytes.hex()}")
    print(f"Challenge length: {len(challenge_bytes)} bytes")

    try:
        attestation_response = data.get('attestationResponse')
        if not attestation_response:
            return jsonify({'error': 'No attestation response provided'}), 400

        print("\nProcessing attestation response:")
        print(f"Response contains: {list(attestation_response.keys())}")
        print(f"Response type: {attestation_response.get('type')}")
        print(f"Credential ID: {attestation_response.get('id')}")

        response_section = attestation_response.get('response', {})
        print(f"Response section keys: {list(response_section.keys())}")

        client_data_json = response_section.get('clientDataJSON', '')
        client_data_bytes = base64url_to_bytes(client_data_json)
        client_data_obj = json.loads(client_data_bytes.decode('utf-8'))

        if isinstance(client_data_obj['challenge'], bytes):
            client_data_obj['challenge'] = base64.urlsafe_b64encode(client_data_obj['challenge']).decode().rstrip('=')
        elif not isinstance(client_data_obj['challenge'], str):
            raise ValueError(f"Invalid challenge format: expected string, got {type(client_data_obj['challenge'])}")

        print("Challenge format verified successfully")

        client_challenge_base64url = client_data_obj.get('challenge', '')
        client_challenge_bytes = base64url_to_bytes(client_challenge_base64url)

        print(f"Client challenge bytes (Hex): {client_challenge_bytes.hex()}")
        print(f"Client challenge length: {len(client_challenge_bytes)} bytes")

        challenges_match = challenge_bytes == client_challenge_bytes
        print(f"\nChallenges match: {challenges_match}")

        if not challenges_match:
            print("CHALLENGE MISMATCH!")
            return jsonify({
                'error': 'Challenge mismatch between server and client',
                'detail': 'The challenge sent by the client does not match the one stored on the server'
            }), 400

        attestation_object = response_section.get('attestationObject', '')
        attestation_object_bytes = base64url_to_bytes(attestation_object)

        try:
            attestation_obj = AttestationObject(attestation_object_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse AttestationObject: {str(e)}")

        client_data_obj['challenge'] = client_data_obj['challenge'].decode() if isinstance(client_data_obj['challenge'],
                                                                                           bytes) else client_data_obj[
            'challenge']

        client_data_json_fixed = json.dumps(client_data_obj)
        client_data = CollectedClientData(client_data_json_fixed.encode('utf-8'))

        state = {
            'challenge': base64.urlsafe_b64encode(challenge_bytes).decode().rstrip('='),
            'user_verification': 'required'  # or 'preferred' based on what your app expects
        }

        print("\n=== Debug: WebAuthn Objects Before Register Complete ===")
        print(f"CollectedClientData Raw JSON: {client_data_bytes.decode('utf-8')}")
        print(f"CollectedClientData Parsed: {client_data_obj}")
        print(f"CollectedClientData (Object Dict): {client_data.__dict__}")
        print(f"Attestation Object AuthenticatorData (Hex): {attestation_obj.auth_data.hex()}")
        print(f"State (Challenge): {state}")
        print("=========================================================\n")

        try:
            print("\nAttempting register_complete...")
            auth_data = server.register_complete(state, client_data, attestation_obj)
            print("Registration successful!")

            # Mark the challenge as expired
            challenge_record.expired = True
            db.session.commit()

            # Extract the credential ID from the auth_data
            credential_id = websafe_encode(auth_data.credential_data.credential_id)

            # Prepare the key details and public key data
            public_key = cbor.encode(auth_data.credential_data.public_key)
            sign_count = auth_data.counter
            
            # Create key details dictionary from the provided data
            key_details = {
                'model': model,
                'type': type_,
                'serial_number': serial_number,
                'pin': pin
            }

            # If this is a force registration (reassigned key)
            if force_registration:
                # If forcing registration and keyId is provided, look up that specific key
                target_key = None
                if keyId:
                    print(f"Looking up specific key ID: {keyId}")
                    target_key = SecurityKey.query.get(keyId)
                
                # If no key found by ID but we're forcing registration, try by credential ID
                if not target_key:
                    print(f"Looking up key by credential ID: {credential_id[:10]}...")
                    target_key = SecurityKey.query.filter_by(credential_id=credential_id).first()
                    
                if target_key:
                    print(f"Force registration: Updating existing key {target_key.id} for user {user.id}")
                    
                    # Update the existing key
                    target_key.user_id = user.id
                    target_key.is_active = True
                    target_key.deactivated_at = None
                    target_key.deactivation_reason = None
                    target_key.credential_id = credential_id  # Update with new credential ID
                    target_key.public_key = base64.b64encode(public_key).decode('utf-8')
                    target_key.sign_count = sign_count
                    # Update created_at to current time for reassigned keys
                    target_key.created_at = datetime.now(timezone.utc)
                    target_key.last_used = None
                    
                    # Update with new key details if provided
                    if key_details:
                        target_key.model = key_details.get('model')
                        target_key.type = key_details.get('type')
                        target_key.serial_number = key_details.get('serial_number')
                        if key_details.get('pin'):
                            target_key.pin = generate_password_hash(key_details.get('pin'))
                    
                    # Create audit log for re-registration
                    audit_log_re_register = SecurityKeyAudit(
                        security_key_id=target_key.id,
                        user_id=user.id,
                        action='re-register',
                        details=f"Security key re-registered for user {user.username}", # Detail updated
                        performed_by=actor_id,
                        previous_state=None, # Or capture previous state if relevant
                        new_state={
                            'user_id': user.id,
                            'credential_id': credential_id,
                            'model': target_key.model,
                            'type': target_key.type,
                            'serial_number': target_key.serial_number,
                            'is_active': True,
                            'created_at': target_key.created_at.isoformat()
                        }
                    )
                    db.session.add(audit_log_re_register)
                    db.session.commit() # Commit audit log separately or as part of main transaction
                    
                    # Update user's security key fields
                    user.has_security_key = True
                    user.credential_id = credential_id
                    user.public_key = base64.b64encode(public_key).decode('utf-8')
                    user.sign_count = sign_count
                    
                    # Update user's security key status
                    user.update_security_key_status()
                    db.session.commit()
                    
                    return jsonify({
                        'status': 'success',
                        'message': 'Security key re-registered successfully',
                        'keyId': target_key.id
                    })
                else:
                    print(f"Warning: Force registration requested but no existing key found with ID {keyId}")
                    # If we're using keyId but couldn't find the key, return error
                    if keyId:
                        return jsonify({
                            'error': 'Key not found',
                            'detail': f'No security key found with ID {keyId} for reassignment'
                        }), 404
            
            # Check if this credential ID is already registered (only if not forcing registration)
            if not force_registration:
                existing_key = SecurityKey.query.filter_by(credential_id=credential_id).first()
                if existing_key:
                    # If key exists but is inactive, prevent reuse
                    if not existing_key.is_active:
                        return jsonify({
                            'error': 'Security key previously deactivated',
                            'detail': 'This security key has been deactivated and cannot be reused for security reasons.'
                        }), 400
                    return jsonify({
                        'error': 'Security key already registered',
                        'detail': 'This security key is already registered to another account.'
                    }), 400

            # Check if user already has an active security key
            active_key = SecurityKey.query.filter_by(user_id=user.id, is_active=True).first()
            if active_key:
                # For admin-initiated registration (key replacement for lost/stolen keys)
                if auth_token:
                    auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
                    if auth_session and auth_session.user_id != user.id:  # Check if admin is registering
                        # Deactivate the existing key
                        active_key.is_active = False
                        db.session.flush()
                    else:
                        return jsonify({
                            'error': 'Active key exists',
                            'detail': 'User already has an active security key. Deactivate existing key before registering a new one.'
                        }), 400
                else:
                    return jsonify({
                        'error': 'Active key exists',
                        'detail': 'User already has an active security key. Deactivate existing key before registering a new one.'
                    }), 400

            # Create a new SecurityKey entry
            with db.session.begin_nested():  # Create savepoint
                # Get the security key details from auth session or direct request data
                session_key_details = None
                try:
                    # Get authentication session if auth token provided
                    auth_session = None
                    if auth_token:
                        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        
                    if auth_session and auth_session.client_binding:
                        try:
                            session_key_details = json.loads(auth_session.client_binding)
                            # Hash the PIN if it exists
                            if session_key_details.get('pin'):
                                session_key_details['pin'] = generate_password_hash(session_key_details.get('pin'))
                        except (json.JSONDecodeError, TypeError):
                            print("Error parsing client_binding from session")
                    
                    # If we couldn't get details from session, use the ones from the request
                    if not session_key_details:
                        session_key_details = {
                            'model': model,
                            'type': type_,
                            'serial_number': serial_number,
                            'pin': generate_password_hash(pin) if pin else None
                        }
                except Exception as e:
                    print(f"Error processing key details: {str(e)}")
                    session_key_details = {
                        'model': model,
                        'type': type_,
                        'serial_number': serial_number,
                        'pin': generate_password_hash(pin) if pin else None
                    }
            
                # Create a new security key record with details
                new_key = SecurityKey(
                    user_id=user.id,
                    credential_id=credential_id,
                    public_key=base64.b64encode(public_key).decode('utf-8'),
                    sign_count=sign_count,
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                    model=session_key_details.get('model'),
                    type=session_key_details.get('type'),
                    serial_number=session_key_details.get('serial_number'),
                    pin=session_key_details.get('pin')
                )
                db.session.add(new_key)
                db.session.flush()  # This ensures new_key has an ID

                # Create audit log with appropriate action type
                action = 're-register' if force_registration else 'initial-register'
                details = (
                    f"Security key re-registered after reassignment for user {user.username}"
                    if force_registration
                    else f"New security key registered for user {user.username}"
                )
                audit_log = SecurityKeyAudit(
                    security_key_id=new_key.id,
                    user_id=user.id,
                    action=action,
                    details=details,
                    performed_by=actor_id,
                    previous_state=None,
                    new_state={
                        'user_id': user.id,
                        'credential_id': credential_id,
                        'model': session_key_details.get('model'),
                        'type': session_key_details.get('type'),
                        'serial_number': session_key_details.get('serial_number'),
                        'is_active': True,
                        'created_at': new_key.created_at.isoformat()
                    }
                )
                db.session.add(audit_log)

                # Update user's has_security_key field
                user.has_security_key = True

                # Update the credential_id and public_key fields in the Users table
                user.credential_id = credential_id
                user.public_key = base64.b64encode(public_key).decode('utf-8')
                user.sign_count = sign_count

                db.session.flush()  # Ensure changes are visible within transaction

            # Update user's security key status
            user.update_security_key_status()
            db.session.commit()  # Commit the entire transaction

            return jsonify({
                'status': 'success',
                'message': 'Security key registered successfully',
                'keyId': new_key.id
            })
        except ValueError as ve:
            print(f"ValueError during register_complete: {str(ve)}")
            return jsonify({'error': str(ve), 'detail': 'Challenge verification failed'}), 400

    except Exception as e:
        print(f"\nRegistration error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 400


# WebAuthn authentication endpoints
@app.route('/api/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    try:
        data = request.get_json()
        identifier = data.get('username')
        second_factor = data.get('secondFactor', False)
        auth_token = data.get('auth_token')
        binding_nonce = data.get('binding_nonce')
        direct_security_key_auth = data.get('directSecurityKeyAuth', False)

        if not identifier:
            return jsonify({'error': 'Username, email, or national ID required'}), 400

        # Find user by different identifier types
        user = None

        # Try to find user by national ID if it's a number
        try:
            national_id = int(identifier)
            user = Users.query.filter_by(national_id=national_id).first()
        except ValueError:
            # If not a number, try email
            user = Users.query.filter_by(email=identifier).first()

        # If no user found by national ID or email, check by username
        if not user:
            user = Users.query.filter_by(username=identifier).first()

        # Final check for user existence
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Check for any security keys first (active or inactive)
        all_security_keys = SecurityKey.query.filter_by(user_id=user.id).all()

        if not all_security_keys:
            return jsonify({'error': 'No security keys registered for this user'}), 404

        # Get user's active security keys for authentication
        active_security_keys = SecurityKey.query.filter_by(user_id=user.id, is_active=True).all()

        # Check if any keys are active
        if not active_security_keys:
            # User has keys, but none are active
            inactive_keys = SecurityKey.query.filter_by(user_id=user.id, is_active=False).all()
            if inactive_keys:
                return jsonify({
                    'error': 'Your security key is inactive. Please contact your administrator to activate your security key.',
                    'status': 'inactive_key'
                }), 403

            # Shouldn't reach here, but just in case
            return jsonify({'error': 'No active security keys found for this user'}), 404

        # For direct security key auth, skip session verification
        auth_session = None
        if not direct_security_key_auth:
            # If this is meant to be a second factor, verify that password auth happened first
            if second_factor:
                # Validate the token binding if provided
                if auth_token and binding_nonce:
                    # Validate binding
                    if not validate_token_binding(auth_token, binding_nonce, request):
                        return jsonify({'error': 'Invalid session or connection'}), 400

                    # Find the session using the provided token
                    auth_session = AuthenticationSession.query.filter_by(
                        session_token=auth_token,
                        user_id=user.id,
                        password_verified=True,
                        security_key_verified=False
                    ).first()

                    if not auth_session:
                        return jsonify({'error': 'Invalid or expired session'}), 400

                    # Update session last used timestamp
                    auth_session.last_used = datetime.now(timezone.utc)
                    db.session.commit()
                else:
                    # Find an active authentication session for this user
                    auth_session = AuthenticationSession.query.filter(
                        AuthenticationSession.user_id == user.id,
                        AuthenticationSession.password_verified == True,
                        AuthenticationSession.security_key_verified == False,
                        AuthenticationSession.expires_at > datetime.now(timezone.utc)
                    ).order_by(AuthenticationSession.created_at.desc()).first()

                    if not auth_session:
                        return jsonify({'error': 'Password authentication required first'}), 400

        # Prepare credentials for all active security keys
        credentials = []
        for key in active_security_keys:
            try:
                credential_id = websafe_decode(key.credential_id)
                credentials.append(
                    PublicKeyCredentialDescriptor(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        id=credential_id
                    )
                )
            except Exception as e:
                print(f"❌ Error decoding credential_id for key {key.id}: {e}")
                continue

        if not credentials:
            return jsonify({'error': 'No valid credentials found for user'}), 500

        # Prepare authentication options
        try:
            # Set user verification requirement based on risk score for MFA
            verification_requirement = UserVerificationRequirement.PREFERRED

            # If second factor and risk score is high, require stronger verification
            if auth_session and auth_session.risk_score > 50:
                verification_requirement = UserVerificationRequirement.REQUIRED
                print(f"High risk score ({auth_session.risk_score}): Requiring stronger verification")

            auth_data, state = server.authenticate_begin(
                credentials=credentials,
                user_verification=verification_requirement
            )
        except Exception as e:
            print(f"❌ Error in authenticate_begin: {e}")

            # Record this error
            auth_attempt = AuthenticationAttempt(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                auth_type='security_key_auth',
                success=False
            )
            db.session.add(auth_attempt)
            db.session.commit()

            return jsonify({'error': 'Failed to generate authentication options'}), 500

        # Extract challenge from state
        if isinstance(state, dict) and 'challenge' in state:
            challenge_bytes = state['challenge']
            if isinstance(challenge_bytes, str):
                challenge_bytes = base64url_to_bytes(challenge_bytes)
        else:
            challenge_bytes = state  # In some versions, state is the challenge itself

        # Store challenge in database
        # Clear any existing challenges for this user
        WebAuthnChallenge.query.filter_by(user_id=user.id, expired=False).update({"expired": True})
        db.session.commit()

        # Create new challenge record with base64 string
        challenge_base64 = base64.b64encode(challenge_bytes).decode('utf-8')

        # Updated: Mark if this is part of a multi-factor flow
        is_second_factor = second_factor and not direct_security_key_auth

        new_challenge = WebAuthnChallenge(
            user_id=user.id,
            challenge=challenge_base64,
            is_second_factor=is_second_factor
        )
        db.session.add(new_challenge)
        db.session.commit()

        # Generate base64url-encoded strings for client
        challenge_base64url = bytes_to_base64url(challenge_bytes)

        # Build the allowCredentials array for all security keys
        allow_credentials = []
        for cred in credentials:
            allow_credentials.append({
                'type': 'public-key',
                'id': websafe_encode(cred.id)
            })

        # Set timeout based on risk
        timeout = 60000  # Default 1 minute
        verification = 'preferred'

        # If high risk, reduce timeout and require stronger verification
        risk_score = 0
        if direct_security_key_auth:
            # Calculate risk for direct auth
            risk_score = assess_risk(user.id, request)
            if risk_score > 50:
                timeout = 30000  # 30 seconds for high-risk scenarios
                verification = 'required'  # Require stronger verification
        elif auth_session:
            # Use session risk score for 2FA
            risk_score = auth_session.risk_score
            if risk_score > 50:
                timeout = 30000  # 30 seconds for high-risk scenarios
                verification = 'required'  # Require stronger verification

        # Return formatted options for client
        return jsonify({
            'publicKey': {
                'rpId': rp.id,
                'challenge': challenge_base64url,
                'allowCredentials': allow_credentials,
                'timeout': timeout,
                'userVerification': verification
            },
            'riskScore': risk_score,
            'requiresAdditionalVerification': risk_score > 50
        })
    except Exception as e:
        print(f"❌ Unexpected error in webauthn_login_begin: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': 'An unexpected error occurred during security key authentication'}), 500


@app.route('/api/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    data = request.get_json()
    identifier = data.get('username')
    print(f"WebAuthn login/complete with identifier: {identifier}")
    second_factor = data.get('secondFactor', False)
    auth_token = data.get('auth_token')
    binding_nonce = data.get('binding_nonce')
    direct_security_key_auth = data.get('directSecurityKeyAuth', False)

    if not identifier:
        return jsonify({'error': 'Username, email, or national ID required'}), 400

    # Find user by different identifier types, matching the login/begin logic
    user = None

    # Try to find user by national ID if it's a number
    try:
        national_id = int(identifier)
        user = Users.query.filter_by(national_id=national_id).first()
    except ValueError:
        # If not a number, try email
        user = Users.query.filter_by(email=identifier).first()

    # If no user found by national ID or email, check by username
    if not user:
        user = Users.query.filter_by(username=identifier).first()

    # Final check for user existence
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Calculate risk score - important to do this for every authentication attempt
    risk_score = assess_risk(user.id, request)

    # Create an authentication attempt record
    auth_attempt = AuthenticationAttempt(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
        auth_type='security_key_auth',
        risk_score=risk_score,  # Store the calculated risk score
        success=False,  # Will update to True if successful
        location=get_location_from_ip(request.remote_addr),  # Add location info
        device_type=detect_device_type(request.headers.get('User-Agent', ''))  # Add device type
    )
    db.session.add(auth_attempt)

    # Validate token binding if provided and not direct security key auth
    if second_factor and auth_token and binding_nonce and not direct_security_key_auth:
        if not validate_token_binding(auth_token, binding_nonce, request):
            db.session.commit()  # Commit the failed attempt
            return jsonify({'error': 'Invalid session or connection'}), 400

    # Get the latest challenge for this user
    challenge_record = db.session.query(WebAuthnChallenge).filter(
        WebAuthnChallenge.user_id == user.id,
        WebAuthnChallenge.expired == False
    ).order_by(WebAuthnChallenge.created_at.desc()).first()

    if not challenge_record:
        db.session.commit()  # Commit the failed attempt
        return jsonify({'error': 'Authentication session expired'}), 400

    try:
        # Get the assertion response from frontend
        assertion_response = data.get('assertionResponse')

        # Get credential ID from the assertion
        credential_id = assertion_response.get('id')

        # Find which security key was used
        security_key = None
        if credential_id:
            security_key = SecurityKey.query.filter_by(
                credential_id=credential_id,
                user_id=user.id
            ).first()

            if not security_key:
                # Check if this key belongs to another user
                other_user_key = SecurityKey.query.filter_by(credential_id=credential_id).first()
                if other_user_key:
                    print(f"Security key {credential_id[:8]}... is registered to another user")
                    db.session.commit()  # Commit the failed attempt
                    return jsonify({'error': 'Login failed. Key is already registered to another user'}), 400

                # Try with credentialId encoded differently
                security_key = SecurityKey.query.filter(
                    SecurityKey.user_id == user.id,
                    func.substring(SecurityKey.credential_id, 1, 10) == func.substring(credential_id, 1, 10)
                ).first()

        # Check if the key exists and is active
        if not security_key:
            print("Could not determine which security key was used")
            db.session.commit()  # Commit the failed attempt
            return jsonify({'error': 'Invalid or unregistered security key'}), 400

        # Check if the key is active
        if not security_key.is_active:
            print(f"Security key {security_key.id} is inactive")
            db.session.commit()  # Commit the failed attempt
            return jsonify({'error': 'This security key has been deactivated'}), 400

        # Extract data for counter check
        response_data = assertion_response.get('response', {})
        auth_data_bytes = base64url_to_bytes(response_data.get('authenticatorData'))
        auth_data = AuthenticatorData(auth_data_bytes)

        # Get stored challenge
        stored_challenge = challenge_record.challenge
        challenge_bytes = base64.b64decode(stored_challenge)

        # Create proper state object
        verification_requirement = 'preferred'

        # If this is a second factor with high risk, use stronger verification
        auth_session = None
        if second_factor and not direct_security_key_auth:
            # Find the auth session
            if auth_token:
                auth_session = AuthenticationSession.query.filter_by(
                    session_token=auth_token,
                    user_id=user.id,
                    password_verified=True,
                    security_key_verified=False
                ).first()
            else:
                auth_session = AuthenticationSession.query.filter_by(
                    user_id=user.id,
                    password_verified=True,
                    security_key_verified=False
                ).order_by(AuthenticationSession.created_at.desc()).first()

            if auth_session and auth_session.risk_score > 50:
                verification_requirement = 'required'
                print(f"High risk score ({auth_session.risk_score}): Using stronger verification requirement")

        state = {
            'challenge': websafe_encode(challenge_bytes).rstrip('='),
            'user_verification': verification_requirement
        }

        # Mark challenge as expired
        challenge_record.expired = True

        # Update sign count for the specific security key
        if auth_data.counter > security_key.sign_count:
            security_key.sign_count = auth_data.counter
        elif auth_data.counter < security_key.sign_count:
            # This could indicate a cloned security key - potential security issue!
            print(
                f"⚠️ SECURITY ALERT: Counter regression detected! Stored: {security_key.sign_count}, Received: {auth_data.counter}")
            auth_attempt.risk_score = 100
            db.session.commit()
            return jsonify({
                'error': 'Security verification failed',
                'detail': 'Authentication counter check failed. This could indicate a security issue.'
            }), 400

        # Add direct security key auth handling
        if direct_security_key_auth:
            # For direct security key auth, create a new fully-verified session
            binding_hash, new_binding_nonce = generate_binding_data(request)

            # Create new session that's fully verified
            new_session = AuthenticationSession(
                user_id=user.id,
                password_verified=True,  # Mark as if password was verified
                security_key_verified=True,
                client_binding=binding_hash,
                binding_nonce=new_binding_nonce,
                risk_score=risk_score
            )
            db.session.add(new_session)

            # Update user's last login information
            user.last_login_time = datetime.now(timezone.utc)
            user.last_login_ip = request.remote_addr

            # Update security key's last used timestamp
            security_key.last_used = datetime.now(timezone.utc)

            # Mark the authentication attempt as successful
            auth_attempt.success = True
            auth_attempt.risk_score = risk_score

            db.session.commit()

            # Return success with the session token
            return jsonify({
                'status': 'success',
                'message': f"Authentication successful with security key '{security_key.name}'",
                'user_id': user.id,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'role': user.role,
                'has_security_key': True,
                'fully_authenticated': True,
                'auth_token': new_session.session_token,
                'binding_nonce': new_binding_nonce,
                'risk_score': risk_score,
                'securityKey': {
                    'id': security_key.id,
                    'name': security_key.name
                }
            })
        elif second_factor:
            # Find the authentication session if we haven't already
            if not auth_session:
                auth_session = AuthenticationSession.query.filter_by(
                    user_id=user.id,
                    password_verified=True,
                    security_key_verified=False
                ).order_by(AuthenticationSession.created_at.desc()).first()

            if auth_session:
                # Mark security key as verified
                auth_session.security_key_verified = True

                # Update session with the latest risk score calculation
                auth_session.risk_score = risk_score
                auth_session.requires_additional_verification = risk_score > 50

                # Update user's last login information
                user.last_login_time = datetime.now(timezone.utc)
                user.last_login_ip = request.remote_addr

                # Update security key's last used timestamp
                security_key.last_used = datetime.now(timezone.utc)

                # Mark the authentication attempt as successful
                auth_attempt.success = True
                auth_attempt.risk_score = risk_score

                db.session.commit()

                # This is a second factor after password authentication
                return jsonify({
                    'status': 'success',
                    'message': f"Authentication successful with security key '{security_key.name}'",
                    'user_id': user.id,
                    'firstName': user.first_name,
                    'lastName': user.last_name,
                    'role': user.role,
                    'has_security_key': True,
                    'fully_authenticated': True,
                    'auth_token': auth_session.session_token,
                    'risk_score': risk_score,
                    'requires_additional_verification': risk_score > 50,
                    'securityKey': {
                        'id': security_key.id,
                        'name': security_key.name
                    }
                })
            else:
                db.session.commit()  # Commit the failed attempt
                return jsonify({
                    'error': 'No active authentication session found',
                    'detail': 'Password authentication required first'
                }), 400
        else:
            # Standalone security key authentication is no longer allowed
            db.session.commit()  # Commit the failed attempt
            return jsonify({
                'error': 'Authentication flow requires password verification first',
                'detail': 'Please enter your password before attempting security key authentication'
            }), 400

    except Exception as e:
        print(f"Authentication error: {str(e)}")
        import traceback
        print(traceback.format_exc())

        # Update the authentication attempt
        auth_attempt.success = False
        auth_attempt.risk_score = 100  # High risk for errors
        db.session.commit()

        # Provide helpful error messages based on common WebAuthn errors
        if 'NotAllowedError' in str(e):
            return jsonify({
                'error': 'Authentication was not allowed',
                'detail': 'Your security key may not support the required verification method, or you may have used the wrong key.'
            }), 400
        elif 'SecurityError' in str(e):
            return jsonify({
                'error': 'A security error occurred',
                'detail': 'This may be due to using an insecure connection. Please ensure you are using HTTPS.'
            }), 400
        elif 'AbortError' in str(e):
            return jsonify({
                'error': 'Authentication was aborted',
                'detail': 'You may have cancelled the authentication process or waited too long to respond.'
            }), 400
        elif 'counter' in str(e).lower():
            return jsonify({
                'error': 'Security verification failed',
                'detail': 'Authentication counter check failed. This could indicate a cloned security key.'
            }), 400
        else:
            return jsonify({'error': str(e)}), 400



@app.route('/api/webauthn/check-status', methods=['POST'])
def webauthn_check_status():
    """
    Endpoint to check if a security key is still connected/available
    This sends a lightweight challenge to verify the security key's presence
    """
    data = request.get_json() or {}
    username = data.get('username')
    auth_token = data.get('auth_token')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Find user
    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # If user doesn't have a security key registered, return false
    if not user.credential_id:
        return jsonify({
            'isConnected': False,
            'message': 'No security key registered for this user'
        }), 200

    try:
        # Create a silent WebAuthn challenge to verify key presence
        # This will not require user interaction in most cases

        # First, create the credential descriptor from the stored credential
        try:
            credential_id = websafe_decode(user.credential_id)
            credential = PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=credential_id
            )
        except Exception as e:
            print(f"Error decoding credential ID: {e}")
            return jsonify({
                'isConnected': False,
                'message': 'Invalid credential format'
            }), 200

        # Generate a silent authentication challenge
        auth_data, state = server.authenticate_begin(
            credentials=[credential],
            user_verification=UserVerificationRequirement.DISCOURAGED
            # Using DISCOURAGED to avoid prompting the user when possible
        )

        # Extract challenge from state
        challenge_bytes = state if isinstance(state, bytes) else state.get('challenge')
        if not isinstance(challenge_bytes, bytes):
            challenge_bytes = str(challenge_bytes).encode('utf-8')

        # Create base64 representation of the challenge for storage
        challenge_base64 = websafe_encode(challenge_bytes)

        # Save this challenge to database
        # First expire any existing active challenges
        WebAuthnChallenge.query.filter_by(user_id=user.id, expired=False).update({"expired": True})
        db.session.commit()

        # Create new challenge record
        new_challenge = WebAuthnChallenge(
            user_id=user.id,
            challenge=challenge_base64,
            is_second_factor=False  # This is a status check, not a second factor
        )
        db.session.add(new_challenge)
        db.session.commit()

        # Log this status check as an authentication attempt
        auth_attempt = AuthenticationAttempt(
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            auth_type='security_key_status_check',
            success=True,  # We're just logging the attempt, success will be determined later
            risk_score=0  # Low risk operation
        )
        db.session.add(auth_attempt)
        db.session.commit()

        # Return the challenge to the client
        return jsonify({
            'publicKey': {
                'rpId': server.rp.id,
                'challenge': websafe_encode(challenge_bytes),
                'allowCredentials': [{
                    'type': 'public-key',
                    'id': websafe_encode(credential.id)
                }],
                'timeout': 10000,  # 10 second timeout - this is just a status check
                'userVerification': 'discouraged'  # Try to avoid prompting the user
            },
            'challengeId': new_challenge.id
        })

    except Exception as e:
        print(f"Error checking security key status: {str(e)}")
        import traceback
        print(traceback.format_exc())

        return jsonify({
            'isConnected': False,
            'error': 'Failed to check security key status',
            'message': str(e)
        }), 500


@app.route('/api/webauthn/check-status/complete', methods=['POST'])
def webauthn_check_status_complete():
    """
    Complete the security key status check
    """
    data = request.get_json() or {}
    username = data.get('username')
    assertion_response = data.get('assertionResponse')
    challenge_id = data.get('challengeId')

    if not username or not assertion_response or not challenge_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    # Find user
    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        # Get the challenge record
        challenge_record = WebAuthnChallenge.query.get(challenge_id)
        if not challenge_record or challenge_record.expired:
            return jsonify({
                'isConnected': False,
                'message': 'Challenge expired or not found'
            }), 200

        # Mark challenge as expired
        challenge_record.expired = True
        db.session.commit()

        # Get stored public key
        if not user.public_key:
            return jsonify({
                'isConnected': False,
                'message': 'No public key found for this user'
            }), 200

        # Decode stored challenge
        stored_challenge = websafe_decode(challenge_record.challenge)

        # Create state object for verification
        state = {
            'challenge': challenge_record.challenge,
            'user_verification': 'discouraged'
        }

        # Verify the assertion
        server.authenticate_complete(
            state,
            [PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=websafe_decode(user.credential_id)
            )],
            websafe_decode(user.credential_id),
            assertion_response
        )

        # If we get here, the verification was successful

        # Update the user's last authentication time
        auth_session = AuthenticationSession.query.filter_by(
            user_id=user.id,
            security_key_verified=True
        ).order_by(AuthenticationSession.created_at.desc()).first()

        if auth_session:
            auth_session.last_used = datetime.now(timezone.utc)
            db.session.commit()

        # Update the auth attempt to reflect success
        auth_attempt = AuthenticationAttempt.query.filter_by(
            user_id=user.id,
            auth_type='security_key_status_check'
        ).order_by(AuthenticationAttempt.timestamp.desc()).first()

        if auth_attempt:
            auth_attempt.success = True
            db.session.commit()

        return jsonify({
            'isConnected': True,
            'message': 'Security key is connected and verified'
        })

    except Exception as e:
        print(f"Error completing security key status check: {str(e)}")
        import traceback
        print(traceback.format_exc())

        # Log the failed attempt
        auth_attempt = AuthenticationAttempt.query.filter_by(
            user_id=user.id,
            auth_type='security_key_status_check'
        ).order_by(AuthenticationAttempt.timestamp.desc()).first()

        if auth_attempt:
            auth_attempt.success = False
            db.session.commit()

        return jsonify({
            'isConnected': False,
            'error': 'Security key verification failed',
            'message': str(e)
        }), 200  # Return 200 even for errors, with isConnected=false


# New route for checking authentication status
@app.route('/api/auth-status', methods=['POST'])
def auth_status():
    data = request.get_json()
    username = data.get('username')
    auth_token = data.get('auth_token')
    binding_nonce = data.get('binding_nonce')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Find user
    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Default status
    status = {
        'username': username,
        'has_security_key': bool(user.credential_id),
        'requires_mfa': bool(user.credential_id),  # If they have a security key, they need to use it
        'is_authenticated': False,
        'auth_stage': 'none',
        'role': user.role  # Include user role in status response
    }

    # If auth token provided, check session status
    if auth_token and binding_nonce:
        # First validate the token binding
        if validate_token_binding(auth_token, binding_nonce, request):
            # Find the session
            auth_session = AuthenticationSession.query.filter_by(
                session_token=auth_token,
                user_id=user.id
            ).first()

            if auth_session:
                # Update status based on session
                status['is_authenticated'] = auth_session.password_verified and auth_session.security_key_verified

                if auth_session.password_verified and not auth_session.security_key_verified:
                    status['auth_stage'] = 'password_verified'
                elif auth_session.password_verified and auth_session.security_key_verified:
                    status['auth_stage'] = 'fully_authenticated'

                # Update session last used
                auth_session.update_last_used()

                # Include risk assessment if available
                if auth_session.risk_score > 0:
                    status['risk_score'] = auth_session.risk_score
                    status['requires_additional_verification'] = auth_session.requires_additional_verification

    # Check if account is locked
    if user.is_account_locked():
        status['account_locked'] = True
        status['account_locked_until'] = user.account_locked_until.isoformat()

    return jsonify(status)


# New route for security recommendations
@app.route('/api/security-recommendations', methods=['POST'])
def security_recommendations():
    data = request.get_json()
    username = data.get('username')
    auth_token = data.get('auth_token')

    if not username or not auth_token:
        return jsonify({'error': 'Username and auth token required'}), 400

    # Find user
    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Find session
    auth_session = AuthenticationSession.query.filter_by(
        session_token=auth_token,
        user_id=user.id
    ).first()

    if not auth_session:
        return jsonify({'error': 'Invalid session'}), 400

    # Only provide recommendations for authenticated users
    if not (auth_session.password_verified and auth_session.security_key_verified):
        return jsonify({'error': 'Not fully authenticated'}), 403

    # Generate recommendations
    recommendations = []

    # Check for recent failed attempts
    recent_failed = AuthenticationAttempt.query.filter_by(
        user_id=user.id,
        success=False
    ).filter(
        AuthenticationAttempt.timestamp > datetime.now(timezone.utc) - timedelta(days=7)
    ).count()

    # Check for logins from unusual locations
    distinct_ips = db.session.query(AuthenticationAttempt.ip_address).filter_by(
        user_id=user.id,
        success=True
    ).filter(
        AuthenticationAttempt.timestamp > datetime.now(timezone.utc) - timedelta(days=30)
    ).distinct().count()

    if distinct_ips > 3:
        recommendations.append({
            'type': 'info',
            'message': f'Your account has been accessed from {distinct_ips} different locations in the last 30 days.',
            'action': 'If this sounds unusual, review your account activity.'
        })

    # Always recommend backup options
    recommendations.append({
        'type': 'tip',
        'message': 'Consider registering a backup security key in case your primary key is lost or damaged.',
        'action': 'Register a backup security key in your account settings.'
    })

    return jsonify({
        'recommendations': recommendations
    })


@app.route('/api/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    try:
        # Get auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')

        # Verify auth session
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid auth token'}), 401

        # Get current time and time ranges for month-over-month comparison
        now = datetime.now(timezone.utc)
        current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month_start = (current_month_start - timedelta(days=1)).replace(day=1)

        # Get all-time attempts
        all_attempts = AuthenticationAttempt.query.all()

        # Convert timestamps to UTC for comparison
        def to_utc(dt):
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt

        # Get current month's attempts for comparison
        current_month_attempts = [a for a in all_attempts
                                  if to_utc(a.timestamp) >= current_month_start]

        # Get last month's attempts for comparison
        last_month_attempts = [a for a in all_attempts
                               if last_month_start <= to_utc(a.timestamp) < current_month_start]

        # Calculate all-time totals
        total_logins = len(all_attempts)
        successful_logins = sum(1 for attempt in all_attempts if attempt.success)
        failed_attempts = sum(1 for attempt in all_attempts if not attempt.success)

        # Calculate month-over-month changes
        current_total = len(current_month_attempts)
        last_total = len(last_month_attempts)
        current_failed = sum(1 for attempt in current_month_attempts if not attempt.success)
        last_failed = sum(1 for attempt in last_month_attempts if not attempt.success)

        # Calculate percentage changes
        login_change = 0
        if last_total > 0:
            login_change = round(((current_total - last_total) / last_total) * 100, 1)

        failed_change = 0
        if last_failed > 0:
            failed_change = round(((current_failed - last_failed) / last_failed) * 100, 1)

        # Calculate security score (remains the same as it's already all-time)
        total_users = Users.query.count()
        users_with_keys = Users.query.filter(Users.credential_id.isnot(None)).count()
        security_score = round((users_with_keys / total_users * 100) if total_users > 0 else 0, 1)

        # Calculate all-time success rate
        success_rate = round((successful_logins / total_logins * 100) if total_logins > 0 else 0, 1)

        return jsonify({
            'totalLogins': total_logins,
            'loginChange': login_change,
            'securityScore': security_score,
            'successRate': success_rate,
            'failedAttempts': failed_attempts,
            'failedChange': failed_change
        })

    except Exception as e:
        print(f"Error getting dashboard stats: {str(e)}")
        import traceback
        print(traceback.format_exc())  # Print full stack trace for debugging
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/login-attempts', methods=['GET'])
def get_login_attempts():
    try:
        # Get auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')

        # Verify auth session
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid auth token'}), 401

        # Get the time range from query parameters (default to 30d)
        time_range = request.args.get('range', '30d')
        print(f"Received time range: {time_range}")  # Debug log

        # Calculate the start date based on the time range
        now = datetime.now(timezone.utc)
        if time_range == '7d':
            start_date = now - timedelta(days=7)
        elif time_range == '90d':
            start_date = now - timedelta(days=90)
        else:  # Default to 30d
            start_date = now - timedelta(days=30)

        # Normalize start_date to start of day
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        print(f"Calculated start date: {start_date}")  # Debug log

        # Query authentication attempts for the selected time range
        attempts = AuthenticationAttempt.query.filter(
            AuthenticationAttempt.timestamp >= start_date
        ).order_by(
            AuthenticationAttempt.timestamp
        ).all()

        print(f"Found {len(attempts)} attempts since {start_date}")  # Debug log

        # Group attempts by day and initialize all days in the range
        attempts_by_day = {}
        current_date = start_date
        while current_date <= now:
            day = current_date.strftime('%b %d')
            attempts_by_day[day] = {
                'name': day,
                'successful': 0,
                'failed': 0,
                'riskScore': 0,
                'count': 0
            }
            current_date += timedelta(days=1)

        # Fill in the actual attempts data
        for attempt in attempts:
            day = attempt.timestamp.strftime('%b %d')
            if attempt.success:
                attempts_by_day[day]['successful'] += 1
            else:
                attempts_by_day[day]['failed'] += 1
            attempts_by_day[day]['count'] += 1

            # Update risk score (take the highest risk score for the day)
            attempts_by_day[day]['riskScore'] = max(
                attempts_by_day[day]['riskScore'],
                attempt.risk_score or 0
            )

        # Convert to list and round risk scores
        formatted_attempts = []
        for day_data in attempts_by_day.values():
            if day_data['count'] > 0:  # Only include days with attempts
                formatted_attempts.append({
                    'name': day_data['name'],
                    'successful': day_data['successful'],
                    'failed': day_data['failed'],
                    'riskScore': round(day_data['riskScore'], 1)
                })

        # Sort by date
        formatted_attempts.sort(
            key=lambda x: datetime.strptime(x['name'], '%b %d')
        )

        print(f"Returning {len(formatted_attempts)} days of data")  # Debug log
        return jsonify({'attempts': formatted_attempts})

    except Exception as e:
        print(f"Error getting login attempts: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/security-metrics', methods=['GET'])
def get_security_metrics():
    try:
        # Get auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')

        # Verify auth session
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid auth token'}), 401

        # Get total non-deleted users
        total_users = Users.query.filter_by(is_deleted=False).count()

        # Count directly from the SecurityKey table instead of relying on security_key_status
        # Get users with active keys - query directly from SecurityKey table
        users_with_active_keys_query = db.session.query(Users.id).join(
            SecurityKey, Users.id == SecurityKey.user_id
        ).filter(
            SecurityKey.is_active == True,
            Users.is_deleted == False
        ).distinct()

        users_with_active_keys = users_with_active_keys_query.count()
        users_with_active_keys_ids = [user_id[0] for user_id in users_with_active_keys_query.all()]

        # Get users with only inactive keys - users who have keys but none are active
        users_with_inactive_keys_query = db.session.query(Users.id).join(
            SecurityKey, Users.id == SecurityKey.user_id
        ).filter(
            SecurityKey.is_active == False,
            Users.is_deleted == False,
            ~Users.id.in_(users_with_active_keys_ids)
        ).distinct()

        users_with_inactive_keys = users_with_inactive_keys_query.count()
        users_with_inactive_keys_ids = [user_id[0] for user_id in users_with_inactive_keys_query.all()]

        # Combine users with keys
        users_with_keys_ids = users_with_active_keys_ids + users_with_inactive_keys_ids

        # Users without keys = all users who aren't in either active or inactive list
        users_without_keys = db.session.query(Users).filter(
            Users.is_deleted == False,
            ~Users.id.in_(users_with_keys_ids)
        ).count()

        # Log counts for debugging
        print(
            f"Security metrics: Active={users_with_active_keys}, Inactive={users_with_inactive_keys}, None={users_without_keys}")

        # Create metrics data with colors
        metrics_data = [
            {'name': 'Active Keys', 'value': users_with_active_keys, 'color': '#2563eb'},
            {'name': 'Inactive Keys', 'value': users_with_inactive_keys, 'color': '#a6c4fc'},
            {'name': 'No Keys', 'value': users_without_keys, 'color': '#8B5CF6'}
        ]

        # Return the data
        return jsonify({
            'metrics': metrics_data,
            'activeKeys': users_with_active_keys,
            'inactiveKeys': users_with_inactive_keys,
            'withoutKeys': users_without_keys,
            'totalUsers': total_users
        })

    except Exception as e:
        print(f"Error getting security metrics: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': 'Failed to fetch security metrics'}), 500

# Add route for device distribution statistics
@app.route('/api/device-stats', methods=['GET'])
def get_device_stats():
    try:
        # Get auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')

        # Verify auth session
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid auth token'}), 401

        # Query successful login attempts grouped by device type
        device_stats = db.session.query(
            AuthenticationAttempt.device_type,
            func.count(AuthenticationAttempt.id)
        ).filter(
            AuthenticationAttempt.success == True
        ).group_by(
            AuthenticationAttempt.device_type
        ).all()

        # Format data for the pie chart
        stats_data = [
            {'name': device_type or 'Unknown', 'value': count}
            for device_type, count in device_stats
        ]

        return jsonify({'deviceStats': stats_data})

    except Exception as e:
        print(f"Error getting device stats: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


# Function to create default admin user
def create_admin_user():
    # Check if admin user already exists
    try:
        admin = Users.query.filter_by(username='admin').first()
        if admin:
            print("Admin user already exists.")
            return admin

        # Create admin user
        admin = Users(
            first_name='System',
            middle_name=None,
            last_name='Administrator',
            username='admin',
            email='admin@argus.ai',
            national_id=12345678,  # Default admin national ID
            role='admin'
        )
        admin.set_password('admin123')  # Default password - should be changed after first login

        db.session.add(admin)
        db.session.commit()
        print("Default admin user created successfully.")
        return admin
    except Exception as e:
        print(f"Error creating admin user: {str(e)}")
        db.session.rollback()
        return None


@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.get_json()

    # Verify admin token and authorization
    admin_token = request.headers.get('Authorization')
    if not admin_token:
        return jsonify({'error': 'Admin authorization required'}), 401

    # Verify the admin token
    admin_token = admin_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=admin_token).first()

    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401

    # Get the admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    # Get the user to update
    user = Users.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Validate national ID if provided
    if 'nationalId' in data:
        try:
            national_id = int(data['nationalId'])
            if len(str(national_id)) != 8:
                return jsonify({'error': 'National ID must be exactly 8 digits'}), 400

            # Check if national ID is already taken by another user
            existing_user = Users.query.filter(Users.national_id == national_id, Users.id != user_id).first()
            if existing_user:
                return jsonify({'error': 'National ID already exists'}), 409

            user.national_id = national_id
        except ValueError:
            return jsonify({'error': 'National ID must be a number'}), 400

    # Update other fields
    if 'firstName' in data:
        user.first_name = data['firstName']
    if 'middlename' in data:
        user.middle_name = data['middlename']
    if 'lastName' in data:
        user.last_name = data['lastName']
    if 'email' in data:
        existing_user = Users.query.filter(Users.email == data['email'], Users.id != user_id).first()
        if existing_user:
            return jsonify({'error': 'Email already exists'}), 409
        user.email = data['email']
    if 'username' in data:
        existing_user = Users.query.filter(Users.username == data['username'], Users.id != user_id).first()
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 409
        user.username = data['username']
    if 'role' in data:
        user.role = data['role']

    try:
        db.session.commit()
        return jsonify({
            'message': 'User updated successfully',
            'user': {
                'id': user.id,
                'nationalId': user.national_id,
                'username': user.username,
                'firstName': user.first_name,
                'middlename': user.middle_name,
                'lastName': user.last_name,
                'email': user.email,
                'role': user.role
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/reset-db', methods=['POST'])
def reset_db():
    try:
        # Reflect the database tables
        meta = MetaData()
        meta.reflect(bind=db.engine)

        # Drop all tables respecting dependencies
        meta.drop_all(bind=db.engine)

        # Recreate all tables
        db.create_all()

        # Create default admin user after reset
        admin = create_admin_user()

        return jsonify({
            'message': 'Database reset successfully',
            'admin_created': {
                'username': admin.username,
                'id': admin.id,
                'role': admin.role
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Add a route for updating user roles (admin only)
@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
def update_user_role(user_id):
    # Get admin auth token
    admin_token = request.headers.get('Authorization')
    if not admin_token:
        return jsonify({'error': 'Admin authorization required'}), 401

    # Verify admin token
    admin_token = admin_token.replace('Bearer ', '')
    auth_session = AuthenticationSession.query.filter_by(session_token=admin_token).first()

    if not auth_session:
        return jsonify({'error': 'Invalid admin token'}), 401

    # Get admin user
    admin_user = Users.query.get(auth_session.user_id)
    if not admin_user or admin_user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    # Get target user
    user = Users.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get new role from request
    data = request.get_json()
    if not data or 'role' not in data:
        return jsonify({'error': 'New role is required'}), 400

    # Validate role
    valid_roles = ['user', 'admin', 'security_officer', 'auditor', 'manager', 'developer', 'analyst', 'guest']
    new_role = data['role']
    if new_role not in valid_roles:
        return jsonify({'error': f'Invalid role. Valid roles are: {", ".join(valid_roles)}'}), 400

    # Update role
    user.role = new_role
    db.session.commit()

    return jsonify({
        'message': f'User role updated successfully to {new_role}',
        'user': {
            'id': user.id,
            'username': user.username,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'role': user.role
        }
    })


@app.route('/api/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user_data(user_id):
    try:
        # Check authentication
        auth_token = request.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid session'}), 401

        # Verify admin role
        admin_user = Users.query.get(auth_session.user_id)
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        # Don't allow deleting your own account
        if user_id == admin_user.id:
            return jsonify({'error': 'Cannot delete your own account'}), 400

        # Soft delete the user
        user = Users.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Mark user as deleted
        user.is_deleted = True
        user.deleted_at = datetime.now(timezone.utc)

        # Optional: Invalidate any active sessions
        AuthenticationSession.query.filter_by(user_id=user_id).delete()

        # Optional: Also mark related authentication attempts as soft-deleted
        AuthenticationAttempt.query.filter_by(user_id=user_id).update({"is_deleted": True})

        db.session.commit()
        return jsonify({
            'message': f'User {user_id} marked as deleted successfully',
            'deleted_at': user.deleted_at.isoformat()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/update-user-id/<int:old_id>/<int:new_id>', methods=['POST'])
def update_user_id(old_id, new_id):
    try:
        # Start a transaction
        with db.session.begin():
            # First update all related records to use a temporary ID (to avoid conflicts)
            temp_id = 999999

            # Update foreign keys in related tables
            AuthenticationAttempt.query.filter_by(user_id=old_id).update({"user_id": temp_id})
            WebAuthnChallenge.query.filter_by(user_id=old_id).update({"user_id": temp_id})
            AuthenticationSession.query.filter_by(user_id=old_id).update({"user_id": temp_id})

            # Update the user ID
            Users.query.filter_by(id=old_id).update({"id": temp_id})

            # Now update to the new ID
            AuthenticationAttempt.query.filter_by(user_id=temp_id).update({"user_id": new_id})
            WebAuthnChallenge.query.filter_by(user_id=temp_id).update({"user_id": new_id})
            AuthenticationSession.query.filter_by(user_id=temp_id).update({"user_id": new_id})
            Users.query.filter_by(id=temp_id).update({"id": new_id})

            # Reset the sequence to use the next highest ID
            from sqlalchemy import text
            db.session.execute(text("SELECT setval('users_id_seq', (SELECT MAX(id) FROM users))"))

        return jsonify({'message': f'User ID changed from {old_id} to {new_id}'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/location-stats', methods=['GET'])
def get_location_stats():
    try:
        # Get auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')

        # Verify auth session
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid auth token'}), 401

        # Query authentication attempts grouped by location
        # Removed the current_month_start filter to get all-time data
        location_stats = db.session.query(
            AuthenticationAttempt.location,
            func.count(AuthenticationAttempt.id).label('attempt_count')
        ).filter(
            AuthenticationAttempt.location.isnot(None)  # Filter out null locations
        ).group_by(
            AuthenticationAttempt.location
        ).all()

        # Format data with severity levels
        stats_data = []
        for location, count in location_stats:
            # Determine severity based on attempt count
            severity = 'low' if count <= 5 else 'medium' if count <= 15 else 'high'

            stats_data.append({
                'name': location or 'Unknown',
                'value': count,
                'severity': severity
            })

        # Sort by attempt count descending
        stats_data.sort(key=lambda x: x['value'], reverse=True)

        return jsonify({'locationStats': stats_data})

    except Exception as e:
        print(f"Error getting location stats: {str(e)}")
        return jsonify({'error': 'Failed to fetch location stats'}), 500



def is_suspicious_ip(ip_address, location, user_id=None, attempt_id=None):
    """
    Smart suspicious IP detection based on behavioral analytics and anomaly detection.
    Optimized for performance with fewer database queries.

    Args:
        ip_address (str): The IP address to check
        location (str): The location string
        user_id (int, optional): The user ID
        attempt_id (int, optional): Current authentication attempt ID

    Returns:
        bool: True if suspicious, False otherwise
    """
    if not ip_address:
        return False

    try:
        import ipaddress
        from datetime import datetime, timedelta, timezone
        from sqlalchemy import func, desc, and_, case
        from app import db, AuthenticationAttempt

        now = datetime.now(timezone.utc)
        past_day = now - timedelta(days=1)

        # 1. QUICK CHECKS FIRST: Network validation checks (no DB queries)
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if any([ip_obj.is_private, ip_obj.is_multicast, ip_obj.is_reserved, ip_obj.is_loopback]):
                print(f"Suspicious IP: {ip_address} is in a special/private IP range")
                return True
        except ValueError:
            # Invalid IP format
            print(f"Suspicious IP: {ip_address} is not a valid IP format")
            return True

        # Skip further checks if we don't have user_id
        if not user_id:
            return False

        # 2. SYSTEM-WIDE BEHAVIORAL ANALYSIS (fewer DB operations)

        # Check system-wide data about this IP in a single query
        ip_stats = db.session.query(
            func.count(AuthenticationAttempt.id).label('total_attempts'),
            func.count(func.distinct(AuthenticationAttempt.user_id)).label('distinct_users'),
            func.sum(case([(AuthenticationAttempt.success == False, 1)], else_=0)).label('failed_attempts')
        ).filter(
            AuthenticationAttempt.ip_address == ip_address,
            AuthenticationAttempt.timestamp >= past_day
        ).first()

        if ip_stats:
            # High number of failed attempts from this IP across all users
            if ip_stats.failed_attempts and ip_stats.failed_attempts > 10:
                print(f"Suspicious IP: {ip_address} has {ip_stats.failed_attempts} failed login attempts")
                return True

            # IP is used by many different users in a short time (potential credential stuffing)
            if ip_stats.distinct_users and ip_stats.distinct_users > 5:
                print(f"Suspicious IP: {ip_address} used by {ip_stats.distinct_users} different users in 24 hours")
                return True

        # 3. USER-SPECIFIC BEHAVIORAL ANALYSIS

        # Get recent successful logins for this user
        recent_user_logins = db.session.query(
            AuthenticationAttempt.location,
            AuthenticationAttempt.timestamp,
            func.extract('hour', AuthenticationAttempt.timestamp).label('hour'),
            AuthenticationAttempt.id
        ).filter(
            AuthenticationAttempt.user_id == user_id,
            AuthenticationAttempt.success == True,
            AuthenticationAttempt.timestamp >= now - timedelta(days=30)
        ).order_by(desc(AuthenticationAttempt.timestamp)).all()

        # Skip further checks if not enough login history
        if not recent_user_logins or len(recent_user_logins) < 3:
            return False

        # Extract location and time patterns
        login_locations = {}
        login_hours = {}

        for login in recent_user_logins:
            # Count locations
            if login.location:
                login_locations[login.location] = login_locations.get(login.location, 0) + 1

            # Count hours
            if login.hour is not None:
                hour_val = int(login.hour)
                login_hours[hour_val] = login_hours.get(hour_val, 0) + 1

        total_logins = len(recent_user_logins)

        # a. Location Anomaly Detection
        if total_logins >= 5 and location:
            # Check if this is a rarely used location for this user
            location_count = login_locations.get(location, 0)
            if location_count > 0:
                location_percentage = (location_count / total_logins) * 100
                if location_percentage < 5:
                    print(f"Suspicious IP: Rare location for user (only {location_percentage:.1f}% of logins)")
                    return True
            # Or if it's a completely new location for a user with established patterns
            elif len(login_locations) >= 2:
                print(f"Suspicious IP: New location for user with established login patterns")
                return True

        # b. Impossible Travel Detection
        if recent_user_logins and location:
            last_login = recent_user_logins[0]  # Already ordered by desc timestamp
            # Skip if it's the current login attempt
            if attempt_id and last_login.id == attempt_id and len(recent_user_logins) > 1:
                last_login = recent_user_logins[1]

            if last_login and last_login.location and last_login.location != location:
                hours_since_last_login = (now - last_login.timestamp).total_seconds() / 3600
                # Simple travel time check - in production use geolocation APIs for distance
                if hours_since_last_login < 1:
                    print(f"Suspicious IP: Impossible travel detected ({last_login.location} to {location})")
                    return True

        # c. Time-based Anomaly Detection
        if total_logins > 10 and login_hours:
            current_hour = now.hour
            if current_hour not in login_hours and total_logins > 20:
                print(f"Suspicious IP: Login at unusual hour ({current_hour}:00) for this user")
                return True

        return False

    except Exception as e:
        # Log error but don't block login
        print(f"Error in suspicious IP detection: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False


@app.route('/api/security/alerts', methods=['GET'])
def get_security_alerts():
    try:
        auth_token = request.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid session'}), 401

        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # Query alerts from authentication attempts
        attempts = AuthenticationAttempt.query.order_by(
            AuthenticationAttempt.timestamp.desc()
        ).paginate(page=page, per_page=per_page)

        alerts = []
        for attempt in attempts.items:
            # Initialize with a default alert type
            alert_type = None
            severity = "Low"

            # Determine alert type and severity based on conditions
            if not attempt.success:
                # Count recent failed attempts for this user
                recent_failed_count = AuthenticationAttempt.query.filter(
                    AuthenticationAttempt.user_id == attempt.user_id,
                    AuthenticationAttempt.success == False,
                    AuthenticationAttempt.timestamp >= attempt.timestamp - timedelta(hours=24)
                ).count()

                # Set failed login alert with severity based on failure count
                alert_type = "Failed Login"
                if recent_failed_count >= 5:
                    severity = "High"
                elif recent_failed_count >= 3:
                    severity = "Medium"
                else:
                    severity = "Low"

                # Check if this led to account lockout
                if recent_failed_count >= 5:
                    user = Users.query.get(attempt.user_id)
                    if user and user.is_account_locked():
                        alert_type = "Account Lockout"
                        severity = "High"

            # For successful logins, check various conditions
            elif attempt.success:
                # Check for high risk score
                if attempt.risk_score > 75:
                    alert_type = "High Risk Login"
                    severity = "High"
                elif attempt.risk_score > 40:
                    alert_type = "Moderate Risk Login"
                    severity = "Medium"

                # Check for previous risk scores to detect increases
                previous_attempt = AuthenticationAttempt.query.filter(
                    AuthenticationAttempt.user_id == attempt.user_id,
                    AuthenticationAttempt.success == True,
                    AuthenticationAttempt.timestamp < attempt.timestamp
                ).order_by(AuthenticationAttempt.timestamp.desc()).first()

                if previous_attempt and previous_attempt.risk_score and attempt.risk_score > previous_attempt.risk_score + 30:
                    alert_type = "Risk Score Increase"
                    severity = "Medium"

                # Check for IP-based alerts
                previous_ips = AuthenticationAttempt.query.filter(
                    AuthenticationAttempt.user_id == attempt.user_id,
                    AuthenticationAttempt.success == True,
                    AuthenticationAttempt.timestamp < attempt.timestamp
                ).with_entities(AuthenticationAttempt.ip_address).distinct().all()

                previous_ips_list = [ip[0] for ip in previous_ips]

                if attempt.ip_address not in previous_ips_list:
                    alert_type = "New IP Address"
                    severity = "Low"

                # Check if IP is suspicious
                if is_suspicious_ip(attempt.ip_address, attempt.location):
                    alert_type = "Suspicious IP"
                    severity = "High"

                # Check for location change
                previous_location = AuthenticationAttempt.query.filter(
                    AuthenticationAttempt.user_id == attempt.user_id,
                    AuthenticationAttempt.success == True,
                    AuthenticationAttempt.timestamp < attempt.timestamp
                ).order_by(AuthenticationAttempt.timestamp.desc()).first()

                if previous_location and previous_location.location != attempt.location:
                    # Check if it's a rapid location change (within 3 hours)
                    time_diff = attempt.timestamp - previous_location.timestamp
                    if time_diff < timedelta(hours=3):
                        alert_type = "Rapid Travel"
                        severity = "High"
                    else:
                        alert_type = "Location Change"
                        severity = "Medium"

                # Check for new device
                if attempt.device_type:
                    previous_devices = AuthenticationAttempt.query.filter(
                        AuthenticationAttempt.user_id == attempt.user_id,
                        AuthenticationAttempt.success == True,
                        AuthenticationAttempt.device_type == attempt.device_type,
                        AuthenticationAttempt.timestamp < attempt.timestamp
                    ).count()

                    if previous_devices == 0:
                        alert_type = "New Device"
                        severity = "Low"

                # Check for unusual login time (10 PM - 6 AM)
                hour = attempt.timestamp.hour
                if hour < 6 or hour >= 22:
                    alert_type = "Unusual Time"
                    severity = "Medium"

            # Only add the alert if we assigned an alert type
            if alert_type:
                alerts.append({
                    'id': attempt.id,
                    'type': alert_type,
                    'user': attempt.user.username,
                    'details': f"{'Failed' if not attempt.success else 'Successful'} login attempt from {attempt.location or 'Unknown'} using {attempt.device_type or 'Unknown Device'}",
                    'time': attempt.timestamp.isoformat(),
                    'severity': severity,
                    'resolved': attempt.success
                })

        return jsonify({
            'alerts': alerts,
            'total': len(alerts),  # Updated to use actual filtered count
            'pages': max(1, math.ceil(len(alerts) / per_page)),
            'current_page': page
        })

    except Exception as e:
        print(f"Error fetching security alerts: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': 'Failed to fetch security alerts'}), 500


# Add route to get security key audit logs
@app.route('/api/security-keys/audit-logs', methods=['GET'])
def get_security_key_audit_logs():
    try:
        # Get auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid session'}), 401

        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # Query audit logs with relationships
        audit_logs = SecurityKeyAudit.query.order_by(
            SecurityKeyAudit.timestamp.desc()
        ).paginate(page=page, per_page=per_page)

        # Format the audit logs
        logs = []
        for log in audit_logs.items:
            logs.append({
                'id': log.id,
                'securityKeyId': log.security_key_id,
                'userId': log.user_id,
                'username': log.user.username,
                'action': log.action,
                'details': log.details,
                'timestamp': log.timestamp.isoformat(),
                'performedBy': {
                    'id': log.actor.id,
                    'username': log.actor.username
                },
                'previousState': log.previous_state,
                'newState': log.new_state
            })

        return jsonify({
            'logs': logs,
            'total': audit_logs.total,
            'pages': audit_logs.pages,
            'currentPage': page
        })

    except Exception as e:
        print(f"Error fetching security key audit logs: {str(e)}")
        return jsonify({'error': 'Failed to fetch audit logs'}), 500

@app.route('/api/security/stats', methods=['GET'])
def get_security_stats():
    try:
        # Verify auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid session'}), 401

        # Get total alerts and breakdown by severity
        attempts = AuthenticationAttempt.query.all()
        total_alerts = len(attempts)

        high_count = sum(1 for a in attempts if a.risk_score > 75)
        medium_count = sum(1 for a in attempts if 40 < a.risk_score <= 75)
        low_count = total_alerts - (high_count + medium_count)

        # Calculate security score based on security keys
        total_users = Users.query.filter_by(is_deleted=False).count()
        users_with_security_key = Users.query.filter_by(has_security_key=True, is_deleted=False).count()
        security_score = (users_with_security_key / total_users * 100) if total_users > 0 else 0

        # Get locked accounts count
        locked_accounts_count = Users.query.filter_by(account_locked=True, is_deleted=False).count()

        return jsonify({
            'alertStats': {
                'total': total_alerts,
                'bySeverity': {
                    'High': high_count,
                    'Medium': medium_count,
                    'Low': low_count
                }
            },
            'securityScore': {
                'current': security_score,
                'totalUsers': total_users,
                'usersWithKeys': users_with_security_key
            },
            'accountLocks': {
                'totalLocked': locked_accounts_count
            }
        })

    except Exception as e:
        print(f"Error getting security stats: {str(e)}")
        return jsonify({'error': 'Failed to get security stats'}), 500

# Endpoint to unlock a specific account
@app.route('/api/users/<int:user_id>/unlock', methods=['POST'])
def unlock_user_account(user_id):
    try:
        # Verify admin authorization
        auth_token = request.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return jsonify({'error': 'Admin authorization required'}), 401
            
        auth_token = auth_token.replace('Bearer ', '')
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid session'}), 401
            
        admin_user = Users.query.get(auth_session.user_id)
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        if not admin_user.username:
            print(f"CRITICAL: Admin user (ID: {admin_user.id}) performing unlock for user ID {user_id} has a missing username.")
            return jsonify({'error': 'Admin account data is incomplete. Cannot complete unlock operation.'}), 500

        # Find and unlock the user account
        user = Users.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        if not user.account_locked:
            return jsonify({'error': 'Account is not locked'}), 400
            
        # Unlock the account
        user.unlock_account(admin_user.username) # Pass username instead of id
        
        return jsonify({
            'message': f'Account unlocked successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'unlocked_by': admin_user.username, # This is now directly the username
                'unlocked_time': user.unlocked_time.isoformat()
            }
        })
        
    except Exception as e:
        print(f"Error unlocking account: {str(e)}")
        return jsonify({'error': 'Failed to unlock account'}), 500


# Account Locking Management Endpoints
@app.route('/api/accounts/locked', methods=['GET'])
def get_locked_accounts():
    try:
        # Verify admin authorization
        auth_token = request.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return jsonify({'error': 'Admin authorization required'}), 401
            
        auth_token = auth_token.replace('Bearer ', '')
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid session'}), 401
            
        admin_user = Users.query.get(auth_session.user_id)
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        # Get all locked accounts that aren't deleted
        locked_accounts = Users.query.filter_by(account_locked=True, is_deleted=False).all()
        
        accounts_data = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'locked_time': user.locked_time.isoformat() if user.locked_time else None,
            'failed_attempts': user.failed_login_attempts,
            'successful_attempts': user.successful_login_attempts,
            'total_attempts': user.total_login_attempts
        } for user in locked_accounts]
        
        return jsonify({
            'locked_accounts': accounts_data,
            'total_locked': len(accounts_data)
        })
        
    except Exception as e:
        print(f"Error getting locked accounts: {str(e)}")
        return jsonify({'error': 'Failed to retrieve locked accounts'}), 500


# Initialize database and create admin user
with app.app_context():
    db.create_all()
    create_admin_user()
    db.session.commit()

@app.route('/api/internal/hid_security_key_event', methods=['POST'])
def hid_security_key_event():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    vendor_id = data.get('vendor_id')
    product_id = data.get('product_id')
    device_path = data.get('path') # Unique path for the connected device session
    status = data.get('status') # 'connected' or 'disconnected'

    print(f"Received HID event: Status={status}, VID={vendor_id}, PID={product_id}, Path={device_path}")

    if status == 'connected':
        if vendor_id is None or product_id is None:
            return jsonify({'error': 'Missing vendor_id or product_id for connected event'}), 400

        # Attempt to find a SecurityKey that has a credential_id (is registered)
        # but is missing vendor_id and product_id.
        # This is a simple heuristic and might need refinement for multi-user or multi-key scenarios.
        
        print(f"Flask: Searching for active SecurityKey with NULL VID/PID and a credential_id...")
        # Prioritize keys that are active and missing VID/PID
        key_to_update = SecurityKey.query.filter(
            SecurityKey.credential_id.isnot(None),
            SecurityKey.is_active == True,
            SecurityKey.vendor_id.is_(None),
            SecurityKey.product_id.is_(None)
        ).first()

        if not key_to_update:
            print(f"Flask: No active key found. Searching for any SecurityKey with NULL VID/PID and a credential_id...")
            # Fallback: check any key missing VID/PID if no active ones are found
            key_to_update = SecurityKey.query.filter(
                SecurityKey.credential_id.isnot(None),
                SecurityKey.vendor_id.is_(None),
                SecurityKey.product_id.is_(None)
            ).first()

        if key_to_update:
            print(f"Flask: Found SecurityKey ID {key_to_update.id} to update.")
            key_to_update.vendor_id = str(vendor_id) # Ensure string
            key_to_update.product_id = str(product_id) # Ensure string
            try:
                db.session.commit()
                print(f"Updated SecurityKey ID {key_to_update.id} with VID: {vendor_id}, PID: {product_id}")
                
                # Optional: Log this update in SecurityKeyAudit
                # This would require knowing which admin/user context this update is for,
                # which is tricky if usb_detector.py is system-wide.
                # For now, just a server log.
                
                return jsonify({'message': f'SecurityKey {key_to_update.id} updated with VID/PID'}), 200
            except Exception as e:
                db.session.rollback()
                print(f"Error updating SecurityKey with VID/PID: {e}")
                return jsonify({'error': f'Failed to update database: {str(e)}'}), 500
        else:
            print(f"No suitable SecurityKey record found to update with VID: {vendor_id}, PID: {product_id}")
            return jsonify({'message': 'No matching SecurityKey record to update with VID/PID'}), 200
            
    elif status == 'disconnected':
        # Handle disconnection if needed, e.g., logging
        print(f"Security key disconnected event received for path: {device_path}")
        # No database update typically needed on disconnect for VID/PID here
        return jsonify({'message': 'Disconnected event received'}), 200
    else:
        return jsonify({'error': 'Invalid status provided'}), 400

if __name__ == '__main__':
    # Note: db.create_all() and create_admin_user() are usually not called here
    # if using Flask-Migrate and a proper seeding mechanism.
    # Consider moving them to a dedicated init-db command or manage via migrations.
    app.run(debug=True, host='0.0.0.0', port=5000)
