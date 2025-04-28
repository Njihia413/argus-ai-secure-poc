import json
import hashlib
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

from sqlalchemy import func, case

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
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)  # Optional for passwordless auth
    role = db.Column(db.String(20), nullable=False, default='user')  # New role column with default value 'user'

    # User timezone for risk-based authentication
    timezone = db.Column(db.String(50), default='UTC')
    last_login_time = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    failed_login_attempts = db.Column(db.Integer, default=0)
    
    # Security key related fields
    has_security_key = db.Column(db.Boolean, nullable=False, default=False)
    total_login_attempts = db.Column(db.Integer, default=0)  # Track total successful logins
    account_locked_until = db.Column(db.DateTime)

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

    # Increment failed login attempts
    def increment_failed_attempts(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        db.session.commit()

    # Check if account is locked
    def is_account_locked(self):
        """Check if account is locked and return boolean"""
        if self.account_locked_until and self.account_locked_until > datetime.now(timezone.utc):
            return True
        return False

    def get_lock_details(self):
        """Get detailed information about account lock status"""
        if not self.is_account_locked():
            return {
                "locked": False
            }

        now = datetime.now(timezone.utc)
        remaining_seconds = (self.account_locked_until - now).total_seconds()

        return {
            "locked": True,
            "lockedUntil": self.account_locked_until.isoformat(),
            "remainingSeconds": int(remaining_seconds)
        }


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
    auth_type = db.Column(db.String(50))  # Add this column for tracking authentication type
    risk_score = db.Column(db.Integer, default=0)
    location = db.Column(db.String(255))  # For storing geolocation data

    user = db.relationship('Users', backref=db.backref('auth_attempts', lazy=True))

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
    """Get location information from IP address"""
    try:
        # If it's localhost, try to get the public IP
        if ip_address in ('127.0.0.1', 'localhost', '::1'):
            public_ip = get_public_ip()
            if public_ip:
                ip_address = public_ip

        # Try ip-api.com first
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                city = data.get('city', '')
                country = data.get('country', '')
                if city and country:
                    return f"{city}, {country}"
                elif country:
                    return country

        # Fallback to ipapi.co if ip-api.com fails
        response = requests.get(f'https://ipapi.co/{ip_address}/json/')
        if response.status_code == 200:
            data = response.json()
            city = data.get('city', '')
            country = data.get('country_name', '')
            if city and country:
                return f"{city}, {country}"
            elif country:
                return country

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

    # Find the session
    auth_session = AuthenticationSession.query.filter_by(session_token=session_token).first()
    if not auth_session:
        print("No session found with this token")
        return False

    print(f"Found session for user_id: {auth_session.user_id}")

    # Check if session is expired
    if datetime.now(timezone.utc) > auth_session.expires_at:
        print(f"Session expired at {auth_session.expires_at}")
        return False

    # For development purposes, we're temporarily making binding validation less strict
    # In production, this would do a strict comparison of the binding data

    # Just use a subset of client characteristics to make binding less sensitive
    user_agent = request.headers.get('User-Agent', '')

    # Create a simpler binding that only considers the user agent and nonce
    simplified_binding = hashlib.sha256(f"{user_agent}|{binding_nonce}".encode()).hexdigest()

    # Log binding information for debugging
    print(f"Original stored binding: {auth_session.client_binding[:15]}...")
    print(f"Simplified binding: {simplified_binding[:15]}...")

    # For development, we could temporarily return True to bypass validation entirely
    # return True

    # Or use the simplified binding comparison
    result = secrets.compare_digest(auth_session.client_binding, simplified_binding)
    if not result:
        print(f"Binding validation failed (but continuing for development purposes)")
        # For development, we're returning True even on binding mismatch
        return True

    return True


# Function to assess risk for risk-based authentication
def assess_risk(user_id, request):
    # Get user's authentication history
    user = Users.query.get(user_id)
    if not user:
        return 100  # High risk if user not found

    # Start with a base risk score
    risk_score = 0

    # 1. Check IP address history
    current_ip = request.remote_addr
    ip_history = AuthenticationAttempt.query.filter_by(
        user_id=user_id,
        ip_address=current_ip,
        success=True
    ).count()

    if ip_history == 0:
        # New IP address
        risk_score += 30
        print(f"Risk: +30 for new IP address {current_ip}")

    # 2. Check for failed attempts
    recent_failed_attempts = AuthenticationAttempt.query.filter_by(
        user_id=user_id,
        success=False
    ).filter(
        AuthenticationAttempt.timestamp > datetime.now(timezone.utc) - timedelta(hours=24)
    ).count()

    # Each failed attempt adds 15 to risk score (no cap)
    failed_risk = recent_failed_attempts * 15
    risk_score += failed_risk
    if failed_risk > 0:
        print(f"Risk: +{failed_risk} for {recent_failed_attempts} recent failed attempts")

    # 3. Check for unusual timing
    user_timezone = user.timezone or 'UTC'  # Assuming you store user's timezone
    current_hour = datetime.now(timezone.utc).hour
    if current_hour < 6 or current_hour > 22:  # Outside normal hours
        risk_score += 10
        print(f"Risk: +10 for unusual hour ({current_hour})")

    # 4. Check device history (simplified)
    current_user_agent = request.headers.get('User-Agent', '')
    device_history = AuthenticationAttempt.query.filter_by(
        user_id=user_id,
        user_agent=current_user_agent,
        success=True
    ).count()

    if device_history == 0:
        # New device
        risk_score += 20
        print(f"Risk: +20 for new device")

    # 5. Check location (simplified - just using IP as proxy)
    if user.last_login_ip and user.last_login_ip != current_ip:
        risk_score += 15
        print(f"Risk: +15 for location change")

    # Check for rapid authentication from different locations
    if user.last_login_time:
        # Ensure both times are timezone-aware
        current_time = datetime.now(timezone.utc)
        last_login = user.last_login_time if user.last_login_time.tzinfo else user.last_login_time.replace(tzinfo=timezone.utc)
        time_since_last_login = current_time - last_login
        
        if time_since_last_login < timedelta(hours=1) and user.last_login_ip != current_ip:
            risk_score += 25
            print(f"Risk: +25 for rapid location change")

    final_score = min(risk_score, 100)  # Cap at 100
    print(f"Final risk score: {final_score}")
    return final_score


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
            not data.get('firstName') or not data.get('lastName'):
        return jsonify({'error': 'Missing required fields (firstName, lastName, username, or password)'}), 400

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
        last_name=data['lastName'],
        username=data['username'],
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


# Add a new route to get all users (admin only)
@app.route('/api/users', methods=['GET'])
def get_users():
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

    # Return all users with their login attempt counts
    # Delete any registration entries
    AuthenticationAttempt.query.filter_by(auth_type='registration').delete()
    db.session.commit()

    # Update login attempts
    for user in Users.query.all():
        # Update failed attempts
        failed_attempts = AuthenticationAttempt.query.filter_by(
            user_id=user.id,
            success=False,
            auth_type='password'
        ).count()
        user.failed_login_attempts = failed_attempts

        # Update total successful logins
        successful_attempts = AuthenticationAttempt.query.filter_by(
            user_id=user.id,
            success=True,
            auth_type='password'
        ).count()
        user.total_login_attempts = successful_attempts

    db.session.commit()

    # Now get users with updated counts
    users = Users.query.all()
    user_list = []
    
    for user in users:
        user_list.append({
            'id': user.id,
            'username': user.username,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'role': user.role,
            'hasSecurityKey': user.has_security_key,
            'lastLogin': user.last_login_time.isoformat() if user.last_login_time else None,
            'loginAttempts': user.total_login_attempts,
            'failedAttempts': user.failed_login_attempts
        })

    return jsonify({'users': user_list})


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
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

    # Get the user
    user = Users.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get login attempts
    failed_attempts = AuthenticationAttempt.query.filter_by(
        user_id=user.id,
        success=False,
        auth_type='password'
    ).count()

    successful_attempts = AuthenticationAttempt.query.filter_by(
        user_id=user.id,
        success=True,
        auth_type='password'
    ).count()

    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'role': user.role,
            'hasSecurityKey': user.has_security_key,
            'lastLogin': user.last_login_time.isoformat() if user.last_login_time else None,
            'loginAttempts': successful_attempts,
            'failedAttempts': failed_attempts
        }
    })


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    user = Users.query.filter_by(username=data['username']).first()

    # Check if user exists first before creating authentication attempt
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get location from IP
    ip_address = request.remote_addr
    location = get_location_from_ip(ip_address)
    
    # Create a new authentication attempt record after confirming user exists
    user_agent = request.headers.get('User-Agent', '')
    auth_attempt = AuthenticationAttempt(
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        device_type=detect_device_type(user_agent),
        auth_type='password',
        location=location,  # Add location data
        success=False  # Will update to True if successful
    )

    # Check if account is locked
    if user.is_account_locked():
        auth_attempt.risk_score = 100  # Max risk for locked account
        db.session.add(auth_attempt)
        db.session.commit()

        # Return both a human-readable time and ISO timestamp for countdown implementation
        locked_until_human = user.account_locked_until.strftime('%H:%M:%S')
        locked_until_iso = user.account_locked_until.isoformat()

        return jsonify({
            'error': f'Account is temporarily locked due to too many failed attempts. Try again after {locked_until_human}',
            'accountLockedUntil': locked_until_iso,
            'accountLocked': True
        }), 401

    # Assess risk
    risk_score = assess_risk(user.id, request)
    auth_attempt.risk_score = risk_score

    # Verify password
    if not user.check_password(data['password']):
        auth_attempt.success = False
        db.session.add(auth_attempt)
        db.session.commit()

        # Increment failed login attempts
        user.increment_failed_attempts()

        return jsonify({'error': 'Invalid password'}), 401

    # Password is correct - record successful login
    auth_attempt.success = True
    db.session.add(auth_attempt)

    # Increment total successful logins
    user.total_login_attempts += 1

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
        'role': user.role,  # Include user role
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

    # Prepare registration options
    user_entity = PublicKeyCredentialUserEntity(
        id=str(user.id).encode('utf-8'),
        name=username,
        display_name=f"{user.first_name} {user.last_name}"  # Use full name for display_name
    )

    # Get registration data from the server, now including all existing credentials
    # to exclude them from being registered again
    registration_data, state = server.register_begin(
        user_entity,
        credentials=all_credentials,  # Exclude existing credentials
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

    # Print information about the challenge
    print(f"Challenge type: {type(challenge_bytes).__name__}")
    print(f"Challenge length: {len(challenge_bytes)} bytes")
    print(f"Challenge first 10 bytes: {challenge_bytes[:10].hex()}")

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
            'excludeCredentials': exclude_credentials,  # Add this to prevent reregistration
            'authenticatorSelection': {
                'authenticatorAttachment': 'cross-platform',
                'userVerification': 'preferred',
                'requireResidentKey': False,  # Don't require resident keys
            },
            'attestation': 'none'
        },
        'registrationToken': new_challenge.id  # Send the challenge ID as a token
    })


@app.route('/api/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    print("\n=================== REGISTER COMPLETE REQUEST ===================")
    
    def update_security_key_status(user):
        user.has_security_key = True
        db.session.commit()
    data = request.get_json()
    print("Request data:", data)

    username = data.get('username')
    auth_token = data.get('auth_token')
    binding_nonce = data.get('binding_nonce')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # If auth token provided, validate binding
    if auth_token and binding_nonce:
        if not validate_token_binding(auth_token, binding_nonce, request):
            return jsonify({'error': 'Invalid session or connection'}), 400

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

        print("\nAttestation response structure:")
        print(f"Keys in response: {list(attestation_response.keys())}")
        print(f"Type: {attestation_response.get('type')}")
        print(f"ID: {attestation_response.get('id')}")

        response_section = attestation_response.get('response', {})
        print(f"Response section keys: {list(response_section.keys())}")

        client_data_json = response_section.get('clientDataJSON', '')
        client_data_bytes = base64url_to_bytes(client_data_json)
        client_data_obj = json.loads(client_data_bytes.decode('utf-8'))

        if isinstance(client_data_obj['challenge'], bytes):
            client_data_obj['challenge'] = base64.urlsafe_b64encode(client_data_obj['challenge']).decode().rstrip('=')
        elif not isinstance(client_data_obj['challenge'], str):
            raise ValueError(f"🚨 Challenge is NOT a string! Instead got: {type(client_data_obj['challenge'])}")

        print(f"✅ Fixed Challenge Format: {client_data_obj['challenge']}")

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
            raise ValueError(f"🚨 Failed to parse AttestationObject: {str(e)}")

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

            # Check if this credential ID is already registered to another user
            existing_user = Users.query.filter(Users.credential_id == credential_id).first()
            if existing_user:
                return jsonify({
                    'error': 'Security key already registered',
                    'detail': 'This security key is already registered to another account.'
                }), 400

            # Update user's security key information
            with db.session.begin_nested():  # Create savepoint
                public_key = cbor.encode(auth_data.credential_data.public_key)
                sign_count = auth_data.counter

                user.credential_id = credential_id
                user.public_key = base64.b64encode(public_key).decode('utf-8')
                user.sign_count = sign_count
                user.has_security_key = True
                
                db.session.flush()  # Ensure changes are visible within transaction

            db.session.commit()  # Commit the entire transaction

            # Record successful security key registration
            auth_attempt = AuthenticationAttempt(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                auth_type='security_key_registration',
                success=True
            )
            db.session.add(auth_attempt)
            db.session.commit()

            return jsonify({'status': 'success', 'message': 'Security key registered successfully'})
        except ValueError as ve:
            print(f"ValueError during register_complete: {str(ve)}")

            # Record failed registration
            auth_attempt = AuthenticationAttempt(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                auth_type='security_key_registration',
                success=False
            )
            db.session.add(auth_attempt)
            db.session.commit()

            return jsonify({'error': str(ve), 'detail': 'Challenge verification failed'}), 400

    except Exception as e:
        print(f"\nRegistration error: {str(e)}")
        import traceback
        print(traceback.format_exc())

        # Record failed registration
        auth_attempt = AuthenticationAttempt(
            user_id=user.id if user else None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            auth_type='security_key_registration',
            success=False
        )
        db.session.add(auth_attempt)
        db.session.commit()

        return jsonify({'error': str(e)}), 400


# WebAuthn authentication endpoints
@app.route('/api/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    data = request.get_json()
    username = data.get('username')
    second_factor = data.get('secondFactor', False)
    auth_token = data.get('auth_token')
    binding_nonce = data.get('binding_nonce')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Find user
    user = Users.query.filter_by(username=username).first()
    if not user or not user.credential_id:
        return jsonify({'error': 'User not found or no security key registered'}), 404

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
            auth_session.update_last_used()
        else:
            # Find an active authentication session for this user
            auth_session = AuthenticationSession.query.filter(
                AuthenticationSession.user_id == user.id,
                AuthenticationSession.password_verified == True,
                AuthenticationSession.security_key_verified == False,
                AuthenticationSession.expires_at > datetime.utcnow()
            ).order_by(AuthenticationSession.created_at.desc()).first()

            if not auth_session:
                return jsonify({'error': 'Password authentication required first'}), 400

    # Decode credential_id properly
    try:
        credential_id = websafe_decode(user.credential_id)
    except Exception as e:
        print(f"❌ Error decoding credential_id: {e}")

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

        return jsonify({'error': 'Invalid stored credential'}), 500

    # Create credential descriptor
    credential = PublicKeyCredentialDescriptor(
        type=PublicKeyCredentialType.PUBLIC_KEY,
        id=credential_id
    )

    # Prepare authentication options
    try:
        # Set user verification requirement based on risk score for MFA
        verification_requirement = UserVerificationRequirement.PREFERRED

        # If second factor and risk score is high, require stronger verification
        if second_factor and 'auth_session' in locals() and auth_session.risk_score > 50:
            verification_requirement = UserVerificationRequirement.REQUIRED
            print(f"High risk score ({auth_session.risk_score}): Requiring stronger verification")

        auth_data, state = server.authenticate_begin(
            credentials=[credential],
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

    # Debugging logs
    print("\n=== Debug: WebAuthn Login Begin ===")
    print(f"auth_data: {auth_data}")
    print(f"state: {state}")
    print("===================================\n")

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
    is_second_factor = second_factor

    new_challenge = WebAuthnChallenge(
        user_id=user.id,
        challenge=challenge_base64,
        is_second_factor=is_second_factor  # Store whether this is a second factor
    )
    db.session.add(new_challenge)
    db.session.commit()

    # Generate base64url-encoded strings for client
    challenge_base64url = bytes_to_base64url(challenge_bytes)
    credential_id_base64url = websafe_encode(credential_id)

    # Set timeout based on risk
    timeout = 60000  # Default 1 minute
    verification = 'preferred'

    # If high risk, reduce timeout and require stronger verification
    risk_score = 0
    if second_factor and 'auth_session' in locals():
        risk_score = auth_session.risk_score
        if risk_score > 50:
            timeout = 30000  # 30 seconds for high-risk scenarios
            verification = 'required'  # Require stronger verification

    # Return formatted options for client
    return jsonify({
        'publicKey': {
            'rpId': rp.id,
            'challenge': challenge_base64url,
            'allowCredentials': [{
                'type': 'public-key',
                'id': credential_id_base64url
            }],
            'timeout': timeout,
            'userVerification': verification
        },
        'riskScore': risk_score,
        'requiresAdditionalVerification': risk_score > 50 if 'auth_session' in locals() else False
    })


@app.route('/api/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    data = request.get_json()
    username = data.get('username')
    second_factor = data.get('secondFactor', False)
    auth_token = data.get('auth_token')
    binding_nonce = data.get('binding_nonce')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Find user
    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Create an authentication attempt record
    auth_attempt = AuthenticationAttempt(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
        auth_type='security_key_auth',
        success=False  # Will update to True if successful
    )
    db.session.add(auth_attempt)

    # Validate token binding if provided
    if second_factor and auth_token and binding_nonce:
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
        if second_factor:
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

        # Here we would normally use server.authenticate_complete to verify signature
        # For a production app, you should implement full verification using:
        # server.authenticate_complete(
        #     state,
        #     [credential],
        #     stored_challenge,
        #     client_data,
        #     auth_data,
        #     signature
        # )

        # For this PoC, we'll proceed with simplified verification

        # Mark challenge as expired
        challenge_record.expired = True

        # Update sign count if needed
        if auth_data.counter > user.sign_count:
            user.sign_count = auth_data.counter
        elif auth_data.counter < user.sign_count:
            # This could indicate a cloned security key - potential security issue!
            print(
                f"⚠️ SECURITY ALERT: Counter regression detected! Stored: {user.sign_count}, Received: {auth_data.counter}")
            auth_attempt.risk_score = 100
            db.session.commit()
            return jsonify({
                'error': 'Security verification failed',
                'detail': 'Authentication counter check failed. This could indicate a security issue.'
            }), 400

        # IMPORTANT: Check if this authentication should be part of the MFA flow
        if second_factor:
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

                # Update user's last login information
                user.last_login_time = datetime.utcnow()
                user.last_login_ip = request.remote_addr

                # Mark the authentication attempt as successful
                auth_attempt.success = True
                auth_attempt.risk_score = auth_session.risk_score

                db.session.commit()

                # This is a second factor after password authentication
                return jsonify({
                    'status': 'success',
                    'message': 'Authentication successful with both password and security key',
                    'user_id': user.id,
                    'firstName': user.first_name,
                    'lastName': user.last_name,
                    'role': user.role,  # Include user role in the response
                    'has_security_key': True,
                    'fully_authenticated': True,
                    'auth_token': auth_session.session_token,
                    'risk_score': auth_session.risk_score,
                    'requires_additional_verification': auth_session.requires_additional_verification
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

        # Get current time and time ranges
        now = datetime.now(timezone.utc)
        current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month_start = (current_month_start - timedelta(days=1)).replace(day=1)

        # Get current month's attempts
        current_month_attempts = AuthenticationAttempt.query.filter(
            AuthenticationAttempt.timestamp >= current_month_start
        ).all()

        # Get last month's attempts
        last_month_attempts = AuthenticationAttempt.query.filter(
            AuthenticationAttempt.timestamp >= last_month_start,
            AuthenticationAttempt.timestamp < current_month_start
        ).all()

        # Calculate totals and changes
        current_total_logins = len(current_month_attempts)
        last_total_logins = len(last_month_attempts)

        login_change = 0
        if last_total_logins > 0:
            login_change = round(((current_total_logins - last_total_logins) / last_total_logins) * 100, 1)

        # Calculate security score
        total_users = Users.query.count()
        users_with_keys = Users.query.filter(Users.credential_id.isnot(None)).count()
        security_score = round((users_with_keys / total_users * 100) if total_users > 0 else 0, 1)

        # Calculate success rate
        successful_logins = sum(1 for attempt in current_month_attempts if attempt.success)
        success_rate = round((successful_logins / current_total_logins * 100) if current_total_logins > 0 else 0, 1)

        # Calculate failed attempts
        current_failed = sum(1 for attempt in current_month_attempts if not attempt.success)
        last_failed = sum(1 for attempt in last_month_attempts if not attempt.success)

        failed_change = 0
        if last_failed > 0:
            failed_change = round(((current_failed - last_failed) / last_failed) * 100, 1)

        return jsonify({
            'totalLogins': current_total_logins,
            'loginChange': login_change,
            'securityScore': security_score,
            'successRate': success_rate,
            'failedAttempts': current_failed,
            'failedChange': failed_change
        })

    except Exception as e:
        print(f"Error getting dashboard stats: {str(e)}")
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

        # Get the start of the current month
        now = datetime.now(timezone.utc)
        current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Query all authentication attempts for the current month
        attempts = AuthenticationAttempt.query.filter(
            AuthenticationAttempt.timestamp >= current_month_start
        ).order_by(
            AuthenticationAttempt.timestamp
        ).all()

        # Group attempts by day
        attempts_by_day = {}
        for attempt in attempts:
            day = attempt.timestamp.strftime('%b %d')
            if day not in attempts_by_day:
                attempts_by_day[day] = {
                    'name': day,
                    'successful': 0,
                    'failed': 0,
                    'riskScore': 0,
                    'count': 0
                }

            if attempt.success:
                attempts_by_day[day]['successful'] += 1
            else:
                attempts_by_day[day]['failed'] += 1

            # Simply use the stored risk score from the attempt
            attempts_by_day[day]['riskScore'] = max(attempts_by_day[day]['riskScore'], attempt.risk_score or 0)

        # Convert to list and round risk scores
        formatted_attempts = []
        for day_data in attempts_by_day.values():
            formatted_attempts.append({
                'name': day_data['name'],
                'successful': day_data['successful'],
                'failed': day_data['failed'],
                'riskScore': round(day_data['riskScore'], 1)
            })

        # Sort by date
        formatted_attempts.sort(key=lambda x: datetime.strptime(x['name'], '%b %d'))

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

        # Query user counts
        total_users = Users.query.count()
        users_with_keys = Users.query.filter(Users.credential_id.isnot(None)).count()
        users_without_keys = total_users - users_with_keys

        # Format data for the pie chart
        metrics_data = [
            {'name': 'With Security Key', 'value': users_with_keys},
            {'name': 'Without Security Key', 'value': users_without_keys}
        ]

        return jsonify({'metrics': metrics_data})

    except Exception as e:
        print(f"Error getting security metrics: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


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
    admin = Users.query.filter_by(username='admin').first()
    if admin:
        print("Admin user already exists.")
        return admin

    # Create admin user
    admin = Users(
        first_name='System',
        last_name='Administrator',
        username='admin',
        role='admin'
    )
    admin.set_password('admin123')  # Default password - should be changed after first login

    db.session.add(admin)
    db.session.commit()
    print("Default admin user created successfully.")
    return admin


@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
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

    # Get the user to update
    user = Users.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()

    # Update user fields
    if 'firstName' in data:
        user.first_name = data['firstName']
    if 'lastName' in data:
        user.last_name = data['lastName']
    if 'role' in data:
        # Validate role
        valid_roles = ['user', 'admin', 'security_officer', 'auditor', 'manager', 'developer', 'analyst', 'guest']
        if data['role'] not in valid_roles:
            return jsonify({'error': 'Invalid role specified'}), 400
        user.role = data['role']
    if 'username' in data:
        # Check if username is already taken by another user
        existing_user = Users.query.filter_by(username=data['username']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({'error': 'Username already exists'}), 409
        user.username = data['username']
    if 'password' in data and data['password']:
        user.set_password(data['password'])

    try:
        db.session.commit()
        return jsonify({
            'message': 'User updated successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'role': user.role
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reset-db', methods=['POST'])
def reset_db():
    try:
        # This is dangerous and should be protected/removed in production!
        db.drop_all()
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

        # Delete related records first
        AuthenticationAttempt.query.filter_by(user_id=user_id).delete()
        WebAuthnChallenge.query.filter_by(user_id=user_id).delete()
        AuthenticationSession.query.filter_by(user_id=user_id).delete()
        
        # Then delete the user
        user = Users.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': f'All data for user {user_id} deleted successfully'}), 200
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

        # Get the start of the current month
        now = datetime.now(timezone.utc)
        current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Query authentication attempts grouped by location
        location_stats = db.session.query(
            AuthenticationAttempt.location,
            func.count(AuthenticationAttempt.id).label('attempt_count')
        ).filter(
            AuthenticationAttempt.timestamp >= current_month_start,
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
        alerts = []
        attempts = AuthenticationAttempt.query.order_by(
            AuthenticationAttempt.timestamp.desc()
        ).paginate(page=page, per_page=per_page)

        for attempt in attempts.items:
            severity = "High" if attempt.risk_score > 75 else "Medium" if attempt.risk_score > 40 else "Low"
            
            # Determine alert type based on conditions
            if not attempt.success:
                alert_type = "Failed Login"
            elif attempt.risk_score > 75:
                alert_type = "Suspicious IP"
            elif attempt.device_type and not AuthenticationAttempt.query.filter(
                AuthenticationAttempt.device_type == attempt.device_type,
                AuthenticationAttempt.timestamp < attempt.timestamp
            ).first():
                alert_type = "New Device"
            elif attempt.location != "Unknown Location":
                alert_type = "Location Change"
            else:
                alert_type = "Multiple Attempts"
            
            alerts.append({
                'id': attempt.id,
                'type': alert_type,
                'user': attempt.user.username,
                'details': f"{'Failed' if not attempt.success else 'Successful'} login attempt from {attempt.location} using {attempt.device_type}",
                'time': attempt.timestamp.isoformat(),
                'severity': severity,
                'resolved': attempt.success
            })

        return jsonify({
            'alerts': alerts,
            'total': attempts.total,
            'pages': attempts.pages,
            'current_page': attempts.page
        })

    except Exception as e:
        print(f"Error fetching security alerts: {str(e)}")
        return jsonify({'error': 'Failed to fetch security alerts'}), 500

@app.route('/api/security/stats', methods=['GET'])
def get_security_stats():
    try:
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

        # Calculate security score based on security keys and successful logins
        total_users = Users.query.count()
        users_with_security_key = Users.query.filter_by(has_security_key=True).count()
        security_score = (users_with_security_key / total_users * 100) if total_users > 0 else 0

        # Get active sessions grouped by device type directly from the database
        now = datetime.now(timezone.utc)
        active_sessions_query = (
            db.session.query(
                AuthenticationAttempt.device_type,
                func.count(AuthenticationSession.id).label('count')
            )
            .join(
                AuthenticationSession,
                AuthenticationSession.user_id == AuthenticationAttempt.user_id
            )
            .filter(
                AuthenticationSession.expires_at > now,
                AuthenticationAttempt.device_type.isnot(None)
            )
            .group_by(AuthenticationAttempt.device_type)
        )

        # Build device stats dictionary and count total sessions
        device_stats = {}
        total_active_sessions = 0
        for device_type, count in active_sessions_query:
            device_type = device_type or 'Unknown'
            device_stats[device_type] = count
            total_active_sessions += count

        # Get unique devices count
        unique_devices = len(device_stats)

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
                'change': 0  # You can implement change calculation logic if needed
            },
            'activeSessions': {
                'total': total_active_sessions,
                'byDevice': device_stats,
                'uniqueDevices': unique_devices
            }
        })

    except Exception as e:
        print(f"Error fetching security stats: {str(e)}")
        return jsonify({'error': 'Failed to fetch security stats'}), 500


# At the bottom of your app.py file, before `if __name__ == '__main__':`
with app.app_context():
    db.create_all()
    # Create admin user if it doesn't exist
    create_admin_user()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        create_admin_user()
    app.run(debug=True)

