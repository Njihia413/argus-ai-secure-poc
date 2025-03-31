import json
import hashlib
import secrets
from datetime import datetime, timedelta
import uuid

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
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


# User model renamed to Users and with additional fields
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)  # Added first name
    last_name = db.Column(db.String(100), nullable=False)  # Added last name
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)  # Optional for passwordless auth

    # User timezone for risk-based authentication
    timezone = db.Column(db.String(50), default='UTC')
    last_login_time = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    failed_login_attempts = db.Column(db.Integer, default=0)
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
        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()

    # Check if account is locked
    # Update these methods in the Users class

    def is_account_locked(self):
        """Check if account is locked and return boolean"""
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False

    def get_lock_details(self):
        """Get detailed information about account lock status"""
        if not self.is_account_locked():
            return {
                "locked": False
            }

        now = datetime.utcnow()
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expired = db.Column(db.Boolean, default=False)
    # Add a new field to track if this challenge is for a second factor authentication
    is_second_factor = db.Column(db.Boolean, default=False)

    user = db.relationship('Users', backref=db.backref('challenges', lazy=True))


# Add a new model to track authentication stages
class AuthenticationSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    password_verified = db.Column(db.Boolean, default=False)
    security_key_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(minutes=15))
    session_token = db.Column(db.String(100), unique=True, default=lambda: str(uuid.uuid4()))
    # Token binding fields
    client_binding = db.Column(db.String(255))
    binding_nonce = db.Column(db.String(100))
    # Risk assessment fields
    risk_score = db.Column(db.Integer, default=0)
    requires_additional_verification = db.Column(db.Boolean, default=False)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('Users', backref=db.backref('auth_sessions', lazy=True))

    def validate_binding(self, request_binding):
        # Simple time-based expiration check
        if datetime.utcnow() > self.expires_at:
            return False

        # Validate the binding data matches
        return secrets.compare_digest(self.client_binding, request_binding)

    def update_last_used(self):
        self.last_used = datetime.utcnow()
        db.session.commit()


# Model to track authentication attempts for risk-based authentication
class AuthenticationAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    auth_type = db.Column(db.String(50))  # 'password', 'webauthn', etc.
    risk_score = db.Column(db.Integer, default=0)
    location = db.Column(db.String(255))  # For storing geolocation data

    user = db.relationship('Users', backref=db.backref('auth_attempts', lazy=True))


# Configure WebAuthn
rp = PublicKeyCredentialRpEntity(name="Athens AI", id="localhost")
server = Fido2Server(rp)


# Helper Functions for Security Enhancements

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
    if datetime.utcnow() > auth_session.expires_at:
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
        AuthenticationAttempt.timestamp > datetime.utcnow() - timedelta(hours=24)
    ).count()

    failed_risk = min(recent_failed_attempts * 10, 40)  # Cap at 40
    risk_score += failed_risk
    if failed_risk > 0:
        print(f"Risk: +{failed_risk} for {recent_failed_attempts} recent failed attempts")

    # 3. Check for unusual timing
    user_timezone = user.timezone or 'UTC'  # Assuming you store user's timezone
    current_hour = datetime.utcnow().hour
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

    # 6. Check for rapid authentication from different locations
    if user.last_login_time:
        time_since_last_login = datetime.utcnow() - user.last_login_time
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


# Updated route for user registration with first and last name
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    # Check if all required fields are provided
    if not data or not data.get('username') or not data.get('password') or \
            not data.get('firstName') or not data.get('lastName'):
        return jsonify({'error': 'Missing required fields (firstName, lastName, username, or password)'}), 400

    if Users.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409

    user = Users(
        first_name=data['firstName'],
        last_name=data['lastName'],
        username=data['username']
    )
    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    # Record this event
    auth_attempt = AuthenticationAttempt(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
        auth_type='registration',
        success=True
    )
    db.session.add(auth_attempt)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    user = Users.query.filter_by(username=data['username']).first()

    # Check if user exists first before creating authentication attempt
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Create a new authentication attempt record after confirming user exists
    auth_attempt = AuthenticationAttempt(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
        auth_type='password',
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

    # Reset failed login attempts
    user.reset_failed_attempts()

    # Update login history
    user.last_login_time = datetime.utcnow()
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

    # Check if user has a security key registered
    has_security_key = bool(user.credential_id)

    if not has_security_key:
        # User needs to register a security key first
        return jsonify({
            'message': 'Password verified, but you need to register a security key to fully access your account',
            'user_id': user.id,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'has_security_key': False,
            'auth_token': auth_session.session_token,
            'binding_nonce': binding_nonce,
            'risk_score': risk_score,
            'requires_additional_verification': risk_score > 50
        }), 200
    else:
        # User has a security key, so they need to use it as a second factor
        return jsonify({
            'message': 'Password verified. Please complete authentication with your security key',
            'user_id': user.id,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'has_security_key': True,
            'auth_token': auth_session.session_token,
            'binding_nonce': binding_nonce,
            'risk_score': risk_score,
            'requires_additional_verification': risk_score > 50
        }), 200

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

            # Store credential information
            public_key = cbor.encode(auth_data.credential_data.public_key)
            sign_count = auth_data.counter

            user.credential_id = credential_id
            user.public_key = base64.b64encode(public_key).decode('utf-8')
            user.sign_count = sign_count

            db.session.commit()

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
        'auth_stage': 'none'
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
        AuthenticationAttempt.timestamp > datetime.utcnow() - timedelta(days=7)
    ).count()

    if recent_failed > 3:
        recommendations.append({
            'type': 'warning',
            'message': f'There have been {recent_failed} failed login attempts on your account in the last 7 days.',
            'action': 'Review activity and consider updating your password.'
        })

    # Check for logins from unusual locations
    distinct_ips = db.session.query(AuthenticationAttempt.ip_address).filter_by(
        user_id=user.id,
        success=True
    ).filter(
        AuthenticationAttempt.timestamp > datetime.utcnow() - timedelta(days=30)
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

@app.route('/api/reset-db', methods=['POST'])
def reset_db():
    try:
        # This is dangerous and should be protected/removed in production!
        db.drop_all()
        db.create_all()
        return jsonify({'message': 'Database reset successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# At the bottom of your app.py file, before `if __name__ == '__main__':`
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)