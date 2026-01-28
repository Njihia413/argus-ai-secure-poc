"""
File Encryption Module for Argus AI Secure

Provides AES-256-GCM encryption for files at rest.
Keys are derived from user ID + security key ID + system secret.
"""

import os
import hashlib
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Constants
KEY_LENGTH = 32  # 256 bits for AES-256
IV_LENGTH = 12   # 96 bits recommended for GCM
PBKDF2_ITERATIONS = 100_000
SALT_LENGTH = 16


def get_encryption_secret() -> bytes:
    """
    Get the system encryption secret from environment variable.
    Falls back to a default for development (NOT for production).
    """
    secret = os.environ.get('FILE_ENCRYPTION_SECRET')
    if not secret:
        # Development fallback - NEVER use in production
        secret = 'dev-only-insecure-secret-change-in-production'
    return secret.encode('utf-8')


def derive_encryption_key(user_id: int, security_key_id: int, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive a unique encryption key using PBKDF2 with SHA-256.
    
    Args:
        user_id: The user's unique identifier
        security_key_id: The security key's unique identifier
        salt: Optional salt bytes. If not provided, generates new random salt.
        
    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)
    
    # Combine user_id, security_key_id, and system secret
    secret = get_encryption_secret()
    key_material = f"{user_id}:{security_key_id}".encode('utf-8') + secret
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    
    derived_key = kdf.derive(key_material)
    return derived_key, salt


def encrypt_file(file_data: bytes, user_id: int, security_key_id: int) -> Tuple[bytes, bytes, bytes, str]:
    """
    Encrypt file data using AES-256-GCM.
    
    Args:
        file_data: Raw file bytes to encrypt
        user_id: The user's unique identifier
        security_key_id: The security key's unique identifier
        
    Returns:
        Tuple of (encrypted_data, iv, salt, file_hash)
    """
    # Derive encryption key
    key, salt = derive_encryption_key(user_id, security_key_id)
    
    # Generate random IV
    iv = secrets.token_bytes(IV_LENGTH)
    
    # Compute file hash before encryption
    file_hash = compute_file_hash(file_data, user_id, security_key_id)
    
    # Encrypt using AES-256-GCM
    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(iv, file_data, None)
    
    return encrypted_data, iv, salt, file_hash


def decrypt_file(encrypted_data: bytes, iv: bytes, salt: bytes, 
                 user_id: int, security_key_id: int) -> bytes:
    """
    Decrypt file data using AES-256-GCM.
    
    Args:
        encrypted_data: Encrypted file bytes
        iv: Initialization vector used during encryption
        salt: Salt used for key derivation
        user_id: The user's unique identifier
        security_key_id: The security key's unique identifier
        
    Returns:
        Decrypted file bytes
        
    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails (wrong key or tampered data)
    """
    # Derive the same encryption key using stored salt
    key, _ = derive_encryption_key(user_id, security_key_id, salt)
    
    # Decrypt using AES-256-GCM
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(iv, encrypted_data, None)
    
    return decrypted_data


def compute_file_hash(file_data: bytes, user_id: int, security_key_id: int) -> str:
    """
    Compute SHA-256 hash of file data with user context.
    This creates a unique hash that includes user identification.
    
    Args:
        file_data: Raw file bytes
        user_id: The user's unique identifier
        security_key_id: The security key's unique identifier
        
    Returns:
        Hexadecimal hash string
    """
    hasher = hashlib.sha256()
    
    # Include user context in hash
    context = f"{user_id}:{security_key_id}".encode('utf-8')
    hasher.update(context)
    hasher.update(file_data)
    
    return hasher.hexdigest()


def verify_file_hash(file_data: bytes, expected_hash: str, 
                     user_id: int, security_key_id: int) -> bool:
    """
    Verify that file data matches expected hash.
    
    Args:
        file_data: Raw file bytes
        expected_hash: The expected hash value
        user_id: The user's unique identifier
        security_key_id: The security key's unique identifier
        
    Returns:
        True if hash matches, False otherwise
    """
    computed_hash = compute_file_hash(file_data, user_id, security_key_id)
    return secrets.compare_digest(computed_hash, expected_hash)


def get_encrypted_files_path() -> str:
    """
    Get the path to store encrypted files.
    Creates directory if it doesn't exist.
    """
    path = os.environ.get('ENCRYPTED_FILES_PATH', 
                          os.path.join(os.path.dirname(__file__), 'encrypted_files'))
    
    if not os.path.exists(path):
        os.makedirs(path, mode=0o700)  # Only owner can access
    
    return path


def generate_storage_filename() -> str:
    """
    Generate a unique filename for storing encrypted files.
    Uses random bytes to prevent filename enumeration.
    """
    return secrets.token_hex(32)
