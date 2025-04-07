import os
import hmac
import hashlib
import secrets
import base64

class HMAC_SHA256:
    """HMAC-SHA256 operations for secure message authentication"""
    
    @staticmethod
    def create(key, message):
        """
        Create an HMAC using SHA-256
        
        Args:
            key (bytes or str): The key for HMAC
            message (bytes or str): The message to authenticate
            
        Returns:
            str: Hex digest of the HMAC
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        return hmac.new(key, message, hashlib.sha256).hexdigest()
    
    @staticmethod
    def verify(key, message, signature):
        """
        Verify an HMAC signature
        
        Args:
            key (bytes or str): The key for HMAC
            message (bytes or str): The message that was authenticated
            signature (str): The HMAC signature to verify
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        calculated = HMAC_SHA256.create(key, message)
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(calculated, signature)

class SecurePRNG:
    """Cryptographically secure pseudorandom number generator"""
    
    @staticmethod
    def generate_bytes(length=32):
        """
        Generate cryptographically secure random bytes
        
        Args:
            length (int): Number of bytes to generate
            
        Returns:
            bytes: Random bytes
        """
        return os.urandom(length)
    
    @staticmethod
    def generate_hex(length=32):
        """
        Generate a random hex string
        
        Args:
            length (int): Number of bytes (hex string will be twice this length)
            
        Returns:
            str: Random hex string
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_salt(length=16):
        """
        Generate a random salt
        
        Args:
            length (int): Length of the salt in bytes
            
        Returns:
            bytes: Random salt
        """
        return os.urandom(length)
    
    @staticmethod
    def generate_token(length=32):
        """
        Generate a URL-safe token
        
        Args:
            length (int): Number of bytes (token will be longer due to base64 encoding)
            
        Returns:
            str: URL-safe token
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_password(length=16):
        """
        Generate a strong random password
        
        Args:
            length (int): Length of password
            
        Returns:
            str: Random password
        """
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

# Utility function to derive encryption keys securely
def derive_key_hmac(password, salt=None, iterations=100000, key_length=32):
    """
    Derive a key from a password using PBKDF2-HMAC-SHA256
    
    Args:
        password (str): Password to derive key from
        salt (bytes, optional): Salt for key derivation
        iterations (int): Number of iterations
        key_length (int): Length of the derived key
        
    Returns:
        tuple: (key, salt) - both are bytes
    """
    if salt is None:
        salt = SecurePRNG.generate_salt()
    
    if isinstance(password, str):
        password = password.encode('utf-8')
        
    # Use hashlib's pbkdf2_hmac for key derivation
    key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations, key_length)
    
    return key, salt

# Utility function for secure file integrity verification
def file_hmac(file_path, key):
    """
    Create HMAC for a file
    
    Args:
        file_path (str): Path to the file
        key (bytes or str): Key for HMAC
        
    Returns:
        str: HMAC digest
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
        
    h = hmac.new(key, None, hashlib.sha256)
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
            
    return h.hexdigest()