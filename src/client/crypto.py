import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Crypto:
    """Secure cryptographic operations using AES-GCM"""
    
    def __init__(self):
        self.key_size = 32  # AES-256
    
    def generate_key(self):
        """Generate a cryptographically secure random key"""
        return os.urandom(self.key_size)
    
    def derive_key(self, password, salt=None):
        """
        Derive a key from a password using PBKDF2
        
        Args:
            password (str): Password to derive key from
            salt (bytes, optional): Salt for key derivation
            
        Returns:
            tuple: (key, salt) - both are bytes
        """
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    def encrypt(self, data, password=None):
        """
        Encrypt data with AES-GCM
        
        Args:
            data (bytes): Data to encrypt
            password (str, optional): If provided, derive key from password
            
        Returns:
            tuple: (encrypted_data, key) - key is base64 encoded
        """
        # Generate key
        if password:
            key, salt = self.derive_key(password)
            # Include salt in the encrypted data
            key_data = salt + key
        else:
            key = self.generate_key()
            key_data = key
            
        # Generate random nonce (12 bytes for AES-GCM)
        nonce = os.urandom(12)
        
        # Create cipher and encrypt
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        
        # Combine nonce and ciphertext for storage/transmission
        encrypted_data = nonce + ciphertext
        
        return encrypted_data, base64.b64encode(key_data)
    
    def decrypt(self, encrypted_data, key_b64):
        """
        Decrypt data
        
        Args:
            encrypted_data (bytes): Data to decrypt (nonce + ciphertext)
            key_b64 (bytes): Base64 encoded key
            
        Returns:
            bytes: Decrypted data
        """
        # Decode key
        key_data = base64.b64decode(key_b64)
        
        # Check if key includes salt (for password-derived keys)
        if len(key_data) > self.key_size:
            # First 16 bytes are salt, rest is the key
            key = key_data[16:]
        else:
            key = key_data
        
        # Extract nonce (first 12 bytes)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Create cipher and decrypt
        try:
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")