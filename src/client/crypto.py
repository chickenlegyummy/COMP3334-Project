import os
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
        return hashlib.sha256(os.urandom(length)).hexdigest()[:length*2]
    
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
        Generate a random token
        
        Args:
            length (int): Number of bytes
            
        Returns:
            str: Random token as hex string
        """
        return hashlib.sha256(os.urandom(length)).hexdigest()

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

class Crypto:
    """Secure cryptographic operations using AES-GCM with HMAC-SHA256 for integrity"""
    
    def __init__(self):
        self.key_size = 32  # AES-256
    
    def generate_key(self):
        """Generate a cryptographically secure random key"""
        return SecurePRNG.generate_bytes(self.key_size)
    
    def derive_key(self, password, salt=None):
        """
        Derive a key from a password using PBKDF2-HMAC-SHA256
        
        Args:
            password (str): Password to derive key from
            salt (bytes, optional): Salt for key derivation
            
        Returns:
            tuple: (key, salt) - both are bytes
        """
        if salt is None:
            salt = SecurePRNG.generate_salt()
            
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
        Encrypt data with AES-GCM and add HMAC-SHA256 for integrity verification
        
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
            
            # Generate an HMAC for integrity verification
            integrity_key = SecurePRNG.generate_bytes(16)
            integrity_check = HMAC_SHA256.create(integrity_key, data)
            key_data = key_data + integrity_key + integrity_check.encode()
        else:
            key = self.generate_key()
            
            # Generate an HMAC for integrity verification
            integrity_key = SecurePRNG.generate_bytes(16)
            integrity_check = HMAC_SHA256.create(integrity_key, data)
            
            # Combine key with integrity information
            key_data = key + integrity_key + integrity_check.encode()
            
        # Generate random nonce (12 bytes for AES-GCM)
        nonce = SecurePRNG.generate_bytes(12)
        
        # Create cipher and encrypt
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        
        # Combine nonce and ciphertext for storage/transmission
        encrypted_data = nonce + ciphertext
        
        return encrypted_data, base64.b64encode(key_data)
    
    def decrypt(self, encrypted_data, key_b64):
        """
        Decrypt data and verify integrity with HMAC-SHA256
        
        Args:
            encrypted_data (bytes): Data to decrypt (nonce + ciphertext)
            key_b64 (bytes): Base64 encoded key
            
        Returns:
            bytes: Decrypted data
        """
        # Decode key
        key_data = base64.b64decode(key_b64)
        
        # Extract component parts depending on format
        # Newer format with integrity verification
        if len(key_data) > self.key_size + 16:
            if len(key_data) > self.key_size + 16 + 64:  # With salt for password-derived keys
                # Format: salt(16) + key(32) + integrity_key(16) + hmac(64)
                salt = key_data[:16]
                key = key_data[16:48]
                integrity_key = key_data[48:64]
                stored_hmac = key_data[64:].decode()
            else:
                # Format: key(32) + integrity_key(16) + hmac(64)
                key = key_data[:32]
                integrity_key = key_data[32:48]
                stored_hmac = key_data[48:].decode()
        # Original format without integrity verification
        elif len(key_data) > self.key_size:
            # Format: salt(16) + key(32)
            salt = key_data[:16]
            key = key_data[16:]
            integrity_key = None
            stored_hmac = None
        else:
            # Format: key(32)
            key = key_data
            integrity_key = None
            stored_hmac = None
        
        # Extract nonce (first 12 bytes)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Create cipher and decrypt
        try:
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            
            # Verify integrity if we have an integrity check
            if integrity_key and stored_hmac:
                calculated_hmac = HMAC_SHA256.create(integrity_key, plaintext)
                if not hmac.compare_digest(calculated_hmac, stored_hmac):
                    raise Exception("Data integrity check failed - file may have been tampered with")
                    
            return plaintext
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
    
    def file_hmac(self, filepath, key=None):
        """
        Calculate HMAC-SHA256 for a file
        
        Args:
            filepath (str): Path to file
            key (bytes, optional): Key for HMAC, generates one if not provided
            
        Returns:
            tuple: (hmac_digest, key)
        """
        if key is None:
            key = self.generate_key()
            
        h = hmac.new(key, None, hashlib.sha256)
        
        with open(filepath, 'rb') as f:
            chunk = f.read(4096)
            while chunk:
                h.update(chunk)
                chunk = f.read(4096)
                
        return h.hexdigest(), key
    
    def verify_file_hmac(self, filepath, key, hmac_digest):
        """
        Verify HMAC-SHA256 for a file
        
        Args:
            filepath (str): Path to file
            key (bytes): Key used for HMAC
            hmac_digest (str): Expected HMAC digest
            
        Returns:
            bool: True if HMAC matches
        """
        calculated_hmac, _ = self.file_hmac(filepath, key)
        return hmac.compare_digest(calculated_hmac, hmac_digest)
    
    def secure_delete_file(self, filepath):
        """
        Securely delete a file by overwriting with random data
        
        Args:
            filepath (str): Path to file
            
        Returns:
            bool: True if successful
        """
        try:
            # Get file size
            file_size = os.path.getsize(filepath)
            
            # Open and overwrite file
            with open(filepath, 'wb') as f:
                # Overwrite with random data in chunks of 1MB to handle large files
                chunk_size = 1024 * 1024  # 1MB
                remaining = file_size
                
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(SecurePRNG.generate_bytes(write_size))
                    remaining -= write_size
                    
                # Force flush to disk
                f.flush()
                os.fsync(f.fileno())
                
            # Delete the file
            os.remove(filepath)
            return True
        except Exception as e:
            # If secure delete fails, try regular delete
            try:
                os.remove(filepath)
                return True
            except:
                return False