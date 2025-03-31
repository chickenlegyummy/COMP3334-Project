import os
import base64
import hashlib

class Crypto:
    def __init__(self):
        self.salt_size = 16
    
    def _generate_key(self, length=32):
        """Generate a random key of specified length"""
        return os.urandom(length)
    
    def _derive_key_from_bytes(self, key_bytes):
        """Convert raw key bytes to a usable key for encryption"""
        # Use SHA-256 to derive a consistent key from the raw bytes
        return hashlib.sha256(key_bytes).digest()
    
    def _xor_encrypt(self, data, key):
        """XOR-based encryption with key rotation"""
        encrypted = bytearray(len(data))
        for i in range(len(data)):
            encrypted[i] = data[i] ^ key[i % len(key)]
        return bytes(encrypted)
    
    def encrypt(self, data):
        # Generate a random salt
        salt = os.urandom(self.salt_size)
        
        # Generate a key
        key = self._generate_key()
        derived_key = self._derive_key_from_bytes(key)
        
        # Encrypt the data with the key
        encrypted_data = self._xor_encrypt(data, derived_key)
        
        # Prepend the salt to the encrypted data
        final_data = salt + encrypted_data
        
        # Encode the final data as base64 for better handling
        encoded_data = base64.b64encode(final_data)
        
        # Return the encoded data and the key (also encoded for consistency)
        return encoded_data, base64.b64encode(key)
    
    def decrypt(self, encrypted_data, key):
        try:
            # Decode from base64
            decoded_data = base64.b64decode(encrypted_data)
            decoded_key = base64.b64decode(key)
            
            # Extract the salt
            salt = decoded_data[:self.salt_size]
            actual_data = decoded_data[self.salt_size:]
            
            # Derive the key from the provided key bytes
            derived_key = self._derive_key_from_bytes(decoded_key)
            
            # Decrypt using XOR with the derived key
            decrypted_data = self._xor_encrypt(actual_data, derived_key)
            
            return decrypted_data
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")