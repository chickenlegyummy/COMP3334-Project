from cryptography.fernet import Fernet

class Crypto:
    def __init__(self):
        pass  # No key stored here; key is generated per operation
    
    def encrypt(self, data):
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        return encrypted_data, key  # Return both encrypted data and key
    
    def decrypt(self, data, key):
        fernet = Fernet(key)
        return fernet.decrypt(data)