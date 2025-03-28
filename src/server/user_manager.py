from .database import Database
import hashlib

class UserManager:
    def __init__(self):
        self.db = Database("users.db")
        # Create default user for testing
        result = self.db.create_user("test", hashlib.sha256("password".encode()).hexdigest())
        print(f"User 'test' creation: {'Success' if result else 'Failed (already exists)'}")
    
    def verify_user(self, username, password):
        stored_password = self.db.get_user(username)
        if stored_password:
            provided_hash = hashlib.sha256(password.encode()).hexdigest()
            print(f"Verifying {username}: Stored={stored_password}, Provided={provided_hash}")
            return stored_password == provided_hash
        print(f"User {username} not found in database")
        return False