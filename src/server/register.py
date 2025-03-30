import sqlite3
import hashlib
import os
from src.server.user_manager import UserManager  # Import UserManager for consistency

class Register:
    def __init__(self):
        self.db_path = "users.db"
        # Ensure the database is initialized (runs UserManager's setup if db doesn't exist)
        self.user_manager = UserManager()
    
    def register_user(self, username, password, role):
        """Add a new user to the database."""
        try:
            # Validate role
            valid_roles = ["admin", "normal", "guest"]
            if role not in valid_roles:
                raise ValueError(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
            
            # Hash the password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Connect to the database
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Check if username already exists
            c.execute("SELECT username FROM users WHERE username = ?", (username,))
            if c.fetchone():
                raise ValueError(f"Username '{username}' already exists.")
            
            # Insert the new user
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                     (username, password_hash, role))
            conn.commit()
            print(f"User '{username}' registered successfully with role '{role}'!")
        
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except ValueError as e:
            print(f"Error: {e}")
        finally:
            if 'conn' in locals():
                conn.close()

def main():
    print("Admin User Registration Tool")
    print("----------------------------")
    register = Register()
    
    while True:
        try:
            username = input("Enter username (or 'exit' to quit): ").strip()
            if username.lower() == "exit":
                break
            if not username:
                print("Username cannot be empty.")
                continue
            
            password = input("Enter password: ").strip()
            if not password:
                print("Password cannot be empty.")
                continue
            
            role = input("Enter role (admin/normal/guest): ").lower().strip()
            register.register_user(username, password, role)
        
        except KeyboardInterrupt:
            print("\nExiting registration tool.")
            break
        except Exception as e:
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()