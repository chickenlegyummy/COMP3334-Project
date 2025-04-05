import sqlite3
import hashlib
import os
import pyotp
import time
import uuid
from datetime import datetime, timedelta

class UserManager:
    def __init__(self):
        self.db_path = "users.db"
        self.setup_db()
    
    def setup_db(self):
        if not os.path.exists(self.db_path):
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Create improved users table with email and MFA fields
            c.execute('''CREATE TABLE users (
                username TEXT PRIMARY KEY, 
                password TEXT, 
                role TEXT,
                email TEXT,
                mfa_secret TEXT,
                last_login TIMESTAMP,
                status TEXT DEFAULT 'active'
            )''')
            
            # Create password reset tokens table
            c.execute('''CREATE TABLE reset_tokens (
                token TEXT PRIMARY KEY,
                username TEXT,
                expiry TIMESTAMP,
                used INTEGER DEFAULT 0
            )''')
            
            # Create login_audit table
            c.execute('''CREATE TABLE login_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                timestamp TIMESTAMP,
                action TEXT,
                ip_address TEXT
            )''')
            
            # Default admin user
            admin_hash = hashlib.sha256("adminpassword".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", 
                     ("admin", admin_hash, "admin", "admin@example.com"))
            
            # Default normal user: test
            test_hash = hashlib.sha256("password".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", 
                     ("test", test_hash, "normal", "test@example.com"))
            
            # New normal user: test2
            test2_hash = hashlib.sha256("test2pass".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", 
                     ("test2", test2_hash, "normal", "test2@example.com"))
            
            # Default guest user
            guest_hash = hashlib.sha256("guestpass".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", 
                     ("guest", guest_hash, "guest", "guest@example.com"))
            
            conn.commit()
            conn.close()
            print("Default users created: admin (admin/adminpassword), test (test/password), test2 (test2/test2pass), guest (guest/guestpass)")
    
    def verify_user(self, username, password):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT password, role, mfa_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        
        if result and result[0] == password_hash:
            # Update last login timestamp
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("UPDATE users SET last_login = ? WHERE username = ?", (current_time, username))
            conn.commit()
            
            # Check if MFA is enabled
            has_mfa = result[2] is not None and result[2] != ""
            
            conn.close()
            return (True, result[1], has_mfa, result[2] if has_mfa else None)
        
        conn.close()
        return (False, "guest", False, None)
    
    def verify_mfa(self, username, code):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        
        if not result or not result[0]:
            return False
        
        # Verify TOTP code
        totp = pyotp.TOTP(result[0])
        return totp.verify(code)
    
    def register_user(self, username, password, email, role="normal", mfa_secret=None):
        """Register a new user with optional MFA"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check if username already exists
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return False, "Username already exists"
        
        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Insert the new user
        try:
            c.execute("INSERT INTO users (username, password, role, email, mfa_secret) VALUES (?, ?, ?, ?, ?)", 
                     (username, password_hash, role, email, mfa_secret))
            conn.commit()
            conn.close()
            return True, "User registered successfully"
        except Exception as e:
            conn.close()
            return False, f"Registration failed: {str(e)}"
    
    def update_password(self, username, new_password):
        """Update a user's password"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Hash the new password
        password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        try:
            c.execute("UPDATE users SET password = ? WHERE username = ?", (password_hash, username))
            conn.commit()
            conn.close()
            return True, "Password updated successfully"
        except Exception as e:
            conn.close()
            return False, f"Password update failed: {str(e)}"
    
    def verify_current_password(self, username, current_password):
        """Verify if the provided current password is correct"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Hash the provided password
        password_hash = hashlib.sha256(current_password.encode()).hexdigest()
        
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        
        if not result:
            return False, "User not found"
        
        return result[0] == password_hash, "Password verification" + (" successful" if result[0] == password_hash else " failed")
    
    def create_reset_token(self, username, email):
        """Create a password reset token"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Verify username and email match
        c.execute("SELECT email FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        
        if not result or result[0] != email:
            conn.close()
            return False, "Username or email is incorrect"
        
        # Generate reset token and set expiry (24 hours from now)
        token = str(uuid.uuid4())
        expiry = (datetime.now() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Clean up old tokens for this user
            c.execute("DELETE FROM reset_tokens WHERE username = ? OR expiry < datetime('now')", (username,))
            
            # Create new token
            c.execute("INSERT INTO reset_tokens (token, username, expiry) VALUES (?, ?, ?)", 
                     (token, username, expiry))
            conn.commit()
            conn.close()
            return True, token
        except Exception as e:
            conn.close()
            return False, f"Failed to create reset token: {str(e)}"
    
    def verify_reset_token(self, token):
        """Verify if a reset token is valid and not expired"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("SELECT username, expiry, used FROM reset_tokens WHERE token = ?", (token,))
        result = c.fetchone()
        
        if not result:
            conn.close()
            return False, "Invalid token", None
        
        username, expiry, used = result
        
        # Check if token is expired
        if datetime.now() > datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S"):
            conn.close()
            return False, "Token expired", None
        
        # Check if token has been used
        if used == 1:
            conn.close()
            return False, "Token already used", None
        
        conn.close()
        return True, "Valid token", username
    
    def use_reset_token(self, token, new_password):
        """Use a reset token to update password"""
        valid, message, username = self.verify_reset_token(token)
        
        if not valid:
            return False, message
        
        # Update password
        password_updated, update_message = self.update_password(username, new_password)
        
        if password_updated:
            # Mark token as used
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("UPDATE reset_tokens SET used = 1 WHERE token = ?", (token,))
            conn.commit()
            conn.close()
            
            return True, "Password reset successfully"
        else:
            return False, update_message
    
    def enable_mfa(self, username):
        """Enable MFA for a user"""
        mfa_secret = pyotp.random_base32()
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (mfa_secret, username))
            conn.commit()
            conn.close()
            return True, mfa_secret
        except Exception as e:
            conn.close()
            return False, f"Failed to enable MFA: {str(e)}"
    
    def disable_mfa(self, username):
        """Disable MFA for a user"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("UPDATE users SET mfa_secret = NULL WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            return True, "MFA disabled successfully"
        except Exception as e:
            conn.close()
            return False, f"Failed to disable MFA: {str(e)}"
    
    def log_audit(self, username, action, ip_address=None):
        """Log user actions for auditing"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            c.execute("INSERT INTO login_audit (username, timestamp, action, ip_address) VALUES (?, ?, ?, ?)",
                     (username, timestamp, action, ip_address))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            conn.close()
            print(f"Failed to log audit: {str(e)}")
            return False