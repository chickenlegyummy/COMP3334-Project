import sqlite3
import hashlib
import os
import time
import uuid
import re
from datetime import datetime, timedelta
from src.common.totp import TOTP  # Import our custom TOTP implementation
from src.common.security import SecurityUtils

class UserManager:
    def __init__(self):
        self.db_path = "users.db"
        self.setup_db()
    
    def setup_db(self):
        """Set up the SQLite database with proper schema"""
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
                status TEXT DEFAULT 'active',
                failed_attempts INTEGER DEFAULT 0,
                lockout_until TIMESTAMP
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
                ip_address TEXT,
                user_agent TEXT
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
        """
        Verify user credentials with account lockout protection
        
        Args:
            username (str): Username to verify
            password (str): Password to verify
            
        Returns:
            tuple: (success, role, has_mfa, mfa_secret)
        """
        # Sanitize inputs to prevent SQL injection
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            return (False, "guest", False, None)
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check if account is locked
        c.execute("SELECT lockout_until FROM users WHERE username = ?", (username,))
        lockout_result = c.fetchone()
        
        if lockout_result and lockout_result[0]:
            lockout_time = datetime.strptime(lockout_result[0], "%Y-%m-%d %H:%M:%S")
            if datetime.now() < lockout_time:
                conn.close()
                return (False, "guest", False, None)  # Account is locked
        
        # Hash password for comparison
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Verify credentials
        c.execute("SELECT password, role, mfa_secret, failed_attempts FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        
        if not result:
            conn.close()
            return (False, "guest", False, None)
        
        stored_hash, role, mfa_secret, failed_attempts = result
        
        if stored_hash == password_hash:
            # Success - reset failed attempts and update last login
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("UPDATE users SET last_login = ?, failed_attempts = 0, lockout_until = NULL WHERE username = ?", 
                     (current_time, username))
            conn.commit()
            
            # Check if MFA is enabled
            has_mfa = mfa_secret is not None and mfa_secret != ""
            
            conn.close()
            return (True, role, has_mfa, mfa_secret if has_mfa else None)
        else:
            # Failed login - increment failed attempts
            new_failed_attempts = (failed_attempts or 0) + 1
            
            # Lock account after 5 failed attempts for 15 minutes
            lockout_until = None
            if new_failed_attempts >= 5:
                lockout_until = (datetime.now() + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
            
            c.execute("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?", 
                     (new_failed_attempts, lockout_until, username))
            conn.commit()
            conn.close()
            
            return (False, "guest", False, None)
    
    def verify_mfa(self, username, code):
        """
        Verify MFA code using custom TOTP implementation
        
        Args:
            username (str): Username to verify MFA for
            code (str): TOTP code to verify
            
        Returns:
            bool: True if code is valid, False otherwise
        """
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username) or not code.isdigit():
            return False
            
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        
        if not result or not result[0]:
            return False
        
        # Verify TOTP code using our custom implementation
        totp = TOTP(secret=result[0])
        return totp.verify(code)
    
    def register_user(self, username, password, email, role="normal", mfa_secret=None):
        """
        Register a new user with security validation
        
        Args:
            username (str): New username
            password (str): Password
            email (str): Email address
            role (str): User role (default: normal)
            mfa_secret (str, optional): MFA secret if enabled
            
        Returns:
            tuple: (success, message)
        """
        # Validate inputs
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            return False, "Username contains invalid characters or length"
            
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return False, "Invalid email format"
            
        # Validate password strength
        is_strong, message = SecurityUtils.is_password_strong(password)
        if not is_strong:
            return False, message
            
        # Validate role
        if role not in ["admin", "normal", "guest"]:
            role = "normal"  # Default to normal if invalid
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check if username already exists
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return False, "Username already exists"
        
        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Insert the new user using parameterized query
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
        """
        Update a user's password with security validation
        
        Args:
            username (str): Username to update
            new_password (str): New password
            
        Returns:
            tuple: (success, message)
        """
        # Validate username
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            return False, "Invalid username format"
            
        # Validate password strength
        is_strong, message = SecurityUtils.is_password_strong(new_password)
        if not is_strong:
            return False, message
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check if user exists
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not c.fetchone():
            conn.close()
            return False, "User not found"
        
        # Hash the new password
        password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        try:
            c.execute("UPDATE users SET password = ?, failed_attempts = 0, lockout_until = NULL WHERE username = ?", 
                     (password_hash, username))
            conn.commit()
            conn.close()
            return True, "Password updated successfully"
        except Exception as e:
            conn.close()
            return False, f"Password update failed: {str(e)}"
    
    def verify_current_password(self, username, current_password):
        """
        Verify if the provided current password is correct
        
        Args:
            username (str): Username to verify
            current_password (str): Current password to verify
            
        Returns:
            tuple: (success, message)
        """
        # Validate username
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            return False, "Invalid username format"
        
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
        """
        Create a password reset token with security validation
        
        Args:
            username (str): Username requesting reset
            email (str): Email to verify
            
        Returns:
            tuple: (success, token or message)
        """
        # Validate inputs
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            return False, "Invalid username format"
            
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return False, "Invalid email format"
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Verify username and email match
        c.execute("SELECT email FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        
        if not result or result[0] != email:
            conn.close()
            return False, "Username or email is incorrect"
        
        # Generate secure reset token and set expiry (24 hours from now)
        token = SecurityUtils.generate_secure_token()
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
        """
        Verify if a reset token is valid and not expired
        
        Args:
            token (str): Token to verify
            
        Returns:
            tuple: (valid, message, username)
        """
        # Validate token format (prevent SQL injection)
        if not re.match(r'^[0-9a-f]{32,64}$', token):
            return False, "Invalid token format", None
        
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
        """
        Use a reset token to update password
        
        Args:
            token (str): Token to use
            new_password (str): New password
            
        Returns:
            tuple: (success, message)
        """
        # Validate token format
        if not re.match(r'^[0-9a-f]{32,64}$', token):
            return False, "Invalid token format"
            
        # Validate password strength
        is_strong, message = SecurityUtils.is_password_strong(new_password)
        if not is_strong:
            return False, message
        
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
        """
        Enable MFA for a user
        
        Args:
            username (str): Username to enable MFA for
            
        Returns:
            tuple: (success, secret or message)
        """
        # Validate username
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            return False, "Invalid username format"
        
        # Use our custom TOTP implementation
        totp = TOTP()
        mfa_secret = totp.secret
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check if user exists
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not c.fetchone():
            conn.close()
            return False, "User not found"
        
        try:
            c.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (mfa_secret, username))
            conn.commit()
            conn.close()
            return True, mfa_secret
        except Exception as e:
            conn.close()
            return False, f"Failed to enable MFA: {str(e)}"
    
    def disable_mfa(self, username):
        """
        Disable MFA for a user
        
        Args:
            username (str): Username to disable MFA for
            
        Returns:
            tuple: (success, message)
        """
        # Validate username
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            return False, "Invalid username format"
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check if user exists
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not c.fetchone():
            conn.close()
            return False, "User not found"
        
        try:
            c.execute("UPDATE users SET mfa_secret = NULL WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            return True, "MFA disabled successfully"
        except Exception as e:
            conn.close()
            return False, f"Failed to disable MFA: {str(e)}"
    
    def log_audit(self, username, action, ip_address=None, user_agent=None):
        """
        Log user actions for auditing
        
        Args:
            username (str): Username performing the action
            action (str): Action being performed
            ip_address (str, optional): IP address
            user_agent (str, optional): User agent string
            
        Returns:
            bool: Success or failure
        """
        # Validate username
        if username and not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            username = "unknown"  # Use safe default
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            c.execute("INSERT INTO login_audit (username, timestamp, action, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)",
                     (username, timestamp, action, ip_address, user_agent))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            conn.close()
            print(f"Failed to log audit: {str(e)}")
            return False