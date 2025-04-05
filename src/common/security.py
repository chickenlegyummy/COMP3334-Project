import os
import re
import time
import secrets
import string

class SecurityUtils:
    @staticmethod
    def sanitize_filename(filename):
        """
        Sanitize a filename to prevent path traversal attacks.
        
        Args:
            filename (str): The filename to sanitize
            
        Returns:
            str: A sanitized filename with unsafe characters removed
        """
        # Remove any directory traversal attempts
        sanitized = os.path.basename(filename)
        
        # Remove any null bytes
        sanitized = sanitized.replace('\0', '')
        
        # Additional sanitization
        # Only allow alphanumeric characters, dots, dashes, and underscores
        sanitized = re.sub(r'[^\w\.\-]', '_', sanitized)
        
        # Don't allow hidden files (files starting with .)
        if sanitized.startswith('.'):
            sanitized = '_' + sanitized[1:]
            
        # Ensure the filename is not empty after sanitization
        if not sanitized:
            sanitized = "unnamed_file"
            
        return sanitized
    
    @staticmethod
    def is_password_strong(password):
        """
        Check if a password meets the strength requirements.
        
        Args:
            password (str): The password to check
            
        Returns:
            tuple: (bool, str) - (True if strong, message)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        # Check for at least one uppercase, lowercase, digit, and special char
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            return False, "Password must contain uppercase, lowercase, digit, and special characters"
        
        return True, "Password is strong"
    
    @staticmethod
    def generate_secure_token(length=32):
        """
        Generate a cryptographically secure random token.
        
        Args:
            length (int): Length of the token
            
        Returns:
            str: A random token
        """
        return secrets.token_hex(length // 2)

class RateLimiter:
    """Rate limiting implementation for protection against brute force attacks"""
    def __init__(self, max_attempts=5, window_seconds=60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = {}  # IP: [(timestamp, endpoint), ...]
    
    def check_limit(self, ip, endpoint):
        """
        Check if IP has exceeded rate limit for an endpoint
        
        Args:
            ip (str): The IP address
            endpoint (str): The endpoint or action being accessed
            
        Returns:
            bool: True if rate limit exceeded, False otherwise
        """
        now = time.time()
        
        # Clean up old entries
        if ip in self.attempts:
            self.attempts[ip] = [
                attempt for attempt in self.attempts[ip]
                if now - attempt[0] < self.window_seconds
            ]
        
        # Count attempts for this endpoint
        count = sum(1 for attempt in self.attempts.get(ip, []) 
                    if attempt[1] == endpoint)
        
        # Add this attempt
        if ip not in self.attempts:
            self.attempts[ip] = []
        self.attempts[ip].append((now, endpoint))
        
        # Check if over limit
        return count >= self.max_attempts
    
    def reset_for_ip(self, ip):
        """Reset attempts for a specific IP"""
        if ip in self.attempts:
            del self.attempts[ip]

class SessionManager:
    """Secure session management"""
    def __init__(self, timeout=3600):  # 1 hour default timeout
        self.sessions = {}
        self.session_timeout = timeout
    
    def create_session(self, username):
        """
        Create a new session for a user
        
        Args:
            username (str): Username for the session
            
        Returns:
            str: Session ID
        """
        session_id = secrets.token_hex(16)  # 32 character hex string
        self.sessions[session_id] = {
            'username': username,
            'created': time.time(),
            'last_active': time.time(),
            'ip_address': None  # Will be set when used
        }
        return session_id
    
    def validate_session(self, session_id, ip_address=None):
        """
        Validate a session ID and update last_active time
        
        Args:
            session_id (str): The session ID to validate
            ip_address (str, optional): IP address for additional validation
            
        Returns:
            tuple: (bool, str) - (is_valid, username or None)
        """
        if session_id not in self.sessions:
            return False, None
        
        session = self.sessions[session_id]
        now = time.time()
        
        # Check if session has expired
        if now - session['last_active'] > self.session_timeout:
            del self.sessions[session_id]
            return False, None
        
        # Optional IP binding for increased security
        if ip_address and session['ip_address'] and session['ip_address'] != ip_address:
            # Possible session hijacking attempt
            del self.sessions[session_id]
            return False, None
        
        # Update session
        session['last_active'] = now
        if ip_address and not session['ip_address']:
            session['ip_address'] = ip_address
            
        return True, session['username']
    
    def terminate_session(self, session_id):
        """
        Terminate a session
        
        Args:
            session_id (str): The session ID to terminate
            
        Returns:
            bool: True if session was terminated, False if not found
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False
    
    def get_user_sessions(self, username):
        """
        Get all sessions for a user
        
        Args:
            username (str): Username to look up
            
        Returns:
            list: List of session IDs
        """
        return [
            sid for sid, session in self.sessions.items()
            if session['username'] == username
        ]
    
    def cleanup_expired(self):
        """Clean up expired sessions"""
        now = time.time()
        expired = [
            sid for sid, session in self.sessions.items() 
            if now - session['last_active'] > self.session_timeout
        ]
        
        for sid in expired:
            del self.sessions[sid]