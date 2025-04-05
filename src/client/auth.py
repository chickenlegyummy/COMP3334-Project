import getpass
import re
from src.common.totp import TOTP  # Import our custom TOTP implementation

def authenticate(socket):
    """Authenticate user with security validation"""
    while True:
        username = input("Username: ")
        # Validate username format
        if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
            print("Invalid username format. Please use only letters, numbers, and the characters @.+-_")
            continue
        break
        
    password = getpass.getpass("Password: ")
    credentials = f"AUTH:{username}:{password}"
    socket.send(credentials.encode())
    response = socket.recv(1024).decode()
    
    if response.startswith("MFA_REQUIRED:"):
        session_id = response.split(":")[1]
        # Validate MFA code format (must be 6 digits)
        while True:
            code = input("Enter the verification code from your authenticator app: ")
            if re.match(r'^\d{6}$', code):
                break
            print("Invalid code format. Please enter a 6-digit code.")
            
        socket.send(f"MFA_VERIFY:{session_id}:{code}".encode())
        mfa_response = socket.recv(1024).decode()
        return mfa_response == "AUTH_SUCCESS"
    
    return response == "AUTH_SUCCESS"

def verify_mfa(socket, code, session_id):
    """Verify MFA code with security validation"""
    # Validate code format
    if not re.match(r'^\d{6}$', code):
        return False
        
    # Validate session_id format (hex string)
    if not re.match(r'^[0-9a-f]{32}$', session_id):
        return False
        
    socket.send(f"MFA_VERIFY:{session_id}:{code}".encode())
    response = socket.recv(1024).decode()
    return response == "AUTH_SUCCESS"

def request_password_reset(socket, username, email):
    """Request password reset with security validation"""
    # Validate username
    if not re.match(r'^[\w@\.\+\-]{3,30}$', username):
        return "ERROR:Invalid username format"
        
    # Validate email
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return "ERROR:Invalid email format"
        
    socket.send(f"RESET_REQUEST:{username}:{email}".encode())
    response = socket.recv(1024).decode()
    return response