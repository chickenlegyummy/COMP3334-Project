import os
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def validate_filename(filename):
    return bool(filename and all(c.isalnum() or c in "._-" for c in filename))

def get_file_size(filepath):
    return os.path.getsize(filepath)

def generate_verification_code(length=6):
    """Generate a random verification code for password resets/MFA"""
    return ''.join(random.choices(string.digits, k=length))

def send_verification_email(email_address, verification_code):
    """Send a verification code to the given email address"""
    # This is a mock implementation. In a real system, you'd use a proper email service
    # like SendGrid, AWS SES, or your own SMTP server.
    
    try:
        # For demonstration purposes only. In production, use environment variables for credentials.
        smtp_server = "smtp.example.com"
        smtp_port = 587
        smtp_username = "your_email@example.com"
        smtp_password = "your_password"
        
        # Create message
        message = MIMEMultipart()
        message["From"] = smtp_username
        message["To"] = email_address
        message["Subject"] = "Secure File Sharing - Verification Code"
        
        body = f"""
        Hello,
        
        Your verification code is: {verification_code}
        
        This code will expire in 15 minutes.
        
        If you did not request this code, please ignore this email.
        
        Regards,
        Secure File Sharing Team
        """
        
        message.attach(MIMEText(body, "plain"))
        
        # Connect to server and send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(message)
        
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def init_database():
    """Initialize the SQLite database with necessary tables"""
    import sqlite3
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        mfa_secret TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        status TEXT DEFAULT 'active'
    )
    ''')
    
    # Create password_reset_tokens table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        token TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used INTEGER DEFAULT 0,
        FOREIGN KEY (username) REFERENCES users(username)
    )
    ''')
    
    # Create audit_log table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        details TEXT
    )
    ''')
    
    conn.commit()
    conn.close()