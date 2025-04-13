import sqlite3
import hashlib
import os
from src.server.user_manager import UserManager  # Import UserManager for consistency

password = input("Enter password: ").strip()
print(hashlib.sha256(password.encode()).hexdigest())