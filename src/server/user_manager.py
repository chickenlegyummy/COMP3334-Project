import sqlite3
import hashlib
import os

class UserManager:
    def __init__(self):
        self.db_path = "users.db"
        self.setup_db()
    
    def setup_db(self):
        if not os.path.exists(self.db_path):
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
            # Default admin user
            admin_hash = hashlib.sha256("adminpassword".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", admin_hash, "admin"))
            # Default normal user: test
            test_hash = hashlib.sha256("password".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("test", test_hash, "normal"))
            # New normal user: test2
            test2_hash = hashlib.sha256("test2pass".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("test2", test2_hash, "normal"))
            # Default guest user
            guest_hash = hashlib.sha256("guestpass".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("guest", guest_hash, "guest"))
            conn.commit()
            conn.close()
            print("Default users created: admin (admin/adminpassword), test (test/password), test2 (test2/test2pass), guest (guest/guestpass)")
    
    def verify_user(self, username, password):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        return result and result[0] == password_hash, result[1] if result else "guest"