import sqlite3
import threading

class Database:
    def __init__(self, db_path):  # Explicitly accepts db_path
        self.db_path = db_path
        # Don’t create the connection here; defer it to per-thread usage
        self.create_tables()
    
    def get_connection(self):
        # Create a new connection for the current thread if needed
        thread_local = threading.local()
        if not hasattr(thread_local, "conn"):
            thread_local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            thread_local.cursor = thread_local.conn.cursor()
        return thread_local.conn, thread_local.cursor
    
    def create_tables(self):
        # Initial setup can use a temporary connection
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()
    
    def create_user(self, username, password_hash):
        conn, cursor = self.get_connection()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                          (username, password_hash))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_user(self, username):
        conn, cursor = self.get_connection()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result[0] if result else None
    
    def __del__(self):
        # No need to close here since connections are thread-local
        pass