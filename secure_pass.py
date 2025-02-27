import bcrypt
import hmac
import os
import sqlite3
from hashlib import blake2b
from dotenv import load_dotenv

# Load environment variables from .env file (optional)
load_dotenv()

# Secure Pepper (fallback if environment variable is missing)
PEPPER = os.getenv('SECRET_PEPPER', 'default_secure_pepper_value').encode()

# Database setup
DB_FILE = "users.db"

def create_database():
    """Initialize the SQLite database and users table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def secure_hash(password: str) -> bytes:
    """Securely hashes a password using bcrypt with HMAC-peppered input."""
    hmac_pepper = hmac.new(PEPPER, password.encode(), digestmod=blake2b).digest()
    hashed = bcrypt.hashpw(hmac_pepper, bcrypt.gensalt(rounds=14))
    return hashed  # Store this in the database


def store_user(username: str, password: str):
    """Stores a user's username and hashed password in the database."""
    hashed_password = secure_hash(password)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password.decode()))
        conn.commit()
        print(f"User '{username}' added successfully!")
    except sqlite3.IntegrityError:
        print(f"Error: Username '{username}' already exists.")

    conn.close()


def verify_password(username: str, entered_password: str) -> bool:
    """Verifies a user's password against the stored hash in the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    conn.close()

    if result is None:
        print(f"User '{username}' not found.")
        return False

    stored_hash = result[0].encode()
    hmac_pepper = hmac.new(PEPPER, entered_password.encode(), digestmod=blake2b).digest()

    return bcrypt.checkpw(hmac_pepper, stored_hash)


# Example Usage
if __name__ == "__main__":
    create_database()  # Ensure database is initialized

    # Adding users
    store_user("alice", "StrongPassword!2024")
    store_user("bob", "AnotherSecurePass123!")

    # Testing password verification
    print("\nTesting Password Verification:")
    print("Alice correct password:", verify_password("alice", "StrongPassword!2024"))  # True
    print("Alice wrong password:", verify_password("alice", "WrongPassword"))  # False
    print("Non-existent user:", verify_password("charlie", "SomePassword"))  # False
