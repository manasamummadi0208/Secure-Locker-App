import sqlite3
import hashlib
import secrets
import pyotp

DB_FILE = 'users.db'
HASH_ITERATIONS = 200_000
SALT_LENGTH = 16

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, HASH_ITERATIONS).hex()

def create_admin():
    username = 'admin'
    password = 'Admin@123'  # <-- Set your Admin password here

    salt = secrets.token_bytes(SALT_LENGTH)
    hashed = hash_password(password, salt)
    totp_secret = pyotp.random_base32()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO users (username, salt, hashed_password, secret_2fa, role) VALUES (?, ?, ?, ?, ?)',
              (username, salt.hex(), hashed, totp_secret, 'admin'))
    conn.commit()
    conn.close()

    print(f"Admin user '{username}' created successfully!")

if __name__ == "__main__":
    create_admin()
