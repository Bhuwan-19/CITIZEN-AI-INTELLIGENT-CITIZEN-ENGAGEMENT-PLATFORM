import sqlite3
import hashlib
import os

# --- Govt user details ---
username = "1234"
email = "gov@example.com"
password = "admin"
full_name = "Government Admin"
role = "govt"

# --- Generate salt + hash ---
salt = os.urandom(16).hex()
password_hash = hashlib.sha256((password + salt).encode()).hexdigest()

# --- Insert into DB ---
conn = sqlite3.connect("citizen_ai.db")  # Path to your DB
cursor = conn.cursor()

cursor.execute("""
    INSERT OR IGNORE INTO users (username, email, password_hash, salt, full_name, role)
    VALUES (?, ?, ?, ?, ?, ?)
""", (username, email, password_hash, salt, full_name, role))

conn.commit()
conn.close()

print("✅ Government account added successfully.")
