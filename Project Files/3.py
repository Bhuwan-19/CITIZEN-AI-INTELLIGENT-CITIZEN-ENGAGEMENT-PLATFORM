import sqlite3
import hashlib
import os

# Connect to your database
conn = sqlite3.connect('citizen_ai.db')
cursor = conn.cursor()

# Function to hash password with optional salt
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()  # generate random salt
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed, salt

# Government user credentials
govt_username = "govt_admin"
govt_password = "Govt@123"
govt_email = "govt_admin@example.com"
full_name = "Government Admin"
role = "govt"

# Hash the password
hashed_password, salt = hash_password(govt_password)

# Insert user into database (check if user already exists)
cursor.execute("SELECT * FROM users WHERE username=?", (govt_username,))
if cursor.fetchone() is None:
    cursor.execute("""
        INSERT INTO users (username, email, full_name, password_hash, salt, role)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (govt_username, govt_email, full_name, hashed_password, salt, role))
    conn.commit()
    print(f"Government user created! Username: {govt_username}, Password: {govt_password}")
else:
    print("User already exists!")

conn.close()
