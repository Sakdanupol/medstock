# pharmacy_stock_system/database.py
# Run this script ONCE to add the new audit_log table.

import sqlite3
from werkzeug.security import generate_password_hash

# Connect to the database file
conn = sqlite3.connect('pharmacy.db')
cursor = conn.cursor()

print("Connecting to database...")

# --- Create Audit Log Table ---
# This table will store a history of all important actions.
cursor.execute('''
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
''')
print("Audit log table created or already exists.")


# --- Verify other tables exist (no changes needed) ---
cursor.execute('''
CREATE TABLE IF NOT EXISTS medications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT,
    manufacturer TEXT,
    batch_number TEXT,
    expiry_date DATE NOT NULL,
    quantity INTEGER NOT NULL,
    price REAL
);
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'pharmacist'))
);
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS stock_movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    medication_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('in', 'out')),
    quantity INTEGER NOT NULL,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    note TEXT,
    FOREIGN KEY (medication_id) REFERENCES medications (id) ON DELETE CASCADE
);
''')

# --- Optional: Add a default admin user if it doesn't exist ---
try:
    hashed_password = generate_password_hash('admin123')
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                   ('admin', hashed_password, 'admin'))
    print("Default admin user ('admin'/'admin123') created or already exists.")
except sqlite3.IntegrityError:
    # This error is expected if the user already exists, so we can ignore it.
    pass


# --- Close the connection ---
conn.commit()
conn.close()
print("Database schema verified and connection closed.")
