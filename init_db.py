import sqlite3

# Create a new SQLite DB file (or connect if it exists)
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Create the users table
cursor.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstname TEXT NOT NULL,
    surname TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_mentor INTEGER DEFAULT 0
);
''')

conn.commit()
conn.close()
print("users.db created and table initialized.")