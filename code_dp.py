import sqlite3


conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# This table stores one code submission per email
cursor.execute('''
CREATE TABLE IF NOT EXISTS code_submissions_short_first (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    java_code_first TEXT NOT NULL
);
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS code_submissions_short_second (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    java_code_second TEXT NOT NULL
);
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS code_submissions_short_third (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    java_code_third TEXT NOT NULL
);
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS code_submissions_short_fourth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    java_code_fourth TEXT NOT NULL
);
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS code_submissions_short_fifth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    java_code_fifth TEXT NOT NULL
);
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS code_submissions_long (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    java_code TEXT NOT NULL
);
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS mentor_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    feedback TEXT,
    marked INTEGER DEFAULT 0
);
''')

conn.commit()
conn.close()
print("Tables created.")