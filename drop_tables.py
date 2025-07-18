import sqlite3

conn = sqlite3.connect('users.db')
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS code_submissions_short_first")
cursor.execute("DROP TABLE IF EXISTS code_submissions_short_second")
cursor.execute("DROP TABLE IF EXISTS code_submissions_short_third")
cursor.execute("DROP TABLE IF EXISTS code_submissions_short_fourth")
cursor.execute("DROP TABLE IF EXISTS code_submissions_short_fifth")
cursor.execute("DROP TABLE IF EXISTS code_submissions_long")
cursor.execute("DROP TABLE IF EXISTS users")

conn.commit()
conn.close()

print("Table deleted.")
