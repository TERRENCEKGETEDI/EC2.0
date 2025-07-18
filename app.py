from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, jsonify,Response,render_template, abort
from werkzeug.security import generate_password_hash, check_password_hash
import requests, json, sqlite3
# from flask_wtf import FlaskForm
# from wtforms import StringField
# from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
# filename = secure_filename(filename)

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your secret key for session management


import os


from datetime import timedelta

app.permanent_session_lifetime = timedelta(minutes=1)

@app.before_request
def make_session_permanent():
    session.permanent = True


UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('index'))  # or error

    if request.method == 'POST':
        email = session['user']['email']
        username = email.split('@')[0]

        # Handle file upload
        uploaded_file = request.files.get('file')
        if uploaded_file and uploaded_file.filename != '':
            # Secure the original filename
            original_filename = secure_filename(uploaded_file.filename)
            ext = os.path.splitext(original_filename)[1]  # file extension including '.'

            # Create new filename
            new_filename = f"{username}_file{ext}"

            # Save file
            uploaded_file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
        else:
            new_filename = None

        # Handle text input
        user_text = request.form.get('text')
        if user_text:
            text_filename = f"{username}_text.txt"
            with open(os.path.join(app.config['UPLOAD_FOLDER'], text_filename), 'w', encoding='utf-8') as f:
                f.write(user_text)
        else:
            text_filename = None

        return f"File saved as {new_filename}, Text saved as {text_filename}"

    return render_template('upload.html')



# In-memory database for demonstration (replace with a database in a real-world application)
users = {}


@app.route('/')
def index():
    return render_template('login.html')

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'  # Prevent clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Stop MIME sniffing
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
@app.after_request
def hide_server_headers(response):
    response.headers["Server"] = "SecureServer"
    response.headers["X-Powered-By"] = "None"
    return response

@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response


def is_admin():
    return session.get('user', {}).get('is_admin', False)

def is_mentor():
    return session.get('user', {}).get('is_mentor', False)


def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form.get('firstname')
        surname = request.form.get('surname')
        phone = request.form.get('phone')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([firstname, surname, phone, email, password]):
            return 'Please fill out all fields.'

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            return 'Email exists'

        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (firstname, surname, phone, email, password) VALUES (?, ?, ?, ?, ?)",
                       (firstname, surname, phone, email, hashed_password))
        db.commit()
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if user and check_password_hash(user['password'], password):
        session['user'] = {
            'id': user['id'],
            'firstname': user['firstname'],
            'surname': user['surname'],
            'email': user['email'],
            'phone': user['phone'],
            'is_admin': user['is_admin'] if 'is_admin' in user.keys() else False,
            'is_mentor': user['is_mentor'] if 'is_mentor' in user.keys() else False 
        }

        # Redirect admins and mentors to their dashboards
        if session['user']['is_admin']:
            return redirect(url_for('admin_dashboard'))
        # elif session['user']['is_mentor']:
        #     return redirect(url_for('mentor_view_all'))  
        else:
            return redirect(url_for('serve_index'))
    else:
        return 'Invalid email or password.'




def create_admin():
    db = get_db()
    cursor = db.cursor()
    admin_email = "admin@example.com"
    admin_password = "AdminPass123"  # choose a secure password
    hashed_password = generate_password_hash(admin_password)

    # Check if admin exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (admin_email,))
    if cursor.fetchone():
        print("Admin user already exists.")
        return

    cursor.execute("INSERT INTO users (firstname, surname, phone, email, password, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
                   ("Admin", "User", "0000000000", admin_email, hashed_password, 1))
    db.commit()
    print("Admin user created.")

def create_mentor():
    db = get_db()
    cursor = db.cursor()
    mentor_email = "mentor@example.com"
    admin_password = "mentorPass123"  # choose a secure password
    hashed_password = generate_password_hash(admin_password)

    # Check if mentor exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (mentor_email,))
    if cursor.fetchone():
        print("Mentor user already exists.")
        return

    cursor.execute("INSERT INTO users (firstname, surname, phone, email, password, is_admin, is_mentor) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   ("Mentor", "User", "0000000000", mentor_email, hashed_password, 0, 1))
    db.commit()
    print("Mentor user created.")


@app.route('/admin/users')
def admin_users():
    if not is_admin():
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, firstname, surname, phone, email, is_admin, is_mentor FROM users WHERE users.is_admin = 0")
    users = cursor.fetchall()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/reset-password/<int:user_id>', methods=['GET', 'POST'])
def reset_password_form(user_id):
    if not is_admin():
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        new_password = request.form.get('password')
        if not new_password:
            return "Password is required"

        hashed = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
        db.commit()
        return f"Password reset successfully for user ID {user_id}. <a href='/admin/users'>Back</a>"

    # Get user info for form
    cursor.execute("SELECT firstname, surname, email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return render_template('reset_password.html', user=user, user_id=user_id)


@app.route('/mentor/marking')
def mentor_marking():
    if not is_mentor():
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT users.firstname, users.surname, users.email,
               COALESCE(mentor_feedback.marked, 0) as marked
        FROM users
        LEFT JOIN mentor_feedback ON users.email = mentor_feedback.email
        WHERE users.is_admin = 0 AND users.is_mentor = 0
        ORDER BY users.email
    ''')
    users = cursor.fetchall()
    return render_template('mentor_marking.html', users=users)


@app.route('/mentor/marking/<email>', methods=['GET', 'POST'])
def mentor_marking_student(email):
    if not is_mentor():
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        feedback = request.form.get('feedback', '')
        marked = 1 if request.form.get('marked') else 0

        cursor.execute('''
            INSERT INTO mentor_feedback (email, feedback, marked)
            VALUES (?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET feedback = excluded.feedback, marked = excluded.marked
        ''', (email, feedback, marked))
        db.commit()
        return redirect(url_for('mentor_marking'))

    # Fetch student's details
    cursor.execute("SELECT firstname, surname, email FROM users WHERE email = ?", (email,))
    student = cursor.fetchone()

    # Fetch all code fields
    codes = {}
    for table, field in [
        ('code_submissions_short_first', 'java_code_first'),
        ('code_submissions_short_second', 'java_code_second'),
        ('code_submissions_short_third', 'java_code_third'),
        ('code_submissions_short_fourth', 'java_code_fourth'),
        ('code_submissions_short_fifth', 'java_code_fifth'),
        ('code_submissions_long', 'java_code'),
    ]:
        cursor.execute(f"SELECT {field} FROM {table} WHERE email = ?", (email,))
        result = cursor.fetchone()
        codes[field] = result[field] if result else ""

    return render_template('mentor_marking_student.html', student=student, codes=codes)




@app.route('/submit_code_long', methods=['POST'])
def submit_code():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']

    # Read from the 'code' input field
    java_code = request.form.get('code')

    if not java_code:
        return "No code submitted"

    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        INSERT INTO code_submissions_long (email, java_code)
        VALUES (?, ?)
        ON CONFLICT(email) DO UPDATE SET java_code = excluded.java_code
    ''', (email, java_code))

    db.commit()
    return "Code submitted successfully."

@app.route('/view_code_long')
def view_code():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT java_code FROM code_submissions_long WHERE email = ?", (email,))
    result = cursor.fetchone()

    if result:
        return f"<h2>Your Submitted Code:</h2><pre>{result['java_code']}</pre>"
    else:
        return "No code submission found."



@app.route('/submit_code_short_first', methods=['POST'])
def submit_code_first():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    java_code = request.form.get('code_first')

    if not java_code:
        return "No code submitted"

    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        INSERT INTO code_submissions_short_first (email, java_code_first)
        VALUES (?, ?)
        ON CONFLICT(email) DO UPDATE SET java_code_first = excluded.java_code_first
    ''', (email, java_code))

    db.commit()
    return "Code submitted successfully."


@app.route('/view_code_short_first')
def view_code_first():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT java_code_first FROM code_submissions_short_first WHERE email = ?", (email,))
    result = cursor.fetchone()

    if result:
        return f"<h2>Your Submitted Code:</h2><pre>{result['java_code_first']}</pre>"
    else:
        return "No code submission found."


@app.route('/submit_code_short_second', methods=['POST'])
def submit_code_second():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    java_code = request.form.get('code_second')

    if not java_code:
        return "No code submitted"

    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        INSERT INTO code_submissions_short_second (email, java_code_second)
        VALUES (?, ?)
        ON CONFLICT(email) DO UPDATE SET java_code_second = excluded.java_code_second
    ''', (email, java_code))

    db.commit()
    return "Code submitted successfully."


@app.route('/view_code_short_second')
def view_code_second():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT java_code_second FROM code_submissions_short_second WHERE email = ?", (email,))
    result = cursor.fetchone()

    if result:
        return f"<h2>Your Submitted Code:</h2><pre>{result['java_code_second']}</pre>"
    else:
        return "No code submission found."

@app.route('/submit_code_short_third', methods=['POST'])
def submit_code_third():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    java_code = request.form.get('code_third')

    if not java_code:
        return "No code submitted"

    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        INSERT INTO code_submissions_short_third (email, java_code_third)
        VALUES (?, ?)
        ON CONFLICT(email) DO UPDATE SET java_code_third = excluded.java_code_third
    ''', (email, java_code))

    db.commit()
    return "Code submitted successfully."


@app.route('/view_code_short_third')
def view_code_third():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT java_code_third FROM code_submissions_short_third WHERE email = ?", (email,))
    result = cursor.fetchone()

    if result:
        return f"<h2>Your Submitted Code:</h2><pre>{result['java_code_third']}</pre>"
    else:
        return "No code submission found."


@app.route('/submit_code_short_fourth', methods=['POST'])
def submit_code_fourth():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    java_code = request.form.get('code_fourth')

    if not java_code:
        return "No code submitted"

    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        INSERT INTO code_submissions_short_fourth (email, java_code_fourth)
        VALUES (?, ?)
        ON CONFLICT(email) DO UPDATE SET java_code_fourth = excluded.java_code_fourth
    ''', (email, java_code))

    db.commit()
    return "Code submitted successfully."


@app.route('/view_code_short_fourth')
def view_code_fourth():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT java_code_fourth FROM code_submissions_short_fourth WHERE email = ?", (email,))
    result = cursor.fetchone()

    if result:
        return f"<h2>Your Submitted Code:</h2><pre>{result['java_code_fourth']}</pre>"
    else:
        return "No code submission found."


@app.route('/submit_code_short_fifth', methods=['POST'])
def submit_code_fifth():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    java_code = request.form.get('code_fifth')

    if not java_code:
        return "No code submitted"

    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        INSERT INTO code_submissions_short_fifth (email, java_code_fifth)
        VALUES (?, ?)
        ON CONFLICT(email) DO UPDATE SET java_code_fifth = excluded.java_code_fifth
    ''', (email, java_code))

    db.commit()
    return "Code submitted successfully."


@app.route('/view_code_short_fifth')
def view_code_fifth():
    if 'user' not in session:
        return redirect(url_for('index'))

    email = session['user']['email']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT java_code_fifth FROM code_submissions_short_fifth WHERE email = ?", (email,))
    result = cursor.fetchone()

    if result:
        return f"<h2>Your Submitted Code:</h2><pre>{result['java_code_fifth']}</pre>"
    else:
        return "No code submission found."


@app.route('/mentor/view_all')
def mentor_view_all():
    if not is_mentor():
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()

    # Combine all code submissions into one query per user using LEFT JOINs
    cursor.execute('''
        SELECT 
            users.firstname,
            users.surname,
            users.email,
            csf.java_code_first,
            css.java_code_second,
            cst.java_code_third,
            csfo.java_code_fourth,
            csfi.java_code_fifth,
            csl.java_code AS java_code_long
        FROM users
        LEFT JOIN code_submissions_short_first AS csf ON users.email = csf.email
        LEFT JOIN code_submissions_short_second AS css ON users.email = css.email
        LEFT JOIN code_submissions_short_third AS cst ON users.email = cst.email
        LEFT JOIN code_submissions_short_fourth AS csfo ON users.email = csfo.email
        LEFT JOIN code_submissions_short_fifth AS csfi ON users.email = csfi.email
        LEFT JOIN code_submissions_long AS csl ON users.email = csl.email
        WHERE users.is_admin = 0 AND users.is_mentor = 0
        ORDER BY users.email
    ''')
    records = cursor.fetchall()

    return render_template('mentor_view_all.html', records=records)

@app.route('/mentor/marking/long')
def mentor_marking_long():
    if not is_mentor():
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()

    # Combine all code submissions into one query per user using LEFT JOINs
    cursor.execute('''
        SELECT 
            users.firstname,
            users.surname,
            users.email,
            csf.java_code_first,
            css.java_code_second,
            cst.java_code_third,
            csfo.java_code_fourth,
            csfi.java_code_fifth,
            csl.java_code AS java_code_long
        FROM users
        LEFT JOIN code_submissions_short_first AS csf ON users.email = csf.email
        LEFT JOIN code_submissions_short_second AS css ON users.email = css.email
        LEFT JOIN code_submissions_short_third AS cst ON users.email = cst.email
        LEFT JOIN code_submissions_short_fourth AS csfo ON users.email = csfo.email
        LEFT JOIN code_submissions_short_fifth AS csfi ON users.email = csfi.email
        LEFT JOIN code_submissions_long AS csl ON users.email = csl.email
        ORDER BY users.email
    ''')
    records = cursor.fetchall()

    return render_template('mentor_view_all.html', records=records)





@app.route('/home')
def home():
    return redirect(url_for('serve_index'))

@app.route('/static/index.html')
def serve_index():
    if 'user' not in session:
        return redirect(url_for('index'))  # redirect to login page
    return send_from_directory('static', 'index.html')

@app.route('/api/user_data')
def user_data():
    if 'user' in session:
        return jsonify(session['user'])
    else:
        return jsonify({'error': 'User not logged in'}), 401

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('index'))  # Not logged in? Go to login page
    
    user = session['user']
    return f"Welcome {user['firstname']}! This is your dashboard."


@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin():
        return "Access denied", 403
    return render_template('admin_dashboard.html')




@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


#if __name__ == '__main__':
#    app.run(debug=True)
if __name__ == '__main__':
    create_mentor()
    create_admin()
    app.run(host='0.0.0.0', port=5000, debug=True)