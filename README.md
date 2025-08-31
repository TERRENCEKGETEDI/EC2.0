# EC2.0 – Flask Code Submission Platform
A Flask-based web application that allows users to **register, log in, submit code, and upload files**, with role-based access for **admins** and **mentors**.  
Admins can manage users, reset passwords, and mentors can review student submissions and give feedback.

---

## 🚀 Features
- 🔐 User authentication (Register, Login, Logout)
- 👤 Roles: **Admin**, **Mentor**, **Student**
- 📂 File upload & text submission per user
- 💻 Multiple code submission sections (short & long answers)
- 🛡️ Security headers for better protection (CSP, XSS protection, etc.)
- 📊 Admin dashboard:
  - Manage users
  - Reset passwords
- 📑 Mentor dashboard:
  - View student code submissions
  - Provide marking & feedback

---

## 📂 Project Structure
EC2.0/
├── app.py # Main Flask app
├── templates/ # HTML templates (login, register, dashboards, etc.)
├── static/ # Static frontend files (index.html, CSS, JS)
├── uploads/ # Uploaded files/texts
├── users.db # SQLite database (created at runtime)
└── README.md # Project documentation

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository
```bash```
git clone https://github.com/TERRENCEKGETEDI/EC2.0.git
cd EC2.0

---
1. Install Python requirements  
2. Run the `.py` database scripts  
3. Then start the app

---

```bash```
python app.py

The app will be available at:
👉 http://127.0.0.1:5000

---
👤 Default Users
Admin
Email: admin@example.com
Password: AdminPass123

Mentor
Email: mentor@example.com
Password: mentorPass123

(These are created automatically at startup if they don’t exist.)

---

🔑 Routes Overview
Public
/ → Login page
/register → User registration

Authenticated
/home → Redirect to main dashboard
/upload → Upload files & text
/submit_code_* → Submit code (short & long)
/view_code_* → View submitted code

Admin
/admin/dashboard → Admin dashboard
/admin/users → Manage users
/admin/reset-password/<id> → Reset user password

Mentor
/mentor/marking → Mark student submissions
/mentor/view_all → View all code submissions

--- 

🔐 Security

Session-based authentication with Flask sessions
Passwords stored securely with Werkzeug’s generate_password_hash
Security headers added:
Content-Security-Policy
X-Frame-Options
X-Content-Type-Options
Strict-Transport-Security
Referrer-Policy

---

📜 License
This project is licensed under the MIT License.

---

🙌 Acknowledgments
Flask
Werkzeug Security
SQLite
