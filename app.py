from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
import requests
import pyotp  # For generating and verifying OTP
import qrcode  # For generating QR codes
import io  # For handling QR code images in memory
import base64  # For encoding QR codes as base64 strings

app = Flask(__name__)
app.secret_key = "supersecretkey"  # To manage sessions (required by Flask)

DATABASE = 'members.db'

# Simple user store for staff and members (no security library)
USERS = {
    "staff": {"password": "staffpass", "role": "staff", "mfa_key": None},
    "member": {"password": "memberpass", "role": "member", "mfa_key": None},
    "pakkarim": {"password": "karim", "role": "staff", "mfa_key": None},
}

# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                  )''')
    db.commit()

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in USERS and USERS[username]['password'] == password:
            # Check if MFA is required
            session['user'] = username
            session['role'] = USERS[username]['role']
            if not USERS[username]['mfa_key']:
                return redirect(url_for('setup_mfa'))
            return redirect(url_for('verify_mfa'))
        else:
            return "Login Failed!"
    return render_template('login.html')

# MFA Setup Route
@app.route('/setup_mfa', methods=['GET', 'POST'])
def setup_mfa():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    if request.method == 'POST':
        mfa_key = request.form['mfa_key']
        USERS[username]['mfa_key'] = mfa_key  # Save MFA key
        return redirect(url_for('verify_mfa'))
    
    # Generate a TOTP key
    totp = pyotp.TOTP(pyotp.random_base32())
    USERS[username]['mfa_key'] = totp.secret
    qr_data = totp.provisioning_uri(name=username, issuer_name="Gym Management System")
    
    # Generate QR code
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return render_template('setup_mfa.html', qr_code=qr_base64, mfa_key=totp.secret)

# MFA Verification Route
@app.route('/verify_mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    mfa_key = USERS[username]['mfa_key']
    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(mfa_key)
        if totp.verify(otp):
            session['mfa_verified'] = True
            return redirect(url_for('dashboard'))
        else:
            return "Invalid OTP. Please try again."
    
    return render_template('verify_mfa.html')

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user' not in session or 'mfa_verified' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    return render_template('dashboard.html', username=username)

# Add Member Route
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html')

# Register New Member Route
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# View Members Route
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# View Classes Route
@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Fetch all classes from the database
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('mfa_verified', None)
    return redirect(url_for('login'))

if __name__ == '_main_':
    app.run(debug=True)