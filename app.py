# -- import libraries
from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib, secrets, os, sqlite3, time
import pyotp, qrcode

#-- initialise the app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

HASH_ITERATIONS = 200_000   #number of iterations
SALT_LENGTH = 16        # salt length 16 bytes
QR_DIR = 'static/qrcodes'
os.makedirs(QR_DIR, exist_ok=True)
DB_FILE = 'users.db'

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            hashed_password TEXT NOT NULL,
            secret_2fa TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# helper function
def get_user(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            'username': row[0],
            'salt': row[1],
            'hashed_password': row[2],
            '2fa_secret': row[3],
            'role': row[4]
        }
    return None

# function securely hashes a user's password using PBKDF2-HMAC algo with SHA-256
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, HASH_ITERATIONS).hex()

# functions creates a special QR code image based on teh user's 2FA secret key
def generate_qr_code_url(username, secret):
    issuer = "SecureLockerApp"
    totp_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer) # provsioning.. converts the uri string to a special format
    img = qrcode.make(totp_uri) # generates the QR code
    path = f'{QR_DIR}/{username}_qrcode.png'
    img.save(path)
    return path

@app.route('/') #shows the login page (base url)
def home():
    return render_template('login.html')

# ---------------------- User Registration ----------------------

@app.route('/register', methods=['GET', 'POST']) # get -> shows the registration page 
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'] # takes input values from html

        if get_user(username):
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        salt = secrets.token_bytes(SALT_LENGTH) # generates the unique salt , a hashed password and a secret for TOTP
        hashed = hash_password(password, salt)
        totp_secret = pyotp.random_base32()

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO users (username, salt, hashed_password, secret_2fa, role) VALUES (?, ?, ?, ?, ?)',
                  (username, salt.hex(), hashed, totp_secret, 'user'))
        conn.commit()
        conn.close()

        session['username'] = username
        session['role'] = 'user'
        qr_path = generate_qr_code_url(username, totp_secret)
        flash("Registration Successful! Scan QR to setup 2FA.", "success")
        return render_template('success.html', message="Registration Successful!", qr=os.path.basename(qr_path))

    return render_template('register.html')

# ---------------------- User Login ----------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        overall_start = time.time()   

        username = request.form['username']
        password = request.form['password']
        otp = request.form['otp']
        user = get_user(username)

        if not user:
            flash("User does not exist! Please register.", "danger")
            return redirect(url_for('login'))

        if user['role'] != 'user':
            flash("Unauthorized access!", "danger")
            return redirect(url_for('login'))

        salt = bytes.fromhex(user['salt']) # converts the hex salt to bytes

        
        hash_start = time.time()
        hashed_input = hash_password(password, salt) #re-hashes the entered password
        hash_end = time.time()
        print(f"[Hashing] PBKDF2 hashing took: {hash_end - hash_start:.6f} seconds")

        if not secrets.compare_digest(user['hashed_password'], hashed_input):
            flash("Incorrect password!", "danger")
            return redirect(url_for('login'))

        totp = pyotp.TOTP(user['2fa_secret'])   # verifies the otp frpm google autheticator against stored secret
        if not totp.verify(otp):
            flash("Invalid 2FA code!", "danger")
            return redirect(url_for('login'))

        session['username'] = username
        session['role'] = 'user'
        flash("Login Successful!", "success")

        overall_end = time.time()
        print(f"[Login] Total login process took: {overall_end - overall_start:.6f} seconds")

        return render_template('success.html', message="Login Successful!", qr=None)

    return render_template('login.html')

# ---------------------- Admin Login and Panel ----------------------

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)

        if not user or user['role'] != 'admin':
            flash("Admin account not found!", "danger")
            return redirect(url_for('admin_login'))

        salt = bytes.fromhex(user['salt'])
        hashed_input = hash_password(password, salt)

        if not secrets.compare_digest(user['hashed_password'], hashed_input):
            flash("Incorrect admin password!", "danger")
            return redirect(url_for('admin_login'))

        session['username'] = username
        session['role'] = 'admin'
        flash("Admin Login Successful!", "success")
        return redirect(url_for('admin_panel'))

    return render_template('admin_login.html')

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if 'username' not in session or session.get('role') != 'admin':
        flash("Access Denied!", "danger")
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    search_query = request.args.get('search')
    if search_query:
        c.execute('SELECT username, salt, hashed_password, secret_2fa FROM users WHERE username LIKE ?', ('%' + search_query + '%',))
    else:
        c.execute('SELECT username, salt, hashed_password, secret_2fa FROM users')

    users = c.fetchall()
    conn.close()
    return render_template('admin_panel.html', users=users)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if 'username' not in session or session.get('role') != 'admin':
        flash("Access Denied!", "danger")
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    flash(f"User '{username}' deleted successfully.", "success")  
    return redirect(url_for('admin_panel'))

# ---------------------- QR Regenerate for Users ----------------------

@app.route('/request_regenerate_qr')
def request_regenerate_qr():
    if 'username' not in session or session.get('role') != 'user':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))
    return render_template('reauthenticate.html')

@app.route('/reauthenticate', methods=['POST'])
def reauthenticate():
    if 'username' not in session or session.get('role') != 'user':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    username = session['username']
    entered_password = request.form['password']
    user = get_user(username)

    if user:
        salt = bytes.fromhex(user['salt'])
        correct_hash = user['hashed_password']
        hashed_input = hash_password(entered_password, salt)

        if secrets.compare_digest(correct_hash, hashed_input):
            return redirect(url_for('regenerate_qr'))
        else:
            flash('Incorrect password. Try again.', 'danger')
            return redirect(url_for('request_regenerate_qr'))

    flash('User not found.', 'danger')
    return redirect(url_for('login'))

@app.route('/regenerate_qr')
def regenerate_qr():
    if 'username' not in session or session.get('role') != 'user':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    username = session['username']
    new_secret = pyotp.random_base32()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET secret_2fa = ? WHERE username = ?', (new_secret, username))
    conn.commit()
    conn.close()

    qr_path = generate_qr_code_url(username, new_secret)
    flash("New QR Code Generated Successfully!", "success")
    return render_template('success.html', message="New QR Generated!", qr=os.path.basename(qr_path))

# ------------ PBKDF2 Latency Experiment ------------

def experiment_pbkdf2():
    print("\nPBKDF2 Hashing Time Experiment:")
    for iterations in [50_000, 100_000, 200_000, 300_000]:
        start_time = time.time()
        hashlib.pbkdf2_hmac('sha256', b'password123', b'mysalt', iterations)
        end_time = time.time()
        print(f"{iterations} iterations took {end_time - start_time:.6f} seconds")
    print("-----------------------------------------------------\n")

if __name__ == '__main__':
    from werkzeug.serving import is_running_from_reloader
    if not is_running_from_reloader():
        experiment_pbkdf2()
    app.run(debug=True)
