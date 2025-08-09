# app.py
import os
import random
import string
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import bleach
from datetime import timedelta

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, 'juice_shop.db')

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.permanent_session_lifetime = timedelta(days=7)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # users table with role (user/admin)
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # simple products table (used by index)
    cur.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price REAL NOT NULL,
        image_url TEXT NOT NULL,
        category TEXT NOT NULL
    )
    ''')

    # seed two users if not exist (alice, bob)
    cur.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()['c'] == 0:
        cur.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                    ("alice", "alice@example.com", generate_password_hash("password123"), "user"))
        cur.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                    ("bob", "bob@example.com", generate_password_hash("password123"), "user"))
        # optional demo admin (not needed for CTF) - but keep it commented
        # cur.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
        #             ("realadmin", "realadmin@example.com", generate_password_hash("adminpass"), "admin"))

    # seed a couple products for index page
    cur.execute("SELECT COUNT(*) as p FROM products")
    if cur.fetchone()['p'] == 0:
        products = [
            ("Orange Juice", "Fresh squeezed orange.", 3.5, "/static/images/orange.jpg", "juice"),
            ("Apple Juice", "No sugar added.", 3.0, "/static/images/apple.jpg", "juice"),
            ("Mango Blast", "Tropical delight.", 4.0, "/static/images/mango.jpg", "juice"),
            ("Berry Mix", "Mixed berries.", 4.5, "/static/images/berry.jpg", "juice"),
        ]
        cur.executemany("INSERT INTO products (name,description,price,image_url,category) VALUES (?,?,?,?,?)", products)

    conn.commit()
    conn.close()

init_db()

# ---------------------------
# Helpers
# ---------------------------
def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

def get_current_user():
    if 'user_id' in session:
        return get_user_by_id(session['user_id'])
    return None

def random_fake_info():
    # generate some fake sensitive-ish info
    return {
        "ssn": "{}-{}-{}".format(random.randint(100,999), random.randint(10,99), random.randint(1000,9999)),
        "token": ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
        "notes": "Sensitive data id: {}".format(random.randint(100000,999999))
    }

# ---------------------------
# Routes
# ---------------------------

@app.before_request
def load_user():
    g.user = get_current_user()

@app.route('/')
def home():
    conn = get_db_connection()
    products = conn.execute('SELECT id, name, price, image_url FROM products LIMIT 4').fetchall()
    conn.close()
    return render_template('index.html', products=products, user=g.user)

# Register
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = bleach.clean(request.form.get('username', '').strip())
        email = bleach.clean(request.form.get('email', '').strip())
        password = request.form.get('password', '')
        if not username or not email or not password:
            flash("Please fill all fields", "warning")
            return redirect(url_for('register'))
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",
                         (username, email, generate_password_hash(password)))
            conn.commit()
            flash("Account created. Please login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = bleach.clean(request.form.get('username','').strip())
        password = request.form.get('password','')
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session.permanent = True
            session['user_id'] = user['id']
            flash("Logged in successfully.", "success")
            return redirect(url_for('home'))
        flash("Invalid credentials.", "danger")
        return redirect(url_for('login'))
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('home'))

# Profile view / edit
@app.route('/profile', methods=['GET','POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_user_by_id(session['user_id'])
    if request.method == 'POST':
        # allow editing of display fields; email is deliberately editable for CTF
        new_email = bleach.clean(request.form.get('email', user['email']).strip())
        display_name = bleach.clean(request.form.get('display_name', user['username']).strip())
        conn = get_db_connection()
        try:
            conn.execute("UPDATE users SET email = ?, username = ? WHERE id = ?",
                         (new_email, display_name, user['id']))
            conn.commit()
            flash("Profile updated.", "success")
            return redirect(url_for('profile'))
        except sqlite3.IntegrityError:
            flash("Email or username already in use.", "danger")
        finally:
            conn.close()
    # show profile edit form
    return render_template('profile.html', user=user)

# ---------------------------
# Vulnerable IDOR endpoint (intentionally flawed)
# ---------------------------
# This endpoint is intended to be "admin-only", but we purposely do NOT check the current user's role.
# Any logged in user can request it. That's the IDOR. The CTF goal: set YOUR email to admin@arabteamhack.com,
# then craft a request to /admin_view?user_id=<target_user_id> to extract fake sensitive info & flag.
@app.route('/admin_view')
def admin_view():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # vulnerable: no authorization check beyond being logged in
    target_id = request.args.get('user_id', type=int)
    if not target_id:
        flash("Provide user_id parameter.", "warning")
        return redirect(url_for('home'))

    target = get_user_by_id(target_id)
    if not target:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    # Check whether the *target* user's email equals the special admin email.
    # If it does, we "reveal" fake sensitive info and the flag.
    admin_email_trigger = "admin@arabteamhack.com"
    sensitive = None
    flag = None
    if target['email'].lower() == admin_email_trigger:
        sensitive = random_fake_info()
        # flag can be any string; keep it deterministic per request for demo or random:
        flag = "CTF{idor_admin_email_triggered_{} }".format(''.join(random.choices('ABCDEF0123456789', k=8)))
    # Render page showing what an "admin" would see for that user.
    # NOTE: In a secure app, we would verify the requesting user's role is admin before showing anything.
    return render_template('admin_view.html', requester=get_user_by_id(session['user_id']),
                           target=target, sensitive=sensitive, flag=flag)

# ---------------------------
# Small utilities / cart omitted for brevity (CTF focuses on profile/IDOR)
# ---------------------------

if __name__ == '__main__':
    app.run(debug=True, host="127.0.0.1", port=80)
