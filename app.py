from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import os
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production!

def is_superuser():
    return session.get('role') == 'superuser'

def is_plant_manager():
    return session.get('role') == 'plant_manager'

def get_db_connection():
    result = urlparse(os.environ.get("DATABASE_URL"))
    username = result.username
    password = result.password
    database = result.path[1:]
    hostname = result.hostname
    port = result.port

    return psycopg2.connect(
        dbname=database,
        user=username,
        password=password,
        host=hostname,
        port=port
    )


# Database setup
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            date TEXT NOT NULL,
            issue TEXT NOT NULL,
            points REAL NOT NULL,
            user_id INTEGER REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

init_db()

# Mapping issues to point values
ISSUE_POINTS = {
    "Call Off": 1.0,
    "Leave/Late": 0.5,
    "NCNS": 2.0
}

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        name = request.form['name']
        issue = request.form['issue']
        date = request.form['date']
        points = ISSUE_POINTS.get(issue, 0)

        conn = get_db_connection()
        c = conn.cursor()
        c.execute('INSERT INTO attendance (name, date, issue, points, user_id) VALUES (%s, %s, %s, %s, %s)',
                  (name, date, issue, points, session['user_id']))
        conn.commit()
        conn.close()

        return redirect('/summary')

    return render_template('index.html')


@app.route('/summary')
def summary():
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    c = conn.cursor()

    if is_superuser() or is_plant_manager():
        c.execute('SELECT name, SUM(points) FROM attendance GROUP BY name')
    else:
        c.execute('SELECT name, SUM(points) FROM attendance WHERE user_id = %s GROUP BY name', (session['user_id'],))

    summary_data = c.fetchall()
    conn.close()
    return render_template('summary.html', summary=summary_data)

@app.route('/details/<name>')
def details(name):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    c = conn.cursor()
    if is_superuser() or is_plant_manager():
        c.execute('SELECT id, date, issue, points FROM attendance WHERE name = %s ORDER BY date', (name,))
    else:
        c.execute('SELECT id, date, issue, points FROM attendance WHERE name = %s AND user_id = %s ORDER BY date',
                  (name, session['user_id']))
    
    details_data = c.fetchall()
    conn.close()
    return render_template('details.html', name=name, details=details_data)

@app.route('/delete/<int:entry_id>', methods=['POST'])
def delete_entry(entry_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    c = conn.cursor()

    # Optionally add security logic here to check ownership if desired
    c.execute('DELETE FROM attendance WHERE id = %s', (entry_id,))
    conn.commit()
    conn.close()
    return redirect(request.referrer or '/summary')


@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
def edit_entry(entry_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    c = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        issue = request.form['issue']
        points = ISSUE_POINTS.get(issue, 0)

        c.execute('''
            UPDATE attendance
            SET name = %s, date = %s, issue = %s, points = %s
            WHERE id = %s
        ''', (name, date, issue, points, entry_id))
        conn.commit()
        conn.close()
        return redirect(f'/details/{name}')

    # Fetch the current record
    c.execute('SELECT name, date, issue FROM attendance WHERE id = %s', (entry_id,))
    entry = c.fetchone()
    conn.close()

    return render_template('edit.html', id=entry_id, entry=entry)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, password))
            conn.commit()
        except psycopg2.IntegrityError:
            conn.rollback()
            conn.close()
            return 'Username already exists!'
        conn.close()
        return redirect('/login')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT id, password, role FROM users WHERE username = %s', (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password_input):
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            return redirect('/')
        else:
            return 'Invalid credentials!'
    return render_template('login.html')




@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/create-superuser')
def create_superuser():
    from werkzeug.security import generate_password_hash
    import psycopg2

    username = 'bobby'
    password = generate_password_hash('@Icyotter462')

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            'INSERT INTO users (username, password, role) VALUES (%s, %s, %s)',
            (username, password, 'superuser')
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        return 'Superuser already exists!'
    finally:
        conn.close()
    return 'Superuser created!'

@app.route('/users')
def view_users():
    if not is_superuser():
        return redirect('/')

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT id, username, role FROM users')
    users = c.fetchall()
    conn.close()

    return render_template('users.html', users=users)

@app.route('/create_user', methods=['POST'])
def create_user():
    if not is_superuser():
        return redirect('/')

    username = request.form['username']
    password_raw = request.form['password']
    role = request.form['role']

    if role not in ['user', 'plant_manager', 'superuser']:
        return 'Invalid role selected.'

    password_hashed = generate_password_hash(password_raw)

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)', (username, password_hashed, role))
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        return 'Username already exists!'
    finally:
        conn.close()

    return redirect('/users')


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_superuser():
        return redirect('/')

    if user_id == session.get('user_id'):
        return 'You cannot delete your own account.'

    conn = get_db_connection()
    c = conn.cursor()

    # Delete attendance entries first
    c.execute('DELETE FROM attendance WHERE user_id = %s', (user_id,))
    # Then delete the user
    c.execute('DELETE FROM users WHERE id = %s', (user_id,))

    conn.commit()
    conn.close()

    return redirect('/users')


@app.route('/update_user_role/<int:user_id>', methods=['POST'])
def update_user_role(user_id):
    if not is_superuser():
        return redirect('/')

    if user_id == session.get('user_id'):
        return 'You cannot change your own role.'

    new_role = request.form.get('new_role')

    if new_role not in ['user', 'plant_manager', 'superuser']:
        return 'Invalid role.'

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('UPDATE users SET role = %s WHERE id = %s', (new_role, user_id))
    conn.commit()
    conn.close()

    return redirect('/users')

# For local dev
if __name__ == '__main__':
    from os import environ
    port = int(environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

