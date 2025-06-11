import os
import sqlite3
import csv
import io
import re
import smtplib
from email.message import EmailMessage
from gevent.pywsgi import WSGIServer

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, flash, g, Response
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

DATABASE = './data_center_approval.db'

# === SMTP Email Configuration ===
# You should replace these values with your actual SMTP server details.
SMTP_SERVER = "smtpsrvvdr02.ongc.co.in"
SMTP_PORT = 25
EMAIL_SENDER = "icedrdc@gmail.com"  # The from email address

def send_email(subject: str, body: str, recipients: list):
    """
    Send an email using SMTP server.
    :param subject: Subject of the email.
    :param body: Plain text body.
    :param recipients: List of recipient email addresses.
    """
    if not recipients:
        # No recipients to send to.
        return
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = ', '.join(recipients)
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            #smtp.starttls()
            #smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(msg)
        app.logger.info(f"Email sent to {recipients} with subject: {subject}")
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")

def get_user_emails_by_role(role):
    """
    Retrieve list of email addresses of users assigned the specified role.
    """
    db = get_db()
    c = db.cursor()
    c.execute('SELECT email_address FROM users WHERE role = ?', (role,))
    rows = c.fetchall()
    return [row['email_address'] for row in rows if '@' in row['email_address']]



# User roles: requester, approver1, approver2, admin

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        # Users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('requester','approver1','approver2','admin')),
                full_name TEXT NOT NULL,
                email_address TEXT  NOT NULL
                
            )
        ''')
        # Requests table
        c.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                laptop_details TEXT NOT NULL,
                requester_name TEXT NOT NULL,
                company TEXT NOT NULL,
                contact TEXT NOT NULL,
                purpose TEXT NOT NULL,
                serial_no TEXT NOT NULL,
                entry_date TEXT NOT NULL,
                status_level1 TEXT NOT NULL CHECK(status_level1 IN ('pending','approved','denied')) DEFAULT 'pending',
                comments_level1 TEXT,
                status_level2 TEXT NOT NULL CHECK(status_level2 IN ('pending','approved','denied')) DEFAULT 'pending',
                comments_level2 TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER NOT NULL,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
        ''')
        db.commit()
        # Create demo users if table empty
        c.execute('SELECT COUNT(*) FROM users')
        if c.fetchone()[0] == 0:
            # Add demo users with hashed passwords: password is 'password123' for all
            users = [
                ('DRDC', generate_password_hash('ongc@123'), 'requester', 'Control Room','agarwal_anant@ongc.co.in'),
                ('KP', generate_password_hash('ongc@123'), 'approver1', 'KP','agarwal_anant@ongc.co.in'),
                ('RP', generate_password_hash('ongc@123'), 'approver2', 'Incharge','agarwal_anant@ongc.co.in'),
                ('anant', generate_password_hash('ongc@123'), 'admin', 'Admin','agarwal_anant@ongc.co.in')
            ]
            c.executemany('INSERT INTO users (username, password_hash, role, full_name, email_address) VALUES (?, ?, ?, ?, ?)', users)
            db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


class User(UserMixin):
    def __init__(self, id_, username, role, full_name,email_address):
        self.id = id_
        self.username = username
        self.role = role
        self.full_name = full_name
        self.email_address = email_address

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user:
        return User(user['id'], user['username'], user['role'], user['full_name'], user['email_address'])
    return None

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        c = db.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['role'], user['full_name'], user['email_address'])
            login_user(user_obj)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# API routes

# Get current user info
@app.route('/api/user')
@login_required
def api_user():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'role': current_user.role,
        'full_name': current_user.full_name,
        'email_address': current_user.email_address
    })

# Get all users (admin only)
@app.route('/api/users')
@login_required
def api_users():
    if current_user.role != 'admin':
        return jsonify({'error':'Unauthorized'}), 403
    db = get_db()
    c = db.cursor()
    c.execute('SELECT id, username, role, full_name, email_address FROM users')
    users = [dict(row) for row in c.fetchall()]
    return jsonify(users)

# Add new user (admin only)
@app.route('/api/users', methods=['POST'])
@login_required
def api_add_user():
    if current_user.role != 'admin':
        return jsonify({'error':'Unauthorized'}), 403
    data = request.json
    required = ['username','password','role','full_name','email_address']
    if not all(k in data for k in required):
        return jsonify({'error':'Missing fields'}), 400
    username = data['username']
    password_hash = generate_password_hash(data['password'])
    role = data['role']
    full_name = data['full_name']
    email_address = data['email_address']
    if role not in ['requester','approver1','approver2','admin']:
        return jsonify({'error':'Invalid role'}), 400
    db = get_db()
    c = db.cursor()
    try:
        c.execute('INSERT INTO users(username,password_hash,role,full_name,email_address) VALUES (?,?,?,?,?)',
                  (username, password_hash, role, full_name,email_address))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error':'Username already exists'}), 400
    return jsonify({'message':'User created'})

# Update user role or full_name (admin only)
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def api_update_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error':'Unauthorized'}), 403
    data = request.json
    role = data.get('role')
    full_name = data.get('full_name')
    email_address = data.get('email_address')
    if role and role not in ['requester','approver1','approver2','admin']:
        return jsonify({'error':'Invalid role'}), 400
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    update_fields = []
    update_values = []
    if role:
        update_fields.append('role = ?')
        update_values.append(role)
    if full_name:
        update_fields.append('full_name = ?')
        update_values.append(full_name)
    if email_address:
        update_fields.append('email_address = ?')
        update_values.append(email_address)
    if not update_fields:
        return jsonify({'error': 'Nothing to update'}), 400
    update_values.append(user_id)
    sql = 'UPDATE users SET ' + ', '.join(update_fields) + ' WHERE id = ?'
    c.execute(sql, update_values)
    db.commit()
    return jsonify({'message':'User updated'})

# Delete user (admin only)
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def api_delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error':'Unauthorized'}), 403
    if user_id == current_user.id:
        return jsonify({'error':'Cannot delete yourself'}), 400
    db = get_db()
    c = db.cursor()
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return jsonify({'message':'User deleted'})

# Create new laptop entry request (requester only)
@app.route('/api/requests', methods=['POST'])
@login_required
def api_create_request():
    if current_user.role != 'requester':
        return jsonify({'error':'Unauthorized'}), 403
    data = request.json
    required = ['laptop_details','requester_name','company','contact','purpose','serial_no','entry_date']
    if not all(k in data for k in required):
        return jsonify({'error':'Missing fields'}), 400

    phone_pattern = re.compile(r'^\d{10}$')
    if not phone_pattern.match(data['contact']):
        return jsonify({'error':'Contact must be a 10-digit number.'}), 400

    db = get_db()
    c = db.cursor()
    c.execute('''
        INSERT INTO requests 
        (laptop_details, requester_name, company, contact, purpose,serial_no, entry_date, created_by) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['laptop_details'], data['requester_name'],
        data['company'], data['contact'], data['purpose'],data['serial_no'],
        data['entry_date'], current_user.id
    ))
    db.commit()
    new_request_id = c.lastrowid

    # Send email notification to approver1(s)
    approver1_emails = get_user_emails_by_role('approver1')
    if approver1_emails:
        print("##################")
        print(approver1_emails)
        subject = f"New Laptop Entry Request #{new_request_id} Awaiting Level 1 Approval"
        body = f"""A new laptop entry request has been created.
        Request ID: {new_request_id}
        Requester: {data['requester_name']}
        Laptop Details: {data['laptop_details']}
        Company: {data['company']}
        Contact: {data['contact']}
        Purpose: {data['purpose']}
        serial_no: {data['serial_no']}
        Entry Date: {data['entry_date']}
        Please review and approve/deny the request at your earliest convenience."""
        send_email(subject, body, approver1_emails)
    return jsonify({'message':'Request created'})

# Get requests for current user (role based)
@app.route('/api/requests')
@login_required
def api_get_requests():
    db = get_db()
    c = db.cursor()
    user_role = current_user.role
    uid = current_user.id
    if user_role == 'requester':
        # only own requests
        c.execute('SELECT * FROM requests WHERE created_by = ? ORDER BY created_at DESC', (uid,))
    elif user_role == 'approver1':
        # pending or any requests that are level1 pending or processed
        c.execute('SELECT * FROM requests WHERE status_level1 = "pending" OR status_level1 IN ("approved","denied") ORDER BY created_at DESC')
    elif user_role == 'approver2':
        # requests approved by level1 and level2 pending
        c.execute('SELECT * FROM requests WHERE status_level1 = "approved" AND status_level2 = "pending" ORDER BY created_at DESC')
    elif user_role == 'admin':
        # all requests
        c.execute('SELECT * FROM requests ORDER BY created_at DESC')
    else:
        return jsonify({'error':'Unauthorized'}), 403
    rows = c.fetchall()
    res = [dict(r) for r in rows]
    return jsonify(res)

# Approve or deny request at level 1 and 2
@app.route('/api/requests/<int:req_id>/approve', methods=['POST'])
@login_required
def api_approve_request(req_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
    req = c.fetchone()
    if not req:
        return jsonify({'error': 'Request not found'}), 404
    role = current_user.role

    data = request.json
    action = data.get('action')
    comment = data.get('comment', '')

    if action not in ['approve','deny']:
        return jsonify({'error': 'Invalid action'}), 400

    # Level 1 approval
    if role == 'approver1':
        if req['status_level1'] != 'pending':
            return jsonify({'error': 'Level 1 approval already done'}), 400
        status_level1 = 'approved' if action == 'approve' else 'denied'

        # If denied, level2 status auto denied too
        status_level2 = req['status_level2']
        if status_level1 == 'denied':
            status_level2 = 'denied'
        c.execute('''
            UPDATE requests 
            SET status_level1 = ?, comments_level1 = ?, status_level2 = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status_level1, comment, status_level2, req_id))
        db.commit()

        if status_level1 != 'denied':
            approver2_emails = get_user_emails_by_role('approver2')
            if approver2_emails:
                print("################")
                print(approver2_emails)
                subject = f"New Laptop Entry Request #{req_id} Awaiting Level 2 Approval"
                body = f"""A new laptop entry request has been created.
                Request ID: {req_id}
                Please review and approve/deny the request at your earliest convenience."""
                send_email(subject, body, approver2_emails)

        else:
            requester_emails = get_user_emails_by_role('requester')
            if requester_emails:
                    print("################")
                    print(requester_emails)
                    subject = f"New Laptop Entry Request #{req_id} Rejected"
                    body = f"""A new laptop entry request has been Rejected.
                    Request ID: {req_id} """
                    send_email(subject, body, requester_emails)


        return jsonify({'message': 'Level 1 approval updated'})

    # Level 2 approval
    elif role == 'approver2':
        if req['status_level1'] != 'approved':
            return jsonify({'error': 'Level 1 approval not completed or denied'}), 400
        if req['status_level2'] != 'pending':
            return jsonify({'error': 'Level 2 approval already done'}), 400
        status_level2 = 'approved' if action == 'approve' else 'denied'
        c.execute('''
            UPDATE requests
            SET status_level2 = ?, comments_level2 = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (status_level2, comment, req_id))
        db.commit()
        if status_level2 != 'denied':
            requester_emails = get_user_emails_by_role('requester')
            if requester_emails:
                print("################")
                print(requester_emails)
                subject = f"New Laptop Entry Request #{req_id} Approved"
                body = f"""A new laptop entry request has been Approved.
                Request ID: {req_id}
                """
                send_email(subject, body, requester_emails)

        else :
            requester_emails = get_user_emails_by_role('requester')
            if requester_emails:
                    print("################")
                    print(requester_emails)
                    subject = f"New Laptop Entry Request #{req_id} Rejected"
                    body = f"""A new laptop entry request has been Rejected.
                    Request ID: {req_id} """
                    send_email(subject, body, requester_emails)

        return jsonify({'message': 'Level 2 approval updated'})
    else:
        return jsonify({'error': 'Unauthorized'}), 403


@app.route('/api/requests/export/csv')
@login_required
def api_export_requests_csv():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        db = get_db()
        c = db.cursor()
        c.execute('SELECT * FROM requests ORDER BY created_at DESC')
        rows = c.fetchall()

        # Create a CSV output
        output = io.StringIO()
        cw = csv.writer(output)
        
        # Write the header row
        cw.writerow(['ID', 'Laptop Details', 'Requester Name', 'Company', 'Contact', 'Purpose', 'Entry Date', 'Level 1 Status', 'Level 1 Comments', 'Level 2 Status', 'Level 2 Comments', 'Created At', 'Updated At'])

        # Write data rows
        for r in rows:
            cw.writerow([
                r['id'],
                r['laptop_details'],
                r['requester_name'],
                r['company'],
                r['contact'],
                r['purpose'],
                r['entry_date'],
                r['status_level1'],
                r['comments_level1'],
                r['status_level2'],
                r['comments_level2'],
                r['created_at'],
                r['updated_at']
            ])

        # Get the CSV string
        output.seek(0)  # Move to the beginning of the StringIO object
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=laptop_entry_requests.csv"}
        )
    except Exception as e:
        app.logger.error(f"Error exporting CSV: {e}")
        return jsonify({'error': 'Failed to export CSV'}), 500



if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(host='0.0.0.0', port=8080, debug=True)
    #http_server = WSGIServer(('0.0.0.0', 8080), app)
    #http_server.serve_forever()
