#!/usr/bin/env python3
# aMiscreant
"""
ToDo
    one consistent working directory for keys / gnupg {once working migrate to encrypted USB/SD Card}.
    E2E - apply.
    Fix received mail layout & visuals.
    Generate stronger gpg keys; and encrypted the keys. Decrypt per call / use.
"""
import os
import random
import secrets
import threading
from pathlib import Path

import gnupg
from flask import Flask, Response
from flask import render_template, redirect, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from stem.control import Controller
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

from utils.tormail_database import load_invites, mark_invite_used, load_users, save_users

# CONFIG: paths
TORMAIL_DIR = Path.home() / ".tormail"
TORMAIL_DIR.mkdir(mode=0o700, exist_ok=True)
SECRET_FILE = TORMAIL_DIR / "secret"     # persisted secret (0600)
SALT_FILE = TORMAIL_DIR / "salt"         # salt for KDF
INVITES_FILE = TORMAIL_DIR / "invites.enc"  # encrypted invites (0600)

# Max users
MAX_USERS = 10

# KDF parameters
KDF_ITERATIONS = 390_000

# Invite Codes / Daily Codes needed for login.
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    token = PasswordField('Token', validators=[DataRequired()])
    invite = StringField('Invite', validators=[DataRequired()])  # Add this line
    submit = SubmitField('Login')

class DecryptForm(FlaskForm):
    message_id = StringField("message_id")
    submit = SubmitField("Decrypt Message")

class SendMessageForm(FlaskForm):
    recipient = StringField("Recipient", validators=[DataRequired()])
    message = StringField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")

# Invite Codes / Daily Codes needed account creation.
class CreateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    token = PasswordField('Token', validators=[DataRequired()])
    invite = StringField('Invite', validators=[DataRequired()])  # Add this line
    submit = SubmitField('Create Account')


# Flask app setup
app = Flask(__name__)
secret_value = secrets.token_hex(64)
app.secret_key = secret_value
app.config['WTF_CSRF_SECRET_KEY'] = secret_value
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Use only secure cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent CSRF

limiter = Limiter(key_func=get_remote_address, default_limits=["100 per day", "10 per hour"])
limiter.init_app(app)


# Persistent GPG directory for testing (use tempfile.mkdtemp() for ephemeral)
gpg_home = os.path.expanduser("~/.tormail_keys")
os.makedirs(gpg_home, exist_ok=True)
print(f"[GPG] Using key home: {gpg_home}")
gpg = gnupg.GPG(gnupghome=gpg_home)

# In-memory message store
messages = {}

# Set various security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; script-src 'self';"
    return response

def current_user_count():
    keys = gpg.list_keys(secret=True)
    return len(keys)


@app.route('/create', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def create_account():
    form = CreateAccountForm()
    users = load_users()

    if len(users) >= MAX_USERS:
        return "❌ Registration closed: max users reached", 403

    if form.validate_on_submit():
        username = form.username.data.strip()
        token = form.token.data.strip()
        invite_code = form.invite.data.strip()

        invites = load_invites()
        if invite_code not in invites or invites[invite_code]:
            return "❌ Invalid or used invite code", 400

        email = f"{username}@tormail.onion"
        # Generate GPG key
        input_data = gpg.gen_key_input(name_email=email, passphrase=token, key_type="RSA", key_length=2048)
        key = gpg.gen_key(input_data)
        if not key.fingerprint:
            return "❌ Failed to generate keys", 500

        # Mark invite as used
        mark_invite_used(invite_code)
        # Store user token (Fernet encrypted)
        users[email] = token
        save_users(users)

        print(f"[+] Created user {email} ({key.fingerprint})")
        return redirect('/')

    return render_template("create_user.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    users = load_users()

    if form.validate_on_submit():
        username = form.username.data.strip()
        token = form.token.data.strip()
        email = f"{username}@tormail.onion"

        stored_token = users.get(email)
        if not stored_token or stored_token != token:
            return "[Error!] Invalid username or password", 403

        # Login successful
        session['username'] = username
        session['token'] = token
        return redirect(f"/inbox?user={username}")

    headers = {
        "Server": f"Apache/{random.randint(2,5)}.{random.randint(0,9)}.phantom",
        "X-Clue": os.urandom(8).hex(),
        "X-Security": random.choice(["On","Off"]),
        "X-Fingerprint": os.urandom(6).hex()
    }
    return Response(render_template("login.html", form=form), headers=headers)

@app.route('/inbox')
@limiter.limit("5 per minute")
def inbox():
    if 'username' not in session or 'token' not in session:
        return redirect('/')

    user = session['username']
    token = session['token']
    user_email = f"{user}@tormail.onion"

    inbox_messages = messages.get(user_email, [])

    decrypted_messages = []
    for idx, msg in enumerate(inbox_messages):
        encrypted_content = msg['encrypted']

        # Decrypt with user token
        decrypted = gpg.decrypt(str(encrypted_content), passphrase=token)

        decrypted_messages.append({
            'id': idx,
            'from': msg['from'],
            'content': str(decrypted) if decrypted.ok else "[Error!] Decryption failed"
        })

    send_form = SendMessageForm()
    decrypt_form = DecryptForm()

    return render_template(
        "inbox.html",
        user=user,
        inbox=decrypted_messages,
        send_form=send_form,
        decrypt_form=decrypt_form
    )

@app.route('/send', methods=['POST'])
@limiter.limit("5 per minute")
def send_message():
    # Ensure user is logged in
    sender = session.get('username')
    token = session.get('token')
    if not sender or not token:
        return redirect('/')

    form = SendMessageForm()
    if not form.validate_on_submit():
        print(form.errors)
        return "❌ Invalid form data", 400

    recipient_input = form.recipient.data.strip()
    message = form.message.data.strip()

    # Ensure the recipient is formatted as an onion email
    recipient_email = (
        recipient_input if "@tormail.onion" in recipient_input else f"{recipient_input}@tormail.onion"
    )

    # Lookup recipient GPG key
    keys = gpg.list_keys()
    match = [k for k in keys if any(recipient_email in uid for uid in k['uids'])]
    if not match:
        return "[Error!] Recipient not found", 404

    fingerprint = match[0]['fingerprint']

    # Encrypt the message
    encrypted = gpg.encrypt(message, fingerprint)
    if not encrypted.ok:
        return "[Error!] Encryption failed", 500

    # Store message in-memory under recipient
    messages.setdefault(recipient_email, []).append({
        "from": f"{sender}@tormail.onion",
        "encrypted": str(encrypted)  # ensure string for consistent decryption
    })

    print(f"[+] Stored message from {sender} to {recipient_email}")
    return redirect("/inbox")  # session ensures correct user inbox


@app.route('/decrypt', methods=['POST'])
@limiter.limit("5 per minute")
def decrypt_message():
    # Ensure user is logged in
    user = session.get('username')
    token = session.get('token')
    if not user or not token:
        return redirect('/')

    form = DecryptForm()
    if not form.validate_on_submit():
        return "[Error!] Invalid form data", 400

    try:
        message_id = int(form.message_id.data.strip())
    except ValueError:
        return "[Error!] Message ID must be an integer", 400

    inbox_messages = messages.get(f"{user}@tormail.onion", [])

    # Check if message ID is valid
    if message_id < 0 or message_id >= len(inbox_messages):
        return "[Error!] Invalid message ID", 400

    # Decrypt the message
    message = inbox_messages[message_id]
    decrypted = gpg.decrypt(str(message['encrypted']), passphrase=token)

    if decrypted.ok:
        return render_template("decrypted_message.html", content=str(decrypted), user=user)
    else:
        print(f"[Error!] Decryption failed for message ID {message_id} of {user}")
        return "[Error!] Decryption failed", 500


@app.route('/logout')
@limiter.limit("5 per minute")
def logout():
    session.clear()
    return redirect('/')

@app.route('/')
@limiter.limit("5 per minute")
def index():
    headers = {
        "Server": f"Apache/{random.randint(2, 5)}.{random.randint(0, 9)}.phantom",
        "X-Clue": os.urandom(8).hex(),
        "X-Security": random.choice(["On", "Off"]),
        "X-Fingerprint": os.urandom(6).hex()
    }

    form = LoginForm()
    html = render_template("login.html", form=form)
    return Response(html, headers=headers)

@app.route('/<path:random_path>')
@limiter.limit("2 per minute")
def catch_all(random_path):
    return f"<h1>404 Not Found ({random_path})</h1>", 404

# 🧅 Tor ephemeral hidden service
def start_hidden_service():
    key_path = os.path.expanduser("~/.icebridge/tor/key")
    with Controller.from_port() as controller:
        controller.authenticate()

        if os.path.exists(key_path):
            with open(key_path) as f:
                key_type, key_content = f.read().strip().split(":", 1)

            service = controller.create_ephemeral_hidden_service(
                {443: 5000},
                key_type=key_type,
                key_content=key_content,
                await_publication=True
            )

            print(f"[ok!] Onion ready at: {service.service_id}.onion")

            # Example: serve on HTTPS using cert and key files
            threading.Thread(target=app.run, kwargs={
                "host": "0.0.0.0",
                "port": 5000,
                "ssl_context": ("cert.pem", "key.pem")  # paths to your cert and key
            }).start()

            input(" Press Enter to shut down hidden service...")
            controller.remove_ephemeral_hidden_service(service.service_id)
        else:
            print("[Error!] Key not found at ~/.icebridge/tor/key")
            exit(1)

if __name__ == "__main__":
    invites = load_invites()
    print("\n[[ok!]  Invite Codes for testing]")
    for code, used in invites.items():
        status = "USED" if used else "AVAILABLE"
        print(f"  {code} → {status}")
    print("\n[[ok!] Starting hidden service...]\n")
    start_hidden_service()
