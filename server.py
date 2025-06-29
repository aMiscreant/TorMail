import os
import random
import secrets
import threading

import gnupg
from flask import Flask, Response, render_template, request, session
from flask import redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from stem.control import Controller
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

# Set MAX user count
MAX_USERS = 10

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

# Store on OpenLog device in the future
valid_invites = {
    "a53266df72bb1e36": False,
    "d50ce17e462b4fe7": False,
    "5e208a137f39da7d": False,
    "840a5f41c5eadc1e": False,
    "b9600bdd11c089df": False,
    "a1879401938d0e64": False,
    "57ce8e85bec1b645": False,
    "5bd20eb098f92705": False,
}

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

    # First, block if max users reached
    if current_user_count() >= MAX_USERS:
        return "❌ Registration is closed: max users reached", 403

    if request.method == 'POST':
        invite_code = request.form.get('invite', '').strip()

        # Validate invite code
        if invite_code not in valid_invites:
            return "❌ Invalid invite code", 400
        if valid_invites[invite_code] is True:
            return "❌ Invite code already used", 400

        username = request.form['username']
        token = request.form['token']
        #token = form.token.data
        email = f"{username}@tormail.onion"

        # Generate GPG keys, etc.
        input_data = gpg.gen_key_input(
            name_email=email,
            passphrase=token,
            key_type="RSA",
            key_length=2048
        )
        key = gpg.gen_key(input_data)

        if key.fingerprint:
            print(f"[+] Created GPG identity: {email} ({key.fingerprint})")

            # Mark invite as used
            valid_invites[invite_code] = True

            return redirect('/')
        else:
            return "❌ Failed to generate keys", 500

    return render_template("create_user.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    print(f"Request method: {request.method}")

    if form.validate_on_submit():
        print(f"Form validated: username={form.username.data}")
        username = form.username.data
        token = form.token.data
        email = f"{username}@tormail.onion"

        keys = gpg.list_keys(secret=True)
        matching = [k for k in keys if any(email in uid for uid in k['uids'])]

        if not matching:
            print("No matching GPG key found")
            return "❌ No such user", 404

        test_message = "test"
        encrypted = gpg.encrypt(test_message, matching[0]['fingerprint'])

        if not encrypted.ok:
            print("Encryption error")
            return "❌ Encryption error", 500

        decrypted = gpg.decrypt(str(encrypted), passphrase=token)

        if str(decrypted) == test_message:
            print("Login successful!")
            session['username'] = username
            session['token'] = token
            return redirect(f"/inbox?user={username}")
        else:
            print("Login failed: decryption mismatch")
            return "❌ Login failed", 403
    else:
        print(f"Form validation failed: errors={form.errors}")

    headers = {
        "Server": f"Apache/{random.randint(2, 5)}.{random.randint(0, 9)}.phantom",
        "X-Clue": os.urandom(8).hex(),
        "X-Security": random.choice(["On", "Off"]),
        "X-Fingerprint": os.urandom(6).hex()
    }

    html = render_template("login.html", form=form)
    return Response(html, headers=headers)


@app.route('/inbox')
@limiter.limit("5 per minute")
def inbox():
    user = request.args.get("user", "unknown")
    user_email = f"{user}@tormail.onion"
    inbox_messages = messages.get(user_email, [])

    decrypted_messages = []
    for msg in inbox_messages:
        encrypted_content = msg['encrypted']
        decrypted = gpg.decrypt(encrypted_content, passphrase=session.get('token'))

        if decrypted.ok:
            decrypted_messages.append({
                'from': msg['from'],
                'content': str(decrypted)
            })
        else:
            decrypted_messages.append({
                'from': msg['from'],
                'content': "❌ Decryption failed"
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
    sender = session.get('username')
    if not sender:
        return redirect('/')

    form = SendMessageForm()
    if form.validate_on_submit():
        recipient_input = form.recipient.data
        message = form.message.data
    else:
        print(form.errors)
        return "❌ Invalid form data", 400

    recipient_email = recipient_input if "@tormail.onion" in recipient_input else f"{recipient_input}@tormail.onion"

    keys = gpg.list_keys()
    match = [k for k in keys if any(recipient_email in uid for uid in k['uids'])]

    if not match:
        return "❌ Recipient not found", 404

    fingerprint = match[0]['fingerprint']
    encrypted = gpg.encrypt(message, fingerprint)

    if not encrypted.ok:
        return "❌ Encryption failed", 500

    # Store message in-memory under full recipient email
    messages.setdefault(recipient_email, []).append({
        "from": f"{sender}@tormail.onion",
        "encrypted": str(encrypted)
    })

    print(f"[DEBUG] Stored message from {sender} to {recipient_email}")
    return redirect(f"/inbox?user={sender}")


@app.route('/decrypt', methods=['POST'])
@limiter.limit("5 per minute")
def decrypt_message():
    if 'username' not in session or 'token' not in session:
        return redirect('/')

    form = DecryptForm()
    if form.validate_on_submit():
        message_id = int(form.message_id.data)
    else:
        return "❌ Invalid form data", 400

    user = session['username']
    token = session['token']
    inbox_messages = messages.get(f"{user}@tormail.onion", [])

    if message_id < 0 or message_id >= len(inbox_messages):
        return "❌ Invalid message ID", 400

    message = inbox_messages[message_id]
    decrypted = gpg.decrypt(message['encrypted'], passphrase=token)

    if decrypted.ok:
        return render_template("decrypted_message.html", content=str(decrypted), user=user)
    else:
        return "❌ Decryption failed", 500

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

            print(f"[✅] Onion ready at: {service.service_id}.onion")

            # Example: serve on HTTPS using cert and key files
            threading.Thread(target=app.run, kwargs={
                "host": "0.0.0.0",
                "port": 5000,
                "ssl_context": ("cert.pem", "key.pem")  # paths to your cert and key
            }).start()

            input("🔒 Press Enter to shut down hidden service...")
            controller.remove_ephemeral_hidden_service(service.service_id)
        else:
            print("❌ Key not found at ~/.icebridge/tor/key")
            exit(1)

if __name__ == "__main__":
    start_hidden_service()
