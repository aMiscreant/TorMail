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

# Flask app setup
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong random session key

limiter = Limiter(key_func=get_remote_address, default_limits=["100 per day", "10 per hour"])
limiter.init_app(app)

# Persistent GPG directory for testing (use tempfile.mkdtemp() for ephemeral)
gpg_home = os.path.expanduser("~/.tormail_keys")
os.makedirs(gpg_home, exist_ok=True)
print(f"[GPG] Using key home: {gpg_home}")
gpg = gnupg.GPG(gnupghome=gpg_home)

# In-memory message store
messages = {}

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/create', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        token = request.form['token']
        email = f"{username}@tormail.onion"

        input_data = gpg.gen_key_input(
            name_email=email,
            passphrase=token,
            key_type="RSA",
            key_length=2048
        )
        key = gpg.gen_key(input_data)

        if key.fingerprint:
            print(f"[+] Created GPG identity: {email} ({key.fingerprint})")
            return redirect('/')
        else:
            return "❌ Failed to generate keys", 500

    return render_template("create_user.html")

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form['username']
    session['username'] = username
    token = request.form['token']
    email = f"{username}@tormail.onion"

    keys = gpg.list_keys(secret=True)
    matching = [k for k in keys if any(email in uid for uid in k['uids'])]

    if not matching:
        return "❌ No such user", 404

    test_message = "test"
    encrypted = gpg.encrypt(test_message, matching[0]['fingerprint'])

    if not encrypted.ok:
        return "❌ Encryption error", 500

    decrypted = gpg.decrypt(str(encrypted), passphrase=token)

    if str(decrypted) == test_message:
        return redirect(f"/inbox?user={username}")
    else:
        return "❌ Login failed", 403

@app.route('/send', methods=['POST'])
@limiter.limit("5 per minute")
def send_message():
    sender = session.get('username')
    if not sender:
        return redirect('/')

    recipient_input = request.form['recipient']
    message = request.form['message']

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


@app.route('/inbox')
@limiter.limit("5 per minute")
def inbox():
    user = request.args.get("user", "unknown")
    user_email = f"{user}@tormail.onion"
    inbox_messages = messages.get(user_email, [])

    # Decrypt messages for the user
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

    return render_template("inbox.html", user=user, inbox=decrypted_messages)


@app.route('/decrypt', methods=['POST'])
@limiter.limit("5 per minute")
def decrypt_message():
    try:
        message_id = int(request.form['message_id'])
        user = session.get('username')
        inbox_messages = messages.get(f"{user}@tormail.onion", [])

        if message_id < 0 or message_id >= len(inbox_messages):
            return "❌ Invalid message ID", 400

        message = inbox_messages[message_id]
        decrypted = gpg.decrypt(message['encrypted'], passphrase=session.get('token'))

        if decrypted.ok:
            return render_template("decrypted_message.html", content=str(decrypted), user=user)
        else:
            return "❌ Decryption failed", 500

    except (ValueError, KeyError, IndexError) as e:
        return f"❌ Error: {str(e)}", 400

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

    html = render_template("login.html")
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
                {80: 5000},
                key_type=key_type,
                key_content=key_content,
                await_publication=True
            )

            print(f"[✅] Onion ready at: {service.service_id}.onion")
            threading.Thread(target=app.run, kwargs={"host": "0.0.0.0", "port": 5000}).start()

            input("🔒 Press Enter to shut down hidden service...")
            controller.remove_ephemeral_hidden_service(service.service_id)
        else:
            print("❌ Key not found at ~/.icebridge/tor/key")
            exit(1)

if __name__ == "__main__":
    start_hidden_service()
