# TorMail 🧅

**TorMail** is an experimental, ephemeral Tor hidden-service mail system built with Flask, GNUPG, and Stem. It’s designed for private, temporary communication where:

- All messages are **end-to-end encrypted** using GPG  
- User identities exist only as ephemeral GPG keys  
- Messages live purely **in-memory**, leaving no disk traces  
- Access happens only through a Tor hidden service  

---

## How It Works

- **Ephemeral Tor Hidden Service**  
    Launches a unique `.onion` address on startup, forwarding traffic to the Flask app.

- **User Accounts**  
    Users generate GPG key pairs tied to `<username>@tormail.onion`, protected by a private passphrase.

- **Authentication**  
    Users decrypt a test message during login to prove key ownership.

- **Messaging**  
    - All messages are GPG-encrypted.  
    - Stored in RAM only while the server is running.  
    - Decrypted only on demand via user sessions.

- **Security Features**  
    - Strict Content Security Policy  
    - Rate-limiting on all endpoints  
    - Randomized HTTP headers to disguise the server fingerprint

---

## Limitations & Warnings

- **No persistence.** Messages vanish if the server restarts.
- Not production-grade — research use only.
- Requires Tor Browser or a SOCKS5 proxy to access the hidden service.

---

## Future Development Goals

TorMail is evolving. Future versions aim to:

- **Implement offline message storage:**
    - Store encrypted mail on an OpenLog SD card module.
    - Operate the SD card with selective hardware isolation:
        - Disable RX/TX lines to physically prevent data exfiltration or tampering.
    - Keep keys and decrypted content out of persistent storage entirely.

- **Enhance security:**
    - Stronger session management.
    - Client-side crypto for additional secrecy.
    - Hardened endpoints and input validation.

- **Improve UX:**
    - Richer HTML templates for inbox and mail composition.
    - Per-message decryption on demand.
    - Optional vanity `.onion` addresses.

---

## Running TorMail

- Clone and launch:

```bash
git clone https://github.com/aMiscreant/TorMail
cd TorMail
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# generate cert.pem and key.pem for https
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=YOUR_VANITY.onion"
python3 tormail.py
```

**ROADMAP** to __v1.0__

>
![ComingSoon](https://github.com/user-attachments/assets/1f33ef23-6a40-4735-ba20-ad16f4855afd)
>

**ROADMAP** to branch __v1-s1__

>
Encrypted NAND Flash to store keys.
>


---

DEV NOTES

---

# **Usage**

## 1. Prepare GPG key directory
```bash
mkdir -p ~/.tormail_keys

```

## 2. Generate and save your Tor hidden service key:
```bash
mkdir -p ~/.icebridge/tor
echo "ED25519-V3:<your_key_here>" > ~/.icebridge/tor/key

```

    NOTE: You can generate this key using stem or Tor itself via ADD_ONION command.

## 3. Run TorMail
python tormail.py

### Once running, it will:
    Spawn a Flask server bound to 0.0.0.0:5000
    Start an ephemeral Tor hidden service pointing to it
    Output your .onion address to the terminal

### Endpoints:
    / – Login page
    /create – Create a new GPG-secured inbox
    /login – Validate access using GPG identity
    /inbox – View and decrypt received messages
    /send – Send encrypted messages to other users
    /decrypt – On-demand decryption of individual messages
    /logout – Clear session
    /<random> – Catch-all 404

### Example Use
    Create a user via /create
    Login using the username and passphrase
    Use /send to deliver messages to other TorMail users
    Check /inbox to read your encrypted messages in-session


generate cert.pem and key.pem
```bash
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=YOUR_VANITY.onion"

```

# Disclaimer

**This project is educational and should not be considered production-grade. No persistent encryption or storage safeguards are applied beyond memory. Use at your own risk.**
