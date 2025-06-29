# TorMail 🧅

**TorMail** is an experimental, ephemeral Tor hidden-service mail system built with Flask, GNUPG, and Stem. It’s designed for private, temporary communication where:

✅ All messages are **end-to-end encrypted** using GPG  
✅ User identities exist only as ephemeral GPG keys  
✅ Messages live purely **in-memory**, leaving no disk traces  
✅ Access happens only through a Tor hidden service  

---

## 🔐 How It Works

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

## ⚠️ Limitations & Warnings

- **No persistence.** Messages vanish if the server restarts.
- Not production-grade — research use only.
- Requires Tor Browser or a SOCKS5 proxy to access the hidden service.

---

## 🚀 Future Development Goals

![Uploading ComingSoon.png…]()

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

## 💻 Running TorMail

Clone and launch:

```bash
git clone https://github.com/aMiscreant/TorMail
cd TorMail
python3 tormail.py
```

![ComingSoon](https://github.com/user-attachments/assets/1f33ef23-6a40-4735-ba20-ad16f4855afd)

### ✅ `LICENSE` (MIT)

```text
MIT License

Copyright (c) 2025 Source Direct Hub

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in  
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN  
THE SOFTWARE.
