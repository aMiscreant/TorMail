# 🔐  TorMail

**TorMail** is a secure, Flask-based, ephemeral messaging system that runs over the Tor network. It leverages GPG for end-to-end encryption and uses an ephemeral hidden service to avoid persistent traces. This is ideal for anonymous, encrypted communication between parties with no disk-based message storage.

---

## 🔐 Features

- Ephemeral Tor hidden service powered by [`stem`](https://stem.torproject.org/)
- GPG-based identity creation and encrypted message exchange
- In-memory message storage (RAM only – nothing saved to disk)
- Secure session management and login validation
- Minimal web UI (via Flask templates)
- Rate limiting via `flask-limiter` to mitigate abuse
- Strong security headers and randomized server response info

---

## 📦 Requirements

- Python 3.11
- [GnuPG](https://gnupg.org/) installed and available in your system path
- Tor daemon running with ControlPort enabled (`ControlPort 9051` and a password or cookie auth)
- Python packages:
  - Flask
  - Flask-Limiter
  - python-gnupg
  - stem

Install dependencies:

```bash
pip install flask flask-limiter python-gnupg stem
