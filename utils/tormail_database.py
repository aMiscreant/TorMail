import base64
import json
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def ensure_secret():
    env_secret = os.getenv("TORMAIL_SECRET")
    if env_secret:
        return env_secret.encode("utf-8")
    from tormail import SECRET_FILE
    if SECRET_FILE.exists():
        SECRET_FILE.chmod(0o600)
        secret_bytes = base64.urlsafe_b64decode(SECRET_FILE.read_bytes())
        return secret_bytes
    secret = os.urandom(32)
    SECRET_FILE.write_bytes(base64.urlsafe_b64encode(secret))
    SECRET_FILE.chmod(0o600)
    return secret

def get_or_create_salt():
    from tormail import SALT_FILE
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    return salt

def derive_fernet_key(secret_bytes: bytes, salt: bytes) -> bytes:
    from tormail import KDF_ITERATIONS
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(secret_bytes)
    return base64.urlsafe_b64encode(key)

def load_invites() -> dict:
    """
    Load invites from file. If no file exists, generate MAX_USERS random invites.
    """
    secret = ensure_secret()
    salt = get_or_create_salt()
    f = Fernet(derive_fernet_key(secret, salt))

    from tormail import INVITES_FILE
    if not INVITES_FILE.exists():
        # Generate exactly MAX_USERS random invites
        from tormail import MAX_USERS
        invites = {secrets.token_hex(8): False for _ in range(MAX_USERS)}
        save_invites(invites)
        return invites

    ct = INVITES_FILE.read_bytes()
    try:
        pt = f.decrypt(ct)
    except Exception as e:
        raise RuntimeError("Failed to decrypt invites file: " + str(e))
    invites = json.loads(pt.decode("utf-8"))
    return invites

def save_invites(invites: dict):
    secret = ensure_secret()
    salt = get_or_create_salt()
    f = Fernet(derive_fernet_key(secret, salt))

    plaintext = json.dumps(invites).encode("utf-8")
    token = f.encrypt(plaintext)

    from tormail import INVITES_FILE
    tmp = INVITES_FILE.with_suffix(".tmp")
    tmp.write_bytes(token)
    tmp.chmod(0o600)
    tmp.replace(INVITES_FILE)
    INVITES_FILE.chmod(0o600)

def mark_invite_used(invite_code: str) -> bool:
    invites = load_invites()
    if invite_code not in invites:
        return False
    if invites[invite_code] is True:
        return False
    invites[invite_code] = True
    save_invites(invites)
    return True

def load_users() -> dict:
    from tormail import TORMAIL_DIR
    users_file = TORMAIL_DIR / "users.enc"
    secret = ensure_secret()
    salt = get_or_create_salt()
    f = Fernet(derive_fernet_key(secret, salt))
    if not users_file.exists():
        return {}
    ct = users_file.read_bytes()
    pt = f.decrypt(ct)
    return json.loads(pt.decode("utf-8"))

def save_users(users: dict):
    from tormail import TORMAIL_DIR
    users_file = TORMAIL_DIR / "users.enc"
    secret = ensure_secret()
    salt = get_or_create_salt()
    f = Fernet(derive_fernet_key(secret, salt))
    pt = json.dumps(users).encode("utf-8")
    users_file.write_bytes(f.encrypt(pt))
    users_file.chmod(0o600)