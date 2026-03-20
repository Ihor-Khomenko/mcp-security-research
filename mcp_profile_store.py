import base64
import json
import os
import re
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PROFILES_DIR = Path("mcp_saved_profiles")
VERSION = 1
PBKDF2_ITERATIONS = 480_000
SALT_LEN = 16

PROFILE_KEYS = (
    "mcp_type",
    "mcp_url",
    "mcp_auth_method",
    "mcp_token",
    "oauth_client_id",
    "oauth_client_secret",
    "oauth_token_url",
    "oauth_scope",
    "mcp_ssl_verify",
    "mcp_ssl_ca_bundle",
)


def ensure_dir() -> None:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)


def slugify(name: str) -> str:
    s = re.sub(r"[^\w\-.]", "_", (name or "").strip(), flags=re.UNICODE)
    s = s.strip("._-") or "profile"
    return s[:120]


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def save_profile(name: str, password: str, fields: dict) -> str:
    if not (password or "").strip():
        raise ValueError("Password is required.")
    ensure_dir()
    slug = slugify(name)
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    fernet = Fernet(key)
    out = {k: fields.get(k) for k in PROFILE_KEYS}
    payload = json.dumps(out, ensure_ascii=False).encode("utf-8")
    ciphertext = fernet.encrypt(payload)
    wrapper = {
        "version": VERSION,
        "salt": base64.b64encode(salt).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    path = PROFILES_DIR / f"{slug}.enc"
    path.write_text(json.dumps(wrapper), encoding="utf-8")
    return slug


def load_profile(name: str, password: str) -> dict:
    slug = slugify(name)
    path = PROFILES_DIR / f"{slug}.enc"
    if not path.is_file():
        raise FileNotFoundError(f"Profile not found: {name!r}")
    wrapper = json.loads(path.read_text(encoding="utf-8"))
    salt = base64.b64decode(wrapper["salt"])
    ciphertext = base64.b64decode(wrapper["ciphertext"])
    key = _derive_key(password, salt)
    fernet = Fernet(key)
    try:
        payload = fernet.decrypt(ciphertext)
    except InvalidToken as e:
        raise ValueError("Wrong password or corrupted profile.") from e
    return json.loads(payload.decode("utf-8"))


def list_profiles() -> list[str]:
    ensure_dir()
    return sorted(p.stem for p in PROFILES_DIR.glob("*.enc"))


def delete_profile(name: str) -> None:
    slug = slugify(name)
    path = PROFILES_DIR / f"{slug}.enc"
    if not path.is_file():
        raise FileNotFoundError(f"Profile not found: {name!r}")
    path.unlink()
