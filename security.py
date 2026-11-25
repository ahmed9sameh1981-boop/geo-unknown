import os, secrets, datetime as dt, pathlib
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()
ALGO = "HS256"
TOKEN_MIN = int(os.environ.get("GEO_TOKEN_MINUTES", "60"))

def _secret() -> str:
    """JWT secret comes from env, else a random key generated once into a 0600 file. Never in source."""
    env = os.environ.get("GEO_JWT_SECRET")
    if env:
        return env
    p = pathlib.Path(os.environ.get("GEO_SECRET_FILE", ".geo_secret"))
    if not p.exists():
        p.write_text(secrets.token_hex(32)); p.chmod(0o600)
    return p.read_text().strip()

def hash_pw(pw: str) -> str:
    return ph.hash(pw)

def verify_pw(h: str, pw: str) -> bool:
    try:
        return ph.verify(h, pw)
    except (VerifyMismatchError, Exception):
        return False

def check_strength(pw: str):
    if len(pw) < 12 or pw.lower() == pw or pw.isalpha() or not any(c.isdigit() for c in pw):
        raise ValueError("Password needs 12+ chars with upper, lower case and a digit")

def make_token(uid: int, role: str) -> str:
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=TOKEN_MIN)
    return jwt.encode({"sub": str(uid), "role": role, "exp": exp}, _secret(), algorithm=ALGO)

def read_token(t: str) -> dict:
    return jwt.decode(t, _secret(), algorithms=[ALGO])
