"""Create .env from .env.example and fill the generated secrets. Never prints a secret."""

import base64
import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parent.parent
env, example = root / ".env", root / ".env.example"

generators = {
    "JWT_SECRET": lambda: secrets.token_hex(32),
    # Same format as cryptography's Fernet.generate_key(), without needing the package.
    "CREDENTIAL_KEY": lambda: base64.urlsafe_b64encode(os.urandom(32)).decode(),
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(24),
}

lines = (env if env.exists() else example).read_text().splitlines()
filled = []
out = []
for line in lines:
    key, sep, value = line.partition("=")
    if sep and key in generators and not value.strip():
        line = f"{key}={generators[key]()}"
        filled.append(key)
    out.append(line)
env.write_text("\n".join(out) + "\n")
env.chmod(0o600)
print(f".env ready ({', '.join(filled) or 'nothing new'} generated). It is git-ignored; keep it private.")
