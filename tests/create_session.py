"""Create a session cookie for a given user ID.

Uses SECRET_KEY and REDIS_URL from environment variables.
Default values match the Docker integration container configuration.
"""
import sys
import os
import json
import hashlib
import hmac
import secrets
import time

import redis

# Use env vars that match the Docker container's config.
# The Docker API container uses: test-secret-key-for-integration-only-not-for-production-32chars!
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "test-secret-key-for-integration-only-not-for-production-32chars!",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6380/0")


def create_session(user_id: str) -> str:
    """Create a session in Redis and return the cookie value."""
    r = redis.from_url(REDIS_URL, decode_responses=True)
    session_id = secrets.token_hex(32)
    signature = hmac.new(
        SECRET_KEY.encode(),
        session_id.encode(),
        hashlib.sha256,
    ).hexdigest()
    cookie = f"{session_id}.{signature}"

    session_data = json.dumps({
        "user_id": user_id,
        "created_at": str(int(time.time())),
        "last_access": str(int(time.time())),
    })
    r.setex(f"session:{session_id}", 3600, session_data)
    r.close()
    return cookie


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python create_session.py <user_id>", file=sys.stderr)
        sys.exit(1)
    user_id = sys.argv[1]
    cookie = create_session(user_id)
    print(cookie)
