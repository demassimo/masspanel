"""Verify imported Unix hashes without changing customers' passwords."""
import hmac
import re
from argon2.exceptions import VerificationError, InvalidHashError

SHA512 = re.compile(r"\$6\$(?:rounds=([0-9]{4,7})\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}")


def supported_legacy_hash(value):
    match = SHA512.fullmatch(value) if isinstance(value, str) else None
    return bool(match and (not match[1] or 1000 <= int(match[1]) <= 1000000))


def verify_password(hasher, encoded, password):
    if not isinstance(password, str) or not 1 <= len(password) <= 256:
        return False
    if supported_legacy_hash(encoded):
        # Ubuntu 24.04 ships Python 3.12 and libxcrypt. Imported hashes are
        # upgraded to Argon2 after successful authentication, never by resetting.
        try:
            import crypt
            actual = crypt.crypt(password, encoded)
        except (ImportError, ValueError, OSError):
            return False
        return bool(actual and hmac.compare_digest(actual, encoded))
    try:
        return hasher.verify(encoded, password)
    except (VerificationError, InvalidHashError, TypeError):
        return False
