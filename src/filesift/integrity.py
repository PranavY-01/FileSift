"""Optional HMAC-SHA256 baseline authentication with downgrade protection (Spec §10.4, E14)."""

import hashlib
import hmac
import json
import os
from typing import Any

from filesift.errors import BaselineAuthError, ConfigError

KEY_ENV = "FILESIFT_KEY"
MIN_KEY_BYTES = 32
ALGORITHM = "hmac-sha256"


def load_key() -> bytes | None:
    value = os.environ.get(KEY_ENV)
    if value is None:
        return None
    try:
        key = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ConfigError(f"{KEY_ENV} is not valid UTF-8") from None
    if len(key) < MIN_KEY_BYTES:
        raise ConfigError(f"{KEY_ENV} must be at least {MIN_KEY_BYTES} bytes after UTF-8 encoding "
                          f"(got {len(key)}); unset it or supply a longer key")
    return key


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """Canonical form of a baseline object without its ``integrity`` field."""
    body = {k: v for k, v in obj.items() if k != "integrity"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _mac(obj: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_bytes(obj), hashlib.sha256).hexdigest()


def sign(obj: dict[str, Any], key: bytes) -> None:
    obj.pop("integrity", None)
    obj["integrity"] = {"algorithm": ALGORITHM, "mac": _mac(obj, key)}


def verify(obj: dict[str, Any], key: bytes | None) -> bool:
    """Apply the downgrade matrix. Returns True when the baseline is authenticated.

    ``obj`` is the raw parsed baseline; its ``integrity`` field is popped.
    """
    stored = obj.pop("integrity", None)
    if stored is None and key is None:
        return False
    if stored is None:
        raise BaselineAuthError(f"baseline has no MAC but {KEY_ENV} is set: refusing a possibly stripped "
                                "(downgraded) baseline")
    if key is None:
        raise BaselineAuthError(f"baseline is authenticated but {KEY_ENV} is not set: cannot verify it")
    if not hmac.compare_digest(_mac(obj, key), stored["mac"]):
        raise BaselineAuthError("baseline MAC does not match: the baseline was modified or the key is wrong")
    return True
