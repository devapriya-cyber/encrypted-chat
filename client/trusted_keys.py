import json
import os


TRUSTED_KEYS_FILE = "trusted_keys.json"


def load_trusted_keys():
    """Load previously trusted public-key fingerprints."""

    if not os.path.exists(TRUSTED_KEYS_FILE):
        return {}

    with open(TRUSTED_KEYS_FILE, "r") as file:
        return json.load(file)


def save_trusted_key(username, fingerprint):
    """Save a trusted fingerprint."""

    trusted_keys = load_trusted_keys()

    trusted_keys[username] = fingerprint

    with open(TRUSTED_KEYS_FILE, "w") as file:
        json.dump(
            trusted_keys,
            file,
            indent=4
        )


def get_trusted_fingerprint(username):
    """Return the trusted fingerprint for a user."""

    trusted_keys = load_trusted_keys()

    return trusted_keys.get(username)