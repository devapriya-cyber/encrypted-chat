import json
import os


# Always store trusted keys next to this script.
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

TRUSTED_KEYS_FILE = os.path.join(
    BASE_DIR,
    "trusted_keys.json"
)


def load_trusted_keys():
    """Load previously trusted public-key fingerprints."""

    if not os.path.exists(TRUSTED_KEYS_FILE):
        return {}

    with open(
        TRUSTED_KEYS_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def save_trusted_key(username, fingerprint):
    """Save a trusted public-key fingerprint."""

    trusted_keys = load_trusted_keys()

    trusted_keys[username] = fingerprint

    with open(
        TRUSTED_KEYS_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            trusted_keys,
            file,
            indent=4
        )


def get_trusted_fingerprint(username):
    """Return the trusted fingerprint for a user."""

    trusted_keys = load_trusted_keys()

    return trusted_keys.get(username)