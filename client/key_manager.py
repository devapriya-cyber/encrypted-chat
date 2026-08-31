import os

from cryptography.hazmat.primitives import serialization

from rsa_keys import generate_rsa_key_pair


KEYS_FOLDER = "keys"


def get_user_key_paths(username):
    """Return paths for a user's RSA keys."""

    os.makedirs(KEYS_FOLDER, exist_ok=True)

    private_path = os.path.join(
        KEYS_FOLDER,
        f"{username}_private.pem"
    )

    public_path = os.path.join(
        KEYS_FOLDER,
        f"{username}_public.pem"
    )

    return private_path, public_path


def generate_and_save_keys(username):
    """Generate and save a user's RSA key pair."""

    private_key, public_key = generate_rsa_key_pair()

    private_path, public_path = get_user_key_paths(username)

    # Save private key
    with open(private_path, "wb") as file:
        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    with open(public_path, "wb") as file:
        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return private_key, public_key


def load_private_key(username):
    """Load a user's private RSA key."""

    private_path, _ = get_user_key_paths(username)

    with open(private_path, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None
        )

    return private_key


def load_public_key(username):
    """Load a user's public RSA key."""

    _, public_path = get_user_key_paths(username)

    with open(public_path, "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read()
        )

    return public_key