import hashlib
from cryptography.hazmat.primitives import serialization


def get_public_key_fingerprint(public_key):
    """
    Generate a SHA-256 fingerprint
    from an RSA public key.
    """

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fingerprint = hashlib.sha256(
        public_key_bytes
    ).hexdigest()

    # Format into readable groups
    return ":".join(
        fingerprint[i:i + 4]
        for i in range(0, len(fingerprint), 4)
    )