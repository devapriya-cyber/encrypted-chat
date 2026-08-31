from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


def generate_rsa_key_pair():
    """Generate an RSA public/private key pair."""

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    public_key = private_key.public_key()

    return private_key, public_key


def encrypt_with_public_key(data, public_key):
    """Encrypt data using an RSA public key."""

    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_data


def decrypt_with_private_key(encrypted_data, private_key):
    """Decrypt RSA-encrypted data using the private key."""

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_data
def sign_data(data, private_key):
    """Create an RSA-PSS digital signature."""

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(data, signature, public_key):
    """Verify an RSA-PSS digital signature."""

    try:

        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception:

        return False