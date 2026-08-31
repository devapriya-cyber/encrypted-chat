from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

from rsa_keys import (
    encrypt_with_public_key,
    decrypt_with_private_key
)


def generate_aes_key():
    """Generate a random 256-bit AES key."""
    return AESGCM.generate_key(
        bit_length=256
    )


def encrypt_message(message, key):
    """Encrypt a message using AES-256-GCM."""

    aes = AESGCM(key)

    # 12-byte nonce recommended for AES-GCM
    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce, ciphertext


def decrypt_message(nonce, ciphertext, key):
    """Decrypt an AES-256-GCM encrypted message."""

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


def encrypt_for_recipient(
    message,
    recipient_public_key
):
    """
    Encrypt the message using AES-256-GCM,
    then encrypt the AES key using the
    recipient's RSA public key.
    """

    # Generate unique AES session key
    aes_key = generate_aes_key()

    # Encrypt message using AES
    nonce, ciphertext = encrypt_message(
        message,
        aes_key
    )

    # Encrypt AES key using recipient's RSA public key
    encrypted_aes_key = encrypt_with_public_key(
        aes_key,
        recipient_public_key
    )

    return (
        encrypted_aes_key,
        nonce,
        ciphertext
    )


def decrypt_received_message(
    encrypted_aes_key,
    nonce,
    ciphertext,
    private_key
):
    """
    Recover the AES key using RSA,
    then decrypt the message using AES.
    """

    # Recover AES session key
    aes_key = decrypt_with_private_key(
        encrypted_aes_key,
        private_key
    )

    # Decrypt message
    message = decrypt_message(
        nonce,
        ciphertext,
        aes_key
    )

    return message