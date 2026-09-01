from rsa_keys import generate_rsa_key_pair
from crypto import (
    encrypt_for_recipient,
    decrypt_received_message,
    create_message_signature,
    verify_message_signature
)


# ==========================================
# GENERATE ALICE AND BOB KEYS
# ==========================================

alice_private_key, alice_public_key = generate_rsa_key_pair()
bob_private_key, bob_public_key = generate_rsa_key_pair()

print("Alice's RSA key pair generated.")
print("Bob's RSA key pair generated.")
print()


# ==========================================
# ALICE ENCRYPTS MESSAGE FOR BOB
# ==========================================

message = "Hello Bob! This message is authenticated."

encrypted_aes_key, nonce, ciphertext = encrypt_for_recipient(
    message,
    bob_public_key
)

print("Message encrypted.")
print()


# ==========================================
# ALICE SIGNS ENCRYPTED PACKAGE
# ==========================================

signature = create_message_signature(
    encrypted_aes_key,
    nonce,
    ciphertext,
    alice_private_key
)

print("Message signature created.")
print()


# ==========================================
# BOB VERIFIES SIGNATURE
# ==========================================

valid = verify_message_signature(
    encrypted_aes_key,
    nonce,
    ciphertext,
    signature,
    alice_public_key
)

print("Signature valid:")
print(valid)
print()


# ==========================================
# BOB DECRYPTS MESSAGE
# ==========================================

decrypted_message = decrypt_received_message(
    encrypted_aes_key,
    nonce,
    ciphertext,
    bob_private_key
)

print("Decrypted message:")
print(decrypted_message)
print()


# ==========================================
# TAMPERING TEST
# ==========================================

tampered_ciphertext = bytearray(ciphertext)

tampered_ciphertext[0] ^= 1

tampered_ciphertext = bytes(tampered_ciphertext)

tampered_valid = verify_message_signature(
    encrypted_aes_key,
    nonce,
    tampered_ciphertext,
    signature,
    alice_public_key
)

print("After ciphertext tampering:")
print("Signature valid:")
print(tampered_valid)