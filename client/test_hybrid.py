from rsa_keys import generate_rsa_key_pair
from crypto import (
    encrypt_for_recipient,
    decrypt_received_message
)


# ==========================================
# BOB CREATES HIS RSA KEY PAIR
# ==========================================

bob_private_key, bob_public_key = generate_rsa_key_pair()

print("Bob's RSA key pair generated.")
print()


# ==========================================
# ALICE WRITES A MESSAGE
# ==========================================

message = "Hello Bob! This message is end-to-end encrypted."

print("Alice's original message:")
print(message)
print()


# ==========================================
# ALICE ENCRYPTS THE MESSAGE
# ==========================================

encrypted_aes_key, nonce, ciphertext = encrypt_for_recipient(
    message,
    bob_public_key
)

print("Message encrypted.")
print()

print("Encrypted AES key:")
print(encrypted_aes_key.hex())
print()

print("Nonce:")
print(nonce.hex())
print()

print("Ciphertext:")
print(ciphertext.hex())
print()


# ==========================================
# BOB RECEIVES AND DECRYPTS
# ==========================================

decrypted_message = decrypt_received_message(
    encrypted_aes_key,
    nonce,
    ciphertext,
    bob_private_key
)

print("Bob's decrypted message:")
print(decrypted_message)