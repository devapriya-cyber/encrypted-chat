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
# ALICE CREATES MESSAGE
# ==========================================

message = "Hello Bob! This message is authenticated."

message_id = "msg-001"

encrypted_aes_key, nonce, ciphertext = encrypt_for_recipient(
    message,
    bob_public_key
)

signature = create_message_signature(
    message_id,
    encrypted_aes_key,
    nonce,
    ciphertext,
    alice_private_key
)

print("Message encrypted and signed.")
print()


# ==========================================
# FIRST DELIVERY
# ==========================================

valid = verify_message_signature(
    message_id,
    encrypted_aes_key,
    nonce,
    ciphertext,
    signature,
    alice_public_key
)

print("First delivery:")
print("Signature valid:", valid)

if valid:

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
# REPLAY ATTACK
# ==========================================

print("REPLAY ATTACK:")
print("Attacker resends the exact same package.")
print()

replay_valid = verify_message_signature(
    message_id,
    encrypted_aes_key,
    nonce,
    ciphertext,
    signature,
    alice_public_key
)

print("Replayed message:")
print("Signature valid:", replay_valid)

if replay_valid:

    replayed_message = decrypt_received_message(
        encrypted_aes_key,
        nonce,
        ciphertext,
        bob_private_key
    )

    print("Replayed message decrypted as:")
    print(replayed_message)

print()


# ==========================================
# MESSAGE ID TAMPERING TEST
# ==========================================

tampered_message_id = "msg-999"

id_tampered_valid = verify_message_signature(
    tampered_message_id,
    encrypted_aes_key,
    nonce,
    ciphertext,
    signature,
    alice_public_key
)

print("After message ID tampering:")
print("Signature valid:", id_tampered_valid)
print()


# ==========================================
# CIPHERTEXT TAMPERING TEST
# ==========================================

tampered_ciphertext = bytearray(ciphertext)

tampered_ciphertext[0] ^= 1

tampered_ciphertext = bytes(
    tampered_ciphertext
)

tampered_valid = verify_message_signature(
    message_id,
    encrypted_aes_key,
    nonce,
    tampered_ciphertext,
    signature,
    alice_public_key
)

print("After ciphertext tampering:")
print("Signature valid:", tampered_valid)