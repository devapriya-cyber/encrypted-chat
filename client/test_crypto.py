from crypto import generate_aes_key, encrypt_message, decrypt_message


# Generate AES key
key = generate_aes_key()

print("AES key generated successfully.")
print()


# Original message
message = "Hello Bob! This is a secret message."

print("Original message:")
print(message)
print()


# Encrypt
nonce, ciphertext = encrypt_message(message, key)

print("Encrypted ciphertext:")
print(ciphertext.hex())
print()


# Decrypt
decrypted_message = decrypt_message(nonce, ciphertext, key)

print("Decrypted message:")
print(decrypted_message)