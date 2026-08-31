from rsa_keys import (
    generate_rsa_key_pair,
    encrypt_with_public_key,
    decrypt_with_private_key
)


# Generate RSA key pair
private_key, public_key = generate_rsa_key_pair()

print("RSA key pair generated successfully.")
print()

# Secret data
secret = b"This is a secret AES key."

print("Original data:")
print(secret)
print()

# Encrypt using public key
encrypted = encrypt_with_public_key(secret, public_key)

print("Encrypted data:")
print(encrypted.hex())
print()

# Decrypt using private key
decrypted = decrypt_with_private_key(encrypted, private_key)

print("Decrypted data:")
print(decrypted)