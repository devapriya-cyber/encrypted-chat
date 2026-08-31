from key_manager import (
    generate_and_save_keys,
    load_private_key,
    load_public_key
)


username = "bob"


print("Generating Bob's keys...")

generate_and_save_keys(username)

print("Keys generated and saved.")
print()


private_key = load_private_key(username)
public_key = load_public_key(username)

print("Private key loaded successfully.")
print("Public key loaded successfully.")