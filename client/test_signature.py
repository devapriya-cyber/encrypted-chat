from rsa_keys import (
    generate_rsa_key_pair,
    sign_data,
    verify_signature
)


private_key, public_key = generate_rsa_key_pair()

message = b"Authenticate Alice"

signature = sign_data(
    message,
    private_key
)

print("Message:")
print(message)

print()
print("Signature generated successfully.")

valid = verify_signature(
    message,
    signature,
    public_key
)

print()
print("Signature valid:")
print(valid)


# Test tampering
tampered_message = b"Authenticate Bob"

tampered_valid = verify_signature(
    tampered_message,
    signature,
    public_key
)

print()
print("After message tampering:")
print("Signature valid:")
print(tampered_valid)