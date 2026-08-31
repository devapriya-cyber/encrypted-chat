from key_manager import load_public_key
from fingerprint import get_public_key_fingerprint


alice_key = load_public_key("alice")
bob_key = load_public_key("bob")


alice_fingerprint = get_public_key_fingerprint(
    alice_key
)

bob_fingerprint = get_public_key_fingerprint(
    bob_key
)


print("Alice's public-key fingerprint:")
print(alice_fingerprint)

print()

print("Bob's public-key fingerprint:")
print(bob_fingerprint)