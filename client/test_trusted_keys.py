from trusted_keys import (
    save_trusted_key,
    get_trusted_fingerprint
)


username = "bob"

fingerprint = "TEST:FINGERPRINT:1234"


print("Saving Bob's trusted fingerprint...")

save_trusted_key(
    username,
    fingerprint
)

print("Fingerprint saved.")

print()

loaded = get_trusted_fingerprint(
    username
)

print("Loaded fingerprint:")
print(loaded)


if loaded == fingerprint:

    print()
    print("Fingerprint verification test PASSED.")

else:

    print()
    print("Fingerprint verification test FAILED.")