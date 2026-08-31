import asyncio
import websockets

from key_manager import load_private_key, load_public_key
from rsa_keys import sign_data
from cryptography.hazmat.primitives import serialization


SERVER_URL = "ws://localhost:8765"


def public_key_to_text(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


async def test():

    username = "alice"

    # Load Alice's RSA keys
    private_key = load_private_key(username)
    public_key = load_public_key(username)

    public_key_text = public_key_to_text(public_key)

    async with websockets.connect(SERVER_URL) as websocket:

        # -----------------------------------------
        # 1. Register Alice
        # -----------------------------------------

        await websocket.send(username)
        await websocket.send(public_key_text)

        print("Alice connected.")
        print("Alice public key sent.")

        # -----------------------------------------
        # 2. Receive authentication challenge
        # -----------------------------------------

        auth_message = await websocket.recv()

        if not auth_message.startswith("AUTH_CHALLENGE|"):

            print("Authentication challenge not received.")
            print("Server response:")
            print(auth_message)

            return

        challenge_hex = auth_message.split("|", 1)[1]
        challenge = bytes.fromhex(challenge_hex)

        print("Authentication challenge received.")

        # -----------------------------------------
        # 3. Sign challenge
        # -----------------------------------------

        signature = sign_data(
            challenge,
            private_key
        )

        await websocket.send(
            "AUTH_RESPONSE|" + signature.hex()
        )

        # -----------------------------------------
        # 4. Authentication result
        # -----------------------------------------

        auth_result = await websocket.recv()

        if auth_result != "AUTH_SUCCESS":

            print("Alice authentication FAILED.")
            print("Server response:")
            print(auth_result)

            return

        print("Alice authenticated successfully.")

        # -----------------------------------------
        # 5. Request Bob's public key
        # -----------------------------------------

        await websocket.send("KEY_REQUEST|bob")

        response = await websocket.recv()

        print()
        print("Server response:")
        print(response[:100] + "...")

        # -----------------------------------------
        # 6. Verify response
        # -----------------------------------------

        if response.startswith("PUBLIC_KEY|bob|"):

            print()
            print("Bob's public key received successfully.")
            print("Key exchange test PASSED.")

        else:

            print()
            print("Failed to receive Bob's public key.")
            print("Key exchange test FAILED.")


if __name__ == "__main__":

    asyncio.run(test())