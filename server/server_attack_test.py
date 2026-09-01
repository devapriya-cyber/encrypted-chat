import asyncio
import secrets
import json
import os

import websockets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


connected_users = {}
public_keys = {}


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

CLIENT_KEYS_DIR = os.path.join(
    BASE_DIR,
    "client",
    "keys"
)


# --------------------------------------------------
# Load registered public keys
# --------------------------------------------------

def load_registered_public_key(username):

    key_path = os.path.join(
        CLIENT_KEYS_DIR,
        f"{username}_public.pem"
    )

    if not os.path.exists(key_path):
        return None, None

    with open(
        key_path,
        "rb"
    ) as file:

        key_text = file.read().decode(
            "utf-8"
        )

    key = serialization.load_pem_public_key(
        key_text.encode("utf-8")
    )

    return key, key_text


# --------------------------------------------------
# Load attacker's public key
# --------------------------------------------------

ATTACKER_KEY_PATH = os.path.join(
    BASE_DIR,
    "client",
    "attacker_public.pem"
)

with open(
    ATTACKER_KEY_PATH,
    "rb"
) as file:

    attacker_public_key_text = (
        file.read().decode("utf-8")
    )


# --------------------------------------------------
# Handle client
# --------------------------------------------------

async def handle_client(websocket):

    username = None
    authenticated = False

    try:

        # --------------------------------------------------
        # 1. Receive username
        # --------------------------------------------------

        username = await websocket.recv()

        username = (
            username.strip().lower()
        )

        if not username:

            await websocket.send(
                "AUTH_FAILED|Invalid username"
            )

            return

        # --------------------------------------------------
        # 2. Check registered identity
        # --------------------------------------------------

        registered_key, registered_key_text = (
            load_registered_public_key(
                username
            )
        )

        if registered_key is None:

            print(
                f"Unknown user attempted "
                f"authentication: {username}"
            )

            await websocket.send(
                "AUTH_FAILED|Unknown user"
            )

            return

        # --------------------------------------------------
        # 3. Receive submitted public key
        # --------------------------------------------------

        public_key_text = (
            await websocket.recv()
        )

        try:

            submitted_public_key = (
                serialization.load_pem_public_key(
                    public_key_text.encode()
                )
            )

        except Exception:

            await websocket.send(
                "AUTH_FAILED|Invalid public key"
            )

            return

        print()
        print(
            f"{username} connected."
        )

        print(
            f"Public key received from "
            f"{username}."
        )

        # --------------------------------------------------
        # 4. Compare submitted key with registered key
        # --------------------------------------------------

        submitted_public_bytes = (
            submitted_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        registered_public_bytes = (
            registered_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        if (
            submitted_public_bytes
            != registered_public_bytes
        ):

            print()
            print(
                "🚨 SECURITY ALERT 🚨"
            )

            print(
                f"Public key mismatch for "
                f"{username}."
            )

            print(
                "Submitted key does NOT match "
                "the registered key."
            )

            print(
                "Authentication BLOCKED."
            )

            await websocket.send(
                "AUTH_FAILED|Public key does not match registered key"
            )

            return

        print(
            "Public key matches registered "
            "identity."
        )

        # --------------------------------------------------
        # 5. Generate authentication challenge
        # --------------------------------------------------

        challenge = secrets.token_bytes(
            32
        )

        await websocket.send(
            "AUTH_CHALLENGE|"
            + challenge.hex()
        )

        print(
            f"Authentication challenge sent "
            f"to {username}."
        )

        # --------------------------------------------------
        # 6. Receive signature
        # --------------------------------------------------

        response = await websocket.recv()

        if not response.startswith(
            "AUTH_RESPONSE|"
        ):

            await websocket.send(
                "AUTH_FAILED|Missing signature"
            )

            return

        signature_hex = (
            response.split(
                "|",
                1
            )[1]
        )

        try:

            signature = bytes.fromhex(
                signature_hex
            )

        except ValueError:

            await websocket.send(
                "AUTH_FAILED|Invalid signature format"
            )

            return

        # --------------------------------------------------
        # 7. Verify signature using REGISTERED key
        # --------------------------------------------------

        try:

            registered_key.verify(

                signature,

                challenge,

                padding.PSS(
                    mgf=padding.MGF1(
                        algorithm=hashes.SHA256()
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                ),

                hashes.SHA256()
            )

            authenticated = True

        except Exception:

            authenticated = False

        # --------------------------------------------------
        # 8. Authentication result
        # --------------------------------------------------

        if not authenticated:

            print()
            print(
                f"Authentication FAILED "
                f"for {username}."
            )

            await websocket.send(
                "AUTH_FAILED|Invalid signature"
            )

            return

        print()
        print(
            f"✓ {username} authenticated "
            f"successfully."
        )

        # --------------------------------------------------
        # 9. Register authenticated user
        # --------------------------------------------------

        connected_users[
            username
        ] = websocket

        public_keys[
            username
        ] = registered_key_text

        await websocket.send(
            "AUTH_SUCCESS"
        )

        # --------------------------------------------------
        # 10. Handle messages
        # --------------------------------------------------

        async for message in websocket:

            print()
            print(
                f"Message received from "
                f"{username}"
            )

            # --------------------------------------------------
            # Public-key request
            # --------------------------------------------------

            if message.startswith(
                "KEY_REQUEST|"
            ):

                requested_user = (
                    message.split(
                        "|",
                        1
                    )[1]
                )

                requested_user = (
                    requested_user.strip().lower()
                )

                if requested_user in public_keys:

                    key_to_send = (
                        public_keys[
                            requested_user
                        ]
                    )

                    # --------------------------------------------------
                    # ATTACK SIMULATION
                    # --------------------------------------------------

                    if (
                        requested_user == "bob"
                        and username == "alice"
                    ):

                        print()
                        print(
                            "🚨 ATTACK SIMULATION 🚨"
                        )

                        print(
                            "Replacing Bob's "
                            "registered public key "
                            "with attacker's key."
                        )

                        key_to_send = (
                            attacker_public_key_text
                        )

                    await websocket.send(
                        f"PUBLIC_KEY|"
                        f"{requested_user}|"
                        f"{key_to_send}"
                    )

                    print(
                        f"Sent {requested_user}'s "
                        f"public key to "
                        f"{username}"
                    )

                else:

                    await websocket.send(
                        f"ERROR|User "
                        f"{requested_user} "
                        f"not found."
                    )

                continue

            # --------------------------------------------------
            # Normal encrypted message
            # --------------------------------------------------

            try:

                recipient, message_text = (
                    message.split(
                        "|",
                        1
                    )
                )

                recipient = (
                    recipient.strip().lower()
                )

            except ValueError:

                print(
                    "Invalid message format."
                )

                continue

            # --------------------------------------------------
            # Forward encrypted message
            # --------------------------------------------------

            if recipient in connected_users:

                recipient_socket = (
                    connected_users[
                        recipient
                    ]
                )

                await recipient_socket.send(
                    f"{username}|"
                    f"{message_text}"
                )

                print(
                    f"Message forwarded from "
                    f"{username} to "
                    f"{recipient}"
                )

            else:

                print(
                    f"{recipient} is not online."
                )

    except websockets.exceptions.ConnectionClosed:

        print(
            f"{username} disconnected."
        )

    finally:

        if username in connected_users:

            del connected_users[
                username
            ]

        if username:

            print(
                f"{username} removed from "
                f"connected users."
            )


# --------------------------------------------------
# Start attack-test server
# --------------------------------------------------

async def main():

    print()
    print(
        "Starting ATTACK TEST server..."
    )

    async with websockets.serve(
        handle_client,
        "localhost",
        8766
    ):

        print(
            "WebSocket server running "
            "on ws://localhost:8766"
        )

        print(
            "ATTACK SIMULATION ENABLED."
        )

        await asyncio.Future()


if __name__ == "__main__":

    asyncio.run(
        main()
    )