import asyncio
import secrets

import websockets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# Connected authenticated users
connected_users = {}

# Public keys of authenticated users
public_keys = {}


async def handle_client(websocket):

    username = None
    authenticated = False

    try:

        # -----------------------------------------
        # 1. Receive username
        # -----------------------------------------

        username = await websocket.recv()

        username = username.strip().lower()

        if not username:
            await websocket.send(
                "AUTH_FAILED|Invalid username"
            )
            return

        # -----------------------------------------
        # 2. Receive public key
        # -----------------------------------------

        public_key_text = await websocket.recv()

        try:

            public_key = (
                serialization.load_pem_public_key(
                    public_key_text.encode()
                )
            )

        except Exception:

            await websocket.send(
                "AUTH_FAILED|Invalid public key"
            )

            return

        print(
            f"{username} connected."
        )

        print(
            f"Public key received from {username}."
        )

        # -----------------------------------------
        # 3. Generate random challenge
        # -----------------------------------------

        challenge = secrets.token_bytes(32)

        await websocket.send(
            "AUTH_CHALLENGE|"
            + challenge.hex()
        )

        print(
            f"Authentication challenge sent to "
            f"{username}."
        )

        # -----------------------------------------
        # 4. Receive signature
        # -----------------------------------------

        response = await websocket.recv()

        if not response.startswith(
            "AUTH_RESPONSE|"
        ):

            await websocket.send(
                "AUTH_FAILED|Missing signature"
            )

            return

        signature_hex = response.split(
            "|",
            1
        )[1]

        try:

            signature = bytes.fromhex(
                signature_hex
            )

        except ValueError:

            await websocket.send(
                "AUTH_FAILED|Invalid signature format"
            )

            return

        # -----------------------------------------
        # 5. Verify RSA signature
        # -----------------------------------------

        try:

            public_key.verify(
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

        # -----------------------------------------
        # 6. Authentication result
        # -----------------------------------------

        if not authenticated:

            print(
                f"Authentication FAILED for "
                f"{username}."
            )

            await websocket.send(
                "AUTH_FAILED|Invalid signature"
            )

            return

        print(
            f"✓ {username} authenticated successfully."
        )

        # -----------------------------------------
        # 7. Register authenticated user
        # -----------------------------------------

        connected_users[username] = websocket

        public_keys[username] = public_key_text

        await websocket.send(
            "AUTH_SUCCESS"
        )

        # -----------------------------------------
        # 8. Handle messages
        # -----------------------------------------

        async for message in websocket:

            print(
                f"Message received from {username}"
            )

            # -----------------------------------------
            # Request public key
            # -----------------------------------------

            if message.startswith(
                "KEY_REQUEST|"
            ):

                requested_user = message.split(
                    "|",
                    1
                )[1]

                requested_user = (
                    requested_user.strip().lower()
                )

                if requested_user in public_keys:

                    await websocket.send(
                        f"PUBLIC_KEY|"
                        f"{requested_user}|"
                        f"{public_keys[requested_user]}"
                    )

                    print(
                        f"Sent {requested_user}'s "
                        f"public key to {username}"
                    )

                else:

                    await websocket.send(
                        f"ERROR|User "
                        f"{requested_user} "
                        f"not found."
                    )

                continue

            # -----------------------------------------
            # Normal encrypted message
            # -----------------------------------------

            try:

                recipient, message_text = (
                    message.split("|", 1)
                )

                recipient = (
                    recipient.strip().lower()
                )

            except ValueError:

                print(
                    "Invalid message format."
                )

                continue

            # -----------------------------------------
            # Check recipient
            # -----------------------------------------

            if recipient in connected_users:

                recipient_socket = (
                    connected_users[recipient]
                )

                await recipient_socket.send(
                    f"{username}|{message_text}"
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

            del connected_users[username]

        if username:

            print(
                f"{username} removed from "
                f"connected users."
            )


async def main():

    print(
        "Starting encrypted chat server..."
    )

    async with websockets.serve(
        handle_client,
        "localhost",
        8765
    ):

        print(
            "WebSocket server running "
            "on ws://localhost:8765"
        )

        await asyncio.Future()


if __name__ == "__main__":

    asyncio.run(main())