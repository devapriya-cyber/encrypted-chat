import asyncio
import secrets
import os

import websockets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# ============================================================
# ATTACK TEST SERVER
# ============================================================
#
# Security tests:
#
# 1. Prevent attacker from authenticating as Bob.
# 2. Simulate public-key substitution when Alice requests Bob's
#    public key.
#
# Server port: 8766
# ============================================================


connected_users = {}
public_keys = {}


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

CLIENT_DIR = os.path.join(
    BASE_DIR,
    "client"
)

CLIENT_KEYS_DIR = os.path.join(
    CLIENT_DIR,
    "keys"
)

ATTACKER_PUBLIC_KEY_PATH = os.path.join(
    CLIENT_DIR,
    "attacker_public.pem"
)


# ============================================================
# LOAD REGISTERED PUBLIC KEY
# ============================================================

def load_registered_public_key(username):

    key_path = os.path.join(
        CLIENT_KEYS_DIR,
        f"{username}_public.pem"
    )

    if not os.path.exists(key_path):
        return None, None

    try:

        with open(key_path, "rb") as file:
            key_text = file.read().decode("utf-8")

        key = serialization.load_pem_public_key(
            key_text.encode("utf-8")
        )

        return key, key_text

    except Exception as error:

        print(
            f"Could not load registered key for "
            f"{username}: {error}"
        )

        return None, None


# ============================================================
# LOAD ATTACKER PUBLIC KEY
# ============================================================

if not os.path.exists(ATTACKER_PUBLIC_KEY_PATH):

    raise FileNotFoundError(
        "Attacker public key not found: "
        + ATTACKER_PUBLIC_KEY_PATH
    )


with open(
    ATTACKER_PUBLIC_KEY_PATH,
    "rb"
) as file:

    attacker_public_key_text = file.read().decode("utf-8")


attacker_public_key = (
    serialization.load_pem_public_key(
        attacker_public_key_text.encode("utf-8")
    )
)


# ============================================================
# HANDLE CLIENT
# ============================================================

async def handle_client(websocket):

    username = None

    try:

        # ====================================================
        # 1. RECEIVE USERNAME
        # ====================================================

        username = await websocket.recv()

        username = username.strip().lower()

        if not username:

            await websocket.send(
                "AUTH_FAILED|Invalid username"
            )

            return

        print()
        print("=" * 60)
        print(f"Connection received from: {username}")
        print("=" * 60)


        # ====================================================
        # 2. LOAD REGISTERED KEY
        # ====================================================

        registered_key, registered_key_text = (
            load_registered_public_key(username)
        )

        if registered_key is None:

            print(
                f"Unknown user: {username}"
            )

            await websocket.send(
                "AUTH_FAILED|Unknown user"
            )

            return


        # ====================================================
        # 3. RECEIVE SUBMITTED PUBLIC KEY
        # ====================================================

        public_key_text = await websocket.recv()

        try:

            submitted_public_key = (
                serialization.load_pem_public_key(
                    public_key_text.encode("utf-8")
                )
            )

        except Exception:

            await websocket.send(
                "AUTH_FAILED|Invalid public key"
            )

            return


        print(
            f"Public key received from {username}."
        )


        # ====================================================
        # 4. COMPARE SUBMITTED KEY WITH REGISTERED KEY
        # ====================================================

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


        # ====================================================
        # ATTACK DETECTION
        # ====================================================

        if submitted_public_bytes != registered_public_bytes:

            print()
            print("!" * 60)
            print("SECURITY ALERT")
            print("!" * 60)
            print(
                f"Public key mismatch for user: {username}"
            )
            print(
                "Submitted key does NOT match "
                "the registered key."
            )
            print(
                "Authentication BLOCKED."
            )
            print("!" * 60)

            await websocket.send(
                "AUTH_FAILED|Public key does not match registered key"
            )

            return


        # ====================================================
        # 5. AUTHENTICATION CHALLENGE
        # ====================================================

        print(
            "Public key matches registered identity."
        )

        challenge = secrets.token_bytes(32)

        await websocket.send(
            "AUTH_CHALLENGE|" + challenge.hex()
        )

        print(
            f"Authentication challenge sent to {username}."
        )


        # ====================================================
        # 6. RECEIVE SIGNATURE
        # ====================================================

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


        # ====================================================
        # 7. VERIFY SIGNATURE
        # ====================================================

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

        except Exception:

            print()
            print(
                f"Authentication FAILED for {username}."
            )

            await websocket.send(
                "AUTH_FAILED|Invalid signature"
            )

            return


        # ====================================================
        # 8. AUTHENTICATION SUCCESS
        # ====================================================

        print()
        print(
            f"✓ {username} authenticated successfully."
        )


        # ====================================================
        # 9. REGISTER CONNECTION
        # ====================================================

        connected_users[username] = websocket

        # IMPORTANT:
        #
        # Always store the legitimate registered public key.
        #
        # The attacker key will ONLY be substituted when
        # Alice requests Bob's public key.
        #
        public_keys[username] = registered_key_text

        await websocket.send(
            "AUTH_SUCCESS"
        )


        # ====================================================
        # 10. HANDLE MESSAGES
        # ====================================================

        async for message in websocket:

            print()
            print(
                f"Message received from {username}"
            )


            # =================================================
            # PUBLIC KEY REQUEST
            # =================================================

            if message.startswith(
                "KEY_REQUEST|"
            ):

                requested_user = message.split(
                    "|",
                    1
                )[1].strip().lower()


                # ------------------------------------------------
                # CHECK USER
                # ------------------------------------------------

                if requested_user not in public_keys:

                    await websocket.send(
                        f"ERROR|User {requested_user} not found."
                    )

                    continue


                # ------------------------------------------------
                # GET LEGITIMATE KEY
                # ------------------------------------------------

                key_to_send = public_keys[
                    requested_user
                ]


                # =================================================
                # MITM / PUBLIC-KEY SUBSTITUTION
                # =================================================

                if (
                    username == "alice"
                    and requested_user == "bob"
                ):

                    print()
                    print("!" * 60)
                    print("MITM ATTACK SIMULATION")
                    print("!" * 60)
                    print(
                        "Alice requested Bob's public key."
                    )
                    print(
                        "Replacing Bob's legitimate public key"
                    )
                    print(
                        "with the ATTACKER'S public key."
                    )
                    print(
                        "Alice should detect the fingerprint mismatch."
                    )
                    print("!" * 60)

                    key_to_send = (
                        attacker_public_key_text
                    )


                # ------------------------------------------------
                # SEND KEY
                # ------------------------------------------------

                await websocket.send(
                    f"PUBLIC_KEY|"
                    f"{requested_user}|"
                    f"{key_to_send}"
                )

                print(
                    f"Public key for {requested_user} "
                    f"sent to {username}."
                )

                continue


            # =================================================
            # NORMAL MESSAGE FORWARDING
            # =================================================

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


            if recipient in connected_users:

                await connected_users[
                    recipient
                ].send(
                    f"{username}|{message_text}"
                )

                print(
                    f"Message forwarded from "
                    f"{username} to {recipient}."
                )

            else:

                print(
                    f"{recipient} is not online."
                )


    except websockets.exceptions.ConnectionClosed:

        print()
        print(
            f"{username} disconnected."
        )


    except Exception as error:

        print()
        print(
            f"Server error for {username}: {error}"
        )


    finally:

        if username in connected_users:

            del connected_users[username]

        if username:

            print(
                f"{username} removed from "
                f"connected users."
            )


# ============================================================
# START SERVER
# ============================================================

async def main():

    print()
    print("=" * 60)
    print("STARTING ATTACK TEST SERVER")
    print("=" * 60)

    async with websockets.serve(
        handle_client,
        "localhost",
        8766
    ):

        print(
            "WebSocket server running on "
            "ws://localhost:8766"
        )

        print(
            "Attack simulation enabled."
        )

        print(
            "Waiting for connections..."
        )

        print()

        await asyncio.Future()


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    asyncio.run(main())