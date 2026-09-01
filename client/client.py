import asyncio
import json
import secrets
import sys

import websockets
from cryptography.hazmat.primitives import serialization

from crypto import (
    encrypt_for_recipient,
    decrypt_received_message,
    create_message_signature,
    verify_message_signature
)

from key_manager import (
    load_private_key,
    load_public_key
)

from fingerprint import get_public_key_fingerprint

from trusted_keys import (
    get_trusted_fingerprint,
    save_trusted_key
)


if "--attack-test" in sys.argv:
    SERVER_URL = "ws://localhost:8766"
else:
    SERVER_URL = "ws://localhost:8765"

def public_key_to_text(public_key):

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def text_to_public_key(public_key_text):

    return serialization.load_pem_public_key(
        public_key_text.encode("utf-8")
    )


async def chat_client():

    # =========================================
    # USERNAME
    # =========================================

    username = input(
        "Enter your username: "
    ).strip().lower()

    if not username:

        print("Invalid username.")
        return

    # =========================================
    # LOAD RSA KEYS
    # =========================================

    try:

        private_key = load_private_key(username)
        public_key = load_public_key(username)

    except FileNotFoundError:

        print()
        print(
            f"No RSA keys found for {username}."
        )

        return

    print()
    print(
        f"Loaded {username}'s RSA keys."
    )

    # =========================================
    # CONNECT TO SERVER
    # =========================================

    try:

        async with websockets.connect(
            SERVER_URL
        ) as websocket:

            # =========================================
            # REGISTER USERNAME
            # =========================================

            await websocket.send(username)

            # =========================================
            # SEND PUBLIC KEY
            # =========================================

            await websocket.send(
                public_key_to_text(public_key)
            )

            print()
            print(
                f"Connected to server as {username}."
            )

            # =========================================
            # AUTHENTICATION CHALLENGE
            # =========================================

            auth_message = await websocket.recv()

            if not auth_message.startswith(
                "AUTH_CHALLENGE|"
            ):

                print()
                print(
                    "AUTHENTICATION FAILED"
                )

                print(
                    f"Server response: {auth_message}"
                )

                return

            challenge_hex = (
                auth_message.split("|", 1)[1]
            )

            try:

                challenge = bytes.fromhex(
                    challenge_hex
                )

            except ValueError:

                print()
                print(
                    "Invalid authentication challenge."
                )

                return

            # =========================================
            # SIGN AUTHENTICATION CHALLENGE
            # =========================================

            from rsa_keys import sign_data

            signature = sign_data(
                challenge,
                private_key
            )

            await websocket.send(
                "AUTH_RESPONSE|"
                + signature.hex()
            )

            # =========================================
            # AUTHENTICATION RESULT
            # =========================================

            auth_result = await websocket.recv()

            if auth_result != "AUTH_SUCCESS":

                print()
                print(
                    "AUTHENTICATION FAILED"
                )

                print(
                    f"Server response: {auth_result}"
                )

                return

            print()
            print(
                f"{username} authenticated successfully."
            )

            # =========================================
            # COMMANDS
            # =========================================

            print()
            print("Commands:")
            print("  /key bob")
            print("  bob|Hello Bob")
            print("  exit")
            print()

            # =========================================
            # KEY STORAGE
            # =========================================

            known_public_keys = {}

            verified_users = set()

            verification_queue = asyncio.Queue()

            # =========================================
            # REPLAY PROTECTION
            # =========================================

            # Stores message IDs that have already
            # passed signature verification and
            # have been processed.
            seen_message_ids = set()

            # =========================================
            # RECEIVE MESSAGES
            # =========================================

            async def receive_messages():

                try:

                    async for raw_message in websocket:

                        # =========================================
                        # PUBLIC KEY RESPONSE
                        # =========================================

                        if raw_message.startswith(
                            "PUBLIC_KEY|"
                        ):

                            parts = raw_message.split(
                                "|",
                                2
                            )

                            if len(parts) != 3:

                                continue

                            received_username = (
                                parts[1]
                                .strip()
                                .lower()
                            )

                            received_key_text = parts[2]

                            try:

                                received_key = (
                                    text_to_public_key(
                                        received_key_text
                                    )
                                )

                                fingerprint = (
                                    get_public_key_fingerprint(
                                        received_key
                                    )
                                )

                                trusted_fingerprint = (
                                    get_trusted_fingerprint(
                                        received_username
                                    )
                                )

                                await verification_queue.put(
                                    (
                                        received_username,
                                        received_key,
                                        fingerprint,
                                        trusted_fingerprint
                                    )
                                )

                            except Exception as error:

                                print()
                                print(
                                    "Could not process "
                                    f"{received_username}'s public key:"
                                )

                                print(error)

                            continue

                        # =========================================
                        # SERVER ERROR
                        # =========================================

                        if raw_message.startswith(
                            "ERROR|"
                        ):

                            print()
                            print(
                                f"Server: {raw_message[6:]}"
                            )

                            print(
                                "> ",
                                end="",
                                flush=True
                            )

                            continue

                        # =========================================
                        # ENCRYPTED MESSAGE
                        # =========================================

                        try:

                            sender, encrypted_package = (
                                raw_message.split(
                                    "|",
                                    1
                                )
                            )

                            sender = (
                                sender.strip().lower()
                            )

                            # =========================================
                            # PARSE JSON
                            # =========================================

                            package = json.loads(
                                encrypted_package
                            )

                            # =========================================
                            # RECOVER MESSAGE ID
                            # =========================================

                            message_id = package.get(
                                "message_id"
                            )

                            if not message_id:

                                print()
                                print(
                                    "🚨 SECURITY WARNING 🚨"
                                )

                                print(
                                    "Message has no message ID."
                                )

                                print(
                                    "MESSAGE BLOCKED."
                                )

                                continue

                            # =========================================
                            # VALIDATE MESSAGE ID
                            # =========================================

                            if not isinstance(
                                message_id,
                                str
                            ):

                                print()
                                print(
                                    "🚨 SECURITY WARNING 🚨"
                                )

                                print(
                                    "Invalid message ID."
                                )

                                print(
                                    "MESSAGE BLOCKED."
                                )

                                continue

                            # =========================================
                            # RECOVER ENCRYPTED AES KEY
                            # =========================================

                            encrypted_aes_key = (
                                bytes.fromhex(
                                    package["encrypted_key"]
                                )
                            )

                            # =========================================
                            # RECOVER NONCE
                            # =========================================

                            nonce = bytes.fromhex(
                                package["nonce"]
                            )

                            # =========================================
                            # RECOVER CIPHERTEXT
                            # =========================================

                            ciphertext = bytes.fromhex(
                                package["ciphertext"]
                            )

                            # =========================================
                            # RECOVER SIGNATURE
                            # =========================================

                            signature_hex = package.get(
                                "signature"
                            )

                            if not signature_hex:

                                print()
                                print(
                                    "🚨 SECURITY WARNING 🚨"
                                )

                                print(
                                    "Message has no signature."
                                )

                                print(
                                    "MESSAGE BLOCKED."
                                )

                                continue

                            signature = bytes.fromhex(
                                signature_hex
                            )

                            # =========================================
                            # FIND VERIFIED SENDER KEY
                            # =========================================

                            sender_public_key = (
                                known_public_keys.get(
                                    sender
                                )
                            )

                            if sender_public_key is None:

                                print()
                                print(
                                    f"Cannot verify "
                                    f"{sender}'s message."
                                )

                                print(
                                    f"Use /key {sender} first."
                                )

                                continue

                            # =========================================
                            # VERIFY MESSAGE SIGNATURE
                            # =========================================

                            signature_valid = (
                                verify_message_signature(
                                    message_id,
                                    encrypted_aes_key,
                                    nonce,
                                    ciphertext,
                                    signature,
                                    sender_public_key
                                )
                            )

                            if not signature_valid:

                                print()
                                print(
                                    "🚨 SECURITY WARNING 🚨"
                                )

                                print(
                                    f"Message signature from "
                                    f"{sender} is INVALID!"
                                )

                                print(
                                    "MESSAGE BLOCKED."
                                )

                                continue

                            print()
                            print(
                                "✓ Message signature verified."
                            )

                            # =========================================
                            # REPLAY ATTACK DETECTION
                            # =========================================

                            if message_id in seen_message_ids:

                                print()
                                print(
                                    "🚨 SECURITY WARNING 🚨"
                                )

                                print(
                                    "Replay attack detected!"
                                )

                                print(
                                    f"Message ID {message_id} "
                                    "has already been processed."
                                )

                                print(
                                    "MESSAGE BLOCKED."
                                )

                                continue

                            # =========================================
                            # RECORD MESSAGE ID
                            # =========================================

                            # Only record the ID after the
                            # signature has been successfully
                            # verified.
                            seen_message_ids.add(
                                message_id
                            )

                            print()
                            print(
                                "✓ Message accepted."
                            )

                            # =========================================
                            # DECRYPT MESSAGE
                            # =========================================

                            plaintext = (
                                decrypt_received_message(
                                    encrypted_aes_key,
                                    nonce,
                                    ciphertext,
                                    private_key
                                )
                            )

                            print()
                            print(
                                f"{sender}: {plaintext}"
                            )

                            print(
                                "> ",
                                end="",
                                flush=True
                            )

                        except Exception as error:

                            print()
                            print(
                                "Could not process message:"
                            )

                            print(error)

                            print(
                                "> ",
                                end="",
                                flush=True
                            )

                except websockets.exceptions.ConnectionClosed:

                    print()
                    print(
                        "Connection closed by server."
                    )

            # =========================================
            # START RECEIVER
            # =========================================

            receive_task = asyncio.create_task(
                receive_messages()
            )

            try:

                # =========================================
                # MAIN INPUT LOOP
                # =========================================

                while True:

                    # =========================================
                    # PROCESS KEY VERIFICATION QUEUE
                    # =========================================

                    try:

                        (
                            received_username,
                            received_key,
                            fingerprint,
                            trusted_fingerprint
                        ) = verification_queue.get_nowait()

                        print()
                        print(
                            "Public key received for "
                            f"{received_username}."
                        )

                        print()
                        print(
                            f"{received_username}'s fingerprint:"
                        )

                        print(fingerprint)

                        # =========================================
                        # TRUSTED KEY EXISTS
                        # =========================================

                        if trusted_fingerprint is not None:

                            if (
                                fingerprint
                                == trusted_fingerprint
                            ):

                                known_public_keys[
                                    received_username
                                ] = received_key

                                verified_users.add(
                                    received_username
                                )

                                print()
                                print(
                                    "✓ Trusted public key verified."
                                )

                            else:

                                print()
                                print(
                                    "🚨 SECURITY WARNING 🚨"
                                )

                                print(
                                    "Public key mismatch!"
                                )

                                print()
                                print("Expected:")

                                print(
                                    trusted_fingerprint
                                )

                                print()
                                print("Received:")

                                print(
                                    fingerprint
                                )

                                print()
                                print(
                                    "MESSAGE BLOCKED."
                                )

                                verified_users.discard(
                                    received_username
                                )

                                known_public_keys.pop(
                                    received_username,
                                    None
                                )

                        # =========================================
                        # FIRST TIME KEY
                        # =========================================

                        else:

                            print()
                            print(
                                "No trusted fingerprint "
                                "exists for this user."
                            )

                            print(
                                "Verify this fingerprint "
                                "with the user through "
                                "a trusted channel."
                            )

                            answer = input(
                                "Trust this key? (yes/no): "
                            ).strip().lower()

                            if answer == "yes":

                                save_trusted_key(
                                    received_username,
                                    fingerprint
                                )

                                known_public_keys[
                                    received_username
                                ] = received_key

                                verified_users.add(
                                    received_username
                                )

                                print(
                                    "Trusted public key saved."
                                )

                            else:

                                print(
                                    "Key rejected."
                                )

                    except asyncio.QueueEmpty:

                        pass

                    # =========================================
                    # USER INPUT
                    # =========================================

                    message = await asyncio.to_thread(
                        input,
                        "> "
                    )

                    message = message.strip()

                    if not message:

                        continue

                    # =========================================
                    # EXIT
                    # =========================================

                    if message.lower() == "exit":

                        break

                    # =========================================
                    # REQUEST PUBLIC KEY
                    # =========================================

                    if message.startswith("/key "):

                        requested_user = (
                            message[5:]
                            .strip()
                            .lower()
                        )

                        if not requested_user:

                            print(
                                "Usage: /key bob"
                            )

                            continue

                        await websocket.send(
                            f"KEY_REQUEST|{requested_user}"
                        )

                        # Give receiver task time
                        # to process the response
                        await asyncio.sleep(0.2)

                        # =========================================
                        # PROCESS KEY VERIFICATION
                        # =========================================

                        while (
                            not verification_queue.empty()
                        ):

                            (
                                received_username,
                                received_key,
                                fingerprint,
                                trusted_fingerprint
                            ) = (
                                await verification_queue.get()
                            )

                            print()
                            print(
                                "Public key received for "
                                f"{received_username}."
                            )

                            print()
                            print(
                                f"{received_username}'s fingerprint:"
                            )

                            print(fingerprint)

                            # =========================================
                            # TRUSTED FINGERPRINT
                            # =========================================

                            if trusted_fingerprint is not None:

                                if (
                                    fingerprint
                                    == trusted_fingerprint
                                ):

                                    known_public_keys[
                                        received_username
                                    ] = received_key

                                    verified_users.add(
                                        received_username
                                    )

                                    print()
                                    print(
                                        "✓ Trusted public key verified."
                                    )

                                else:

                                    print()
                                    print(
                                        "🚨 SECURITY WARNING 🚨"
                                    )

                                    print(
                                        "Public key mismatch!"
                                    )

                                    print(
                                        "MESSAGE BLOCKED."
                                    )

                                    verified_users.discard(
                                        received_username
                                    )

                                    known_public_keys.pop(
                                        received_username,
                                        None
                                    )

                            # =========================================
                            # NEW FINGERPRINT
                            # =========================================

                            else:

                                print()
                                print(
                                    "No trusted fingerprint "
                                    "exists for this user."
                                )

                                print(
                                    "Verify this fingerprint "
                                    "with the user through "
                                    "a trusted channel."
                                )

                                answer = input(
                                    "Trust this key? (yes/no): "
                                ).strip().lower()

                                if answer == "yes":

                                    save_trusted_key(
                                        received_username,
                                        fingerprint
                                    )

                                    known_public_keys[
                                        received_username
                                    ] = received_key

                                    verified_users.add(
                                        received_username
                                    )

                                    print(
                                        "Trusted public key saved."
                                    )

                                else:

                                    print(
                                        "Key rejected."
                                    )

                        continue

                    # =========================================
                    # MESSAGE FORMAT
                    # =========================================

                    try:

                        recipient, plaintext = (
                            message.split(
                                "|",
                                1
                            )
                        )

                        recipient = (
                            recipient.strip().lower()
                        )

                        plaintext = (
                            plaintext.strip()
                        )

                    except ValueError:

                        print()
                        print(
                            "Use:"
                        )

                        print(
                            "recipient|message"
                        )

                        continue

                    # =========================================
                    # CHECK RECIPIENT KEY
                    # =========================================

                    if recipient not in verified_users:

                        print()
                        print(
                            f"✗ {recipient}'s public key "
                            "is not verified."
                        )

                        print(
                            f"Use /key {recipient} first."
                        )

                        continue

                    recipient_public_key = (
                        known_public_keys[
                            recipient
                        ]
                    )

                    # =========================================
                    # HYBRID ENCRYPTION
                    # =========================================

                    (
                        encrypted_aes_key,
                        nonce,
                        ciphertext
                    ) = encrypt_for_recipient(
                        plaintext,
                        recipient_public_key
                    )

                    # =========================================
                    # CREATE UNIQUE MESSAGE ID
                    # =========================================

                    message_id = secrets.token_hex(
                        16
                    )

                    # =========================================
                    # CREATE MESSAGE SIGNATURE
                    # =========================================

                    signature = create_message_signature(
                        message_id,
                        encrypted_aes_key,
                        nonce,
                        ciphertext,
                        private_key
                    )

                    # =========================================
                    # CREATE ENCRYPTED PACKAGE
                    # =========================================

                    encrypted_package = {

                        "message_id":
                            message_id,

                        "encrypted_key":
                            encrypted_aes_key.hex(),

                        "nonce":
                            nonce.hex(),

                        "ciphertext":
                            ciphertext.hex(),

                        "signature":
                            signature.hex()
                    }

                    # =========================================
                    # SEND MESSAGE
                    # =========================================

                    await websocket.send(
                        f"{recipient}|"
                        f"{json.dumps(encrypted_package)}"
                    )

                    print()
                    print(
                        "Encrypted, signed and "
                        "replay-protected message sent."
                    )

            finally:

                receive_task.cancel()

                try:

                    await receive_task

                except asyncio.CancelledError:

                    pass

    except ConnectionRefusedError:

        print()
        print(
            "Could not connect to server."
        )

        print(
            "Make sure server.py is running."
        )

    except Exception as error:

        print()
        print(
            f"Client error: {error}"
        )


if __name__ == "__main__":

    try:

        asyncio.run(
            chat_client()
        )

    except KeyboardInterrupt:

        print(
            "\nChat closed."
        )