# Secure Encrypted Chat

A Python-based encrypted chat application built to demonstrate secure communication concepts such as hybrid encryption, digital signatures, public-key authentication, fingerprint verification, and replay attack protection.

This project was developed as a cybersecurity learning project and focuses on understanding how different security mechanisms work together in a chat application.

## Features

- RSA-3072 public/private key pairs
- AES-256-GCM message encryption
- RSA-OAEP encryption for securely transferring AES keys
- RSA-PSS digital signatures
- Public-key fingerprint verification
- Trusted public-key storage
- Challenge-response authentication
- Replay attack detection
- MITM (Man-in-the-Middle) attack simulation
- Public-key substitution detection
- Authentication attack simulation
- WebSocket-based client-server communication

## How the Encryption Works

The application uses hybrid encryption.

Instead of encrypting the entire message using RSA, a random AES key is generated for each message.

The process is:

1. A random AES-256 key is generated.
2. The message is encrypted using AES-256-GCM.
3. The AES key is encrypted using the recipient's RSA public key with RSA-OAEP.
4. The sender creates a digital signature for the encrypted message package.
5. The encrypted AES key, nonce, ciphertext, message ID, and signature are sent through the server.
6. The recipient verifies the sender's signature.
7. The recipient checks the message ID for replay attacks.
8. The encrypted AES key is decrypted using the recipient's RSA private key.
9. The original message is decrypted using AES-256-GCM.

The server forwards encrypted messages but does not decrypt their contents.

## Security Mechanisms

### AES-256-GCM

AES-256-GCM is used for message encryption.

It provides:

- Confidentiality
- Integrity
- Authentication

A unique nonce is generated for each encrypted message.

### RSA-OAEP

RSA-OAEP is used to encrypt the randomly generated AES key.

This allows the AES key to be securely transferred to the intended recipient without sending it directly.

### RSA-PSS Digital Signatures

Messages are digitally signed using the sender's RSA private key.

The signature covers:

- Message ID
- Encrypted AES key
- Nonce
- Ciphertext

This allows the recipient to detect changes to the encrypted message package.

### Public-Key Fingerprints

Public-key fingerprints are generated using SHA-256 over the public key's DER SubjectPublicKeyInfo representation.

Example:

```text
fdc4:89e4:03f0:39e3:00c3:3b4e:d50a:1038:4af0:1887:d366:33e4:ae14:1cc4:7786:180f

The fingerprint can be compared with a previously trusted fingerprint to detect public-key substitution.

Trusted Keys

Trusted public-key fingerprints are stored locally in:

client/trusted_keys.json

The trusted-key database is intentionally excluded from Git because it contains local trust information.

Challenge-Response Authentication

When a client connects to the server:

The client sends its username.
The client sends its public key.
The server generates a random authentication challenge.
The client signs the challenge using its private key.
The server verifies the signature using the submitted public key.
Authentication succeeds only if the signature is valid.

This demonstrates public-key based authentication without sending the private key.

Replay Attack Protection

Every message contains a unique message ID.

The client maintains a set of previously accepted message IDs.

If the same message ID is received again, the message is rejected as a replay attack.

Example:

First delivery:
✓ Message accepted.

Second delivery:
Replay attack detected!

The current implementation keeps the replay state in memory for the running client session.

MITM Attack Simulation

The project includes a controlled MITM attack simulation.

The attack server intentionally replaces Bob's legitimate public key with an attacker's public key when Alice requests Bob's key.

Alice receives the attacker's public key and calculates its fingerprint.

Because the fingerprint does not match the trusted fingerprint, Alice blocks the communication.

Example:

Public key received for bob.

bob's fingerprint:
ddb9:9ac3:4896:fd8d:25f9:2dbb:5cbb:dc7b:f5fe:9c46:32b8:0d43:592e:6727:b96d:45c3

🚨 SECURITY WARNING 🚨
Public key mismatch!
MESSAGE BLOCKED.

This demonstrates how fingerprint verification can help detect public-key substitution.

The attack simulation screenshot is included in the repository:

mitm-detection.png

Authentication Attack Test

The project also contains an authentication attack simulation.

The attacker attempts to connect using Bob's identity but provides a different public key.

The attack server compares the submitted public key with Bob's registered public key.

The attack is rejected:

Attacker connected as bob.
Attacker public key sent.

Server response:
AUTH_FAILED|Public key does not match registered key

Attack test stopped: no authentication challenge.

This demonstrates why a username alone should not be trusted as an identity.

Project Structure
encrypted_chat/
│
├── client/
│   ├── client.py
│   ├── crypto.py
│   ├── fingerprint.py
│   ├── key_manager.py
│   ├── rsa_keys.py
│   ├── trusted_keys.py
│   │
│   ├── test_crypto.py
│   ├── test_fingerprint.py
│   ├── test_hybrid.py
│   ├── test_keys.py
│   ├── test_key_exchange.py
│   ├── test_message_signature.py
│   ├── test_replay_protection.py
│   ├── test_rsa.py
│   ├── test_signature.py
│   └── test_trusted_keys.py
│
├── server/
│   ├── server.py
│   └── server_attack_test.py
│
├── mitm-detection.png
├── README.md
├── requirements.txt
└── .gitignore

Local cryptographic material such as private keys, public keys, trusted-key databases, and attacker test keys are intentionally excluded from Git.

Running the Project
1. Install Dependencies

Create and activate a virtual environment if required.

Then install the dependencies:

pip install -r requirements.txt
2. Start the Normal Server

Open PowerShell in the project directory and run:

python server\server.py

The normal server runs on:

ws://localhost:8765
3. Start the Client

Open another PowerShell window and run:

python client\client.py

The client can then connect to the server and communicate with another authenticated user.

Running the Security Tests

Individual tests can be executed using Python.

AES Encryption Test
python client\test_crypto.py
Fingerprint Test
python client\test_fingerprint.py
Hybrid Encryption Test
python client\test_hybrid.py
RSA Test
python client\test_rsa.py
Digital Signature Test
python client\test_signature.py
Message Signature Test
python client\test_message_signature.py
Replay Protection Test
python client\test_replay_protection.py
Trusted-Key Test
python client\test_trusted_keys.py
Key Management Test
python client\test_keys.py

Note: the key-generation test creates or replaces local RSA key files, so it should only be run when intentionally generating new keys.

Running the MITM Attack Simulation

The attack simulation uses a separate WebSocket server on port 8766.

Start the attack test server:

python server\server_attack_test.py

Then run the client in attack-test mode:

python client\client.py --attack-test

The attack server performs two main security tests:

Authentication attack using an incorrect public key.
MITM public-key substitution when Alice requests Bob's public key.

The client should detect the substituted key using fingerprint verification and block the communication.

Technologies Used
Python
WebSockets
Cryptography library
RSA
AES-256-GCM
RSA-OAEP
RSA-PSS
SHA-256
JSON
PowerShell
Git and GitHub
Security Design

The project separates different security goals:

Security Goal	Mechanism
Message confidentiality	AES-256-GCM
AES key protection	RSA-OAEP
Message integrity	AES-GCM authentication tag + digital signature
Sender authentication	RSA-PSS signatures
Public-key verification	SHA-256 fingerprint
Replay protection	Unique message IDs
Connection authentication	Challenge-response
MITM detection	Trusted fingerprint comparison
Important Security Limitations

This project is an educational prototype and should not be considered production-ready secure messaging software.

Some limitations include:

The normal server does not maintain a permanent username-to-public-key registration database.
The normal server currently authenticates a user based on the public key submitted during that connection.
Trusted-key verification is performed on the client side.
Replay protection is stored only in memory and is reset when the client restarts.
There is no persistent message history or secure key rotation system.
Private keys are stored locally without password-based encryption.
There is no forward secrecy using protocols such as Diffie-Hellman or X25519.
The system has not undergone a professional security audit.

These limitations are intentional in parts of the project because the main purpose is to demonstrate and understand individual cybersecurity concepts.

Possible Future Improvements

Some improvements that could make the project stronger include:

Permanent server-side public-key registration
X25519 or another forward-secret key exchange
Persistent replay protection with message expiry
Encrypted private-key storage
Secure key rotation
Certificate or public-key infrastructure
Multi-device identity management
Better session management
Secure message history
Rate limiting
Logging and security monitoring
Automated security testing
Formal protocol design and security review
What I Learned

Through this project, I practiced implementing and testing several practical cryptographic concepts instead of only studying them theoretically.

The main concepts I worked with were:

Symmetric and asymmetric encryption
Hybrid encryption
RSA key generation
RSA-OAEP
RSA-PSS
AES-GCM
Digital signatures
Public-key fingerprints
Trusted-key verification
Challenge-response authentication
Replay attack detection
MITM attack simulation
Public-key substitution attacks
WebSocket communication
Security testing
Git and GitHub project management

The project also helped me understand an important security principle:

Encryption alone is not enough. The application also needs a way to authenticate identities and verify that the keys being used actually belong to the intended users.

Disclaimer

This project is intended for educational and cybersecurity learning purposes.

The attack simulations are performed against a local test server and are designed to demonstrate security concepts in a controlled environment.

Do not use the attack components against systems or networks without authorization.

Author

Devapriya

Cybersecurity Student | BCA Graduate

GitHub Repository:

https://github.com/devapriya-cyber/encrypted-chat

This project was created as part of my cybersecurity learning journey and can also be used as a practical project to discuss encryption, authentication, attack simulation, and security testing during an interview.