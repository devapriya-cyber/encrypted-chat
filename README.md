# 🔐 Secure Encrypted Chat

A Python-based secure messaging application developed as a cybersecurity project to demonstrate practical cryptography, authentication, message integrity, trusted public-key verification, replay protection, and MITM attack detection.

> **Educational project:** This application is designed for learning and controlled security demonstrations. It is not intended to be a production-ready secure messaging platform.

---

## 🚀 Project Overview

The Secure Encrypted Chat application demonstrates how different cryptographic mechanisms can work together to protect communication between users.

The project implements:

- RSA-3072 public/private key pairs
- AES-256-GCM message encryption
- RSA-OAEP hybrid encryption
- RSA-PSS digital signatures
- SHA-256 public-key fingerprints
- Challenge-response authentication
- Trusted public-key verification
- Replay attack detection
- MITM/public-key substitution attack simulation
- Automated security tests

The main objective is to understand how confidentiality, integrity, authentication, and key verification can be implemented in a practical Python application.

---

## 🛡️ Security Features

### 🔑 RSA-3072 Key Generation

Each user has an RSA-3072 public/private key pair.

Example:

```text
client/keys/
├── alice_private.pem
├── alice_public.pem
├── bob_private.pem
└── bob_public.pem

Private keys are excluded from Git using .gitignore.

🔒 AES-256-GCM Encryption

Messages are encrypted using AES-256-GCM.

AES-GCM provides authenticated encryption and protects the confidentiality and integrity of the encrypted message.

The message package contains:

Encrypted AES Key
Nonce
Ciphertext
Message ID
Signature
🔐 Hybrid Encryption

The project uses hybrid encryption instead of using RSA to encrypt the entire message.

The process is:

Random AES-256 Key
        │
        ▼
   AES-256-GCM
        │
        ▼
Encrypted Message


AES Key
   │
   ▼
Recipient RSA Public Key
   │
   ▼
RSA-OAEP
   │
   ▼
Encrypted AES Key

The recipient uses their RSA private key to recover the AES key and decrypt the message.

🔐 RSA-OAEP

RSA-OAEP is used to securely encrypt the randomly generated AES key.

The implementation uses SHA-256 with MGF1.

✍️ RSA-PSS Digital Signatures

Messages are digitally signed using RSA-PSS.

The signature covers:

message_id
+
encrypted AES key
+
nonce
+
ciphertext

The receiver verifies the signature before accepting the message.

If any signed data is modified, signature verification fails.

🆔 Message IDs

Each message contains a message identifier.

Example:

msg-001
msg-002
msg-003

The message ID is included in the digital signature and is also used for replay detection.

🔁 Replay Attack Protection

The client maintains a record of message IDs that have already been processed.

seen_message_ids = set()

When a message arrives:

The signature is verified.
The message ID is checked.
If the ID was already processed, the message is rejected.
Otherwise, the ID is recorded.
The message is accepted and decrypted.

Example:

First delivery:
msg-001 → Accepted

Replay:
msg-001 → 🚨 Replay attack detected → Blocked

New message:
msg-002 → Accepted

The current implementation keeps replay state in memory for the running client session.

🔎 Public-Key Fingerprints

The application generates a SHA-256 fingerprint from a user's public key.

The public key is converted to DER format before hashing.

Example:

fdc4:89e4:03f0:39e3:00c3:3b4e:d50a:1038:
4af0:1887:d366:33e4:ae14:1cc4:7786:180f

Fingerprints provide a compact way to compare and verify public keys.

🔐 Trusted Public Keys

Trusted fingerprints are stored locally in:

client/trusted_keys.json

When a public key is received, its fingerprint can be compared with the trusted fingerprint.

If the fingerprint does not match, the client blocks the communication.

Example:

🚨 SECURITY WARNING 🚨

Public key mismatch!
MESSAGE BLOCKED.
🚨 MITM Attack Simulation

The project includes a controlled Man-in-the-Middle/public-key substitution attack simulation.

The attack attempts to replace Bob's legitimate public key with an attacker's public key.

Normal Communication
Alice
  │
  │ Bob's legitimate public key
  ▼
Server
  │
  ▼
Bob
MITM Simulation
Alice
  │
  │ Requests Bob's public key
  ▼
Attack Simulation
  │
  │ Replaces Bob's key
  ▼
Attacker's Public Key
  │
  ▼
Alice

Alice calculates the fingerprint of the received public key.

Because the attacker's public key produces a different fingerprint, Alice detects the substitution and blocks the communication.

Example:

Public key received for bob.

bob's fingerprint:
ddb9:9ac3:4896:fd8d:25f9:2dbb:5cbb:
dc7b:f5fe:9c46:32b8:0d43:592e:6727:b96d:45c3

🚨 SECURITY WARNING 🚨
Public key mismatch!
MESSAGE BLOCKED.
📸 MITM Attack Detection Proof

The following screenshot demonstrates the client detecting the substituted public key and blocking the communication.

🧪 Attacker Impersonation Test

The project also includes an authentication attack test.

The attacker attempts to connect using an existing username while providing a different public key.

The attack-test server compares the submitted public key with the registered public key.

Example result:

Attacker connected as bob.
Attacker public key sent.

Server response:
AUTH_FAILED|Public key does not match registered key

Attack test stopped: no authentication challenge.

This demonstrates protection against simple public-key substitution during authentication in the attack-test environment.

🔐 Challenge-Response Authentication

The application uses a challenge-response mechanism to demonstrate proof of possession of a private key.

The process is:

CLIENT                         SERVER

Username -------------------->

Public Key ------------------>

                  Generate Random Challenge
                  <-------------------------

Sign Challenge
using Private Key

Signature ------------------->

                  Verify Signature
                         │
                  ┌──────┴──────┐
                  │             │
                Valid         Invalid
                  │             │
                  ▼             ▼
            AUTH_SUCCESS   AUTH_FAILED

The private key itself is never sent to the server during authentication.

🧱 Architecture
                  ┌─────────────────────┐
                  │       ALICE         │
                  │                     │
                  │ RSA Keys            │
                  │ AES-GCM             │
                  │ RSA-OAEP            │
                  │ RSA-PSS             │
                  │ Fingerprint         │
                  │ Replay Protection   │
                  └──────────┬──────────┘
                             │
                             │ WebSocket
                             ▼
                  ┌─────────────────────┐
                  │       SERVER        │
                  │                     │
                  │ Authentication      │
                  │ Public Keys         │
                  │ Message Routing     │
                  └──────────┬──────────┘
                             │
                             │ WebSocket
                             ▼
                  ┌─────────────────────┐
                  │        BOB          │
                  │                     │
                  │ RSA Keys            │
                  │ AES-GCM             │
                  │ RSA-OAEP            │
                  │ RSA-PSS             │
                  │ Fingerprint         │
                  │ Replay Protection   │
                  └─────────────────────┘
📁 Project Structure
encrypted-chat/
│
├── client/
│   ├── client.py
│   ├── crypto.py
│   ├── fingerprint.py
│   ├── key_manager.py
│   ├── rsa_keys.py
│   ├── trusted_keys.py
│   ├── trusted_keys.json
│   │
│   ├── attacker.py
│   │
│   ├── keys/
│   │   ├── alice_private.pem
│   │   ├── alice_public.pem
│   │   ├── bob_private.pem
│   │   └── bob_public.pem
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
🧪 Security Tests
AES Encryption Test
python client\test_crypto.py

Tests AES encryption and decryption.

Fingerprint Test
python client\test_fingerprint.py

Tests public-key fingerprint generation.

Hybrid Encryption Test
python client\test_hybrid.py

Tests AES encryption together with RSA-OAEP key protection.

RSA Test
python client\test_rsa.py

Tests RSA encryption and decryption.

Digital Signature Test
python client\test_signature.py

Tests valid and tampered signatures.

Message Signature Test
python client\test_message_signature.py

Tests message signature verification and tamper detection.

Replay Protection Test
python client\test_replay_protection.py

Tests detection of repeated message IDs.

Trusted Key Test
python client\test_trusted_keys.py

Tests trusted fingerprint storage and retrieval.

💻 Technologies
Programming
Python 3
Cryptography
RSA-3072
AES-256-GCM
RSA-OAEP
RSA-PSS
SHA-256
Networking
WebSockets
Python websockets
Development
Git
GitHub
PowerShell
📦 Installation

Clone the repository:

git clone https://github.com/devapriya-cyber/encrypted-chat.git

Enter the project directory:

cd encrypted-chat

Create a virtual environment:

python -m venv venv

Activate it:

.\venv\Scripts\Activate.ps1

Install dependencies:

pip install -r requirements.txt
▶️ Running the Normal Application
Start the server
python server\server.py

The normal server runs on:

ws://localhost:8765
Start the client

In another terminal:

python client\client.py

Start another client instance for the second user when required.

🚨 Running the Attack Simulation

Start the attack-test server:

python server\server_attack_test.py

The attack-test server runs on:

ws://localhost:8766

Run the client against the attack-test server:

python client\client.py --attack-test

The attack server intentionally substitutes Bob's public key with the attacker's public key to demonstrate MITM detection.

🔬 Security Demonstration Flow
1. Start attack-test server
          │
          ▼
2. Alice connects
          │
          ▼
3. Alice authenticates
          │
          ▼
4. Alice requests Bob's public key
          │
          ▼
5. Attack simulation replaces
   Bob's key with attacker's key
          │
          ▼
6. Alice receives substituted key
          │
          ▼
7. Alice calculates fingerprint
          │
          ▼
8. Fingerprint does not match
   trusted Bob fingerprint
          │
          ▼
9. 🚨 Security warning
          │
          ▼
10. Communication blocked
🔍 Cryptographic Design
Security Function	Algorithm	Purpose
Asymmetric cryptography	RSA-3072	Key operations and authentication
Message encryption	AES-256-GCM	Confidentiality and authenticated encryption
AES key protection	RSA-OAEP	Encrypt AES keys
Digital signatures	RSA-PSS	Authentication and integrity
Fingerprinting	SHA-256	Public-key identification
Communication	WebSockets	Client-server transport
🎯 Why Hybrid Encryption?

RSA is not efficient for encrypting large amounts of data.

Therefore, the application uses:

RSA
 ↓
Protect AES key

AES-GCM
 ↓
Encrypt message

This allows the system to combine the advantages of asymmetric and symmetric cryptography.

🛡️ Security Properties Demonstrated
Confidentiality

AES-256-GCM encrypts message content.

Integrity

AES-GCM authentication and RSA-PSS signatures help detect modification.

Authentication

Challenge-response authentication demonstrates proof of possession of a private key.

Public-Key Verification

SHA-256 fingerprints allow unexpected public-key changes to be detected.

Replay Detection

Previously processed message IDs are rejected during the current client session.

MITM Detection

A substituted public key produces a different fingerprint and can be blocked.

⚠️ Security Limitations

This is an educational prototype and has important limitations.

Session-Based Replay Protection

Replay protection currently uses an in-memory set:

seen_message_ids = set()

Replay state is therefore lost when the client application is restarted.

Local Trusted-Key Storage

Trusted fingerprints are stored locally rather than using a production-grade identity and trust infrastructure.

Localhost Demonstration

The project is primarily designed for local testing using:

localhost
Attack Server

server_attack_test.py intentionally performs attack simulations and should not be used as a production server.

Transport Security

The demonstration uses local WebSocket communication. A real deployment would require secure transport such as TLS/WSS.

Key Management

The project demonstrates cryptographic key management concepts but does not implement a complete production-grade key management system.

No Forward Secrecy

The current RSA-based design does not implement a modern forward-secret key agreement protocol.

🎓 Learning Objectives

This project was created to gain practical experience with:

Applied cryptography
RSA key generation
Symmetric encryption
Asymmetric encryption
Hybrid encryption
AES-GCM
RSA-OAEP
RSA-PSS
Digital signatures
Public-key fingerprints
Authentication
Trusted-key verification
Replay attacks
MITM attacks
Public-key substitution
WebSocket communication
Security testing
Attack simulation
📊 Example Test Results
Digital Signature
Signature valid: True
Tampered data valid: False
Replay Protection
First delivery accepted.

Replay detected:
Message ID msg-001 has already been processed.

New message msg-002 accepted.
MITM Detection
Public key received for bob.

🚨 SECURITY WARNING 🚨
Public key mismatch!
MESSAGE BLOCKED.
Impersonation Test
Attacker connected as bob.
Attacker public key sent.

Server response:
AUTH_FAILED|Public key does not match registered key

Attack test stopped: no authentication challenge.
📸 Security Demonstration Evidence

The repository includes:

mitm-detection.png

This screenshot provides visual evidence of the MITM/public-key substitution detection implemented in the project.

🚀 Future Improvements

Possible improvements for a more advanced implementation include:

TLS/WSS communication
Forward secrecy using modern key agreement
Persistent replay protection
Secure key rotation
Improved identity verification
Secure encrypted key storage
Session expiration
Rate limiting
Better logging and monitoring
Multi-device key management
Stronger production-grade trust establishment
Additional automated security tests
📚 Important Security Note

This project demonstrates real cryptographic primitives and security concepts, but it should not be considered a production-secure messaging application.

Real-world secure messaging systems require extensive threat modeling, secure key management, authenticated transport, forward secrecy, secure implementation practices, and independent security auditing.

The attack simulations included in this repository are intended only for controlled, authorized cybersecurity testing.

👩‍💻 Author

Devapriya

Cybersecurity Student

Areas demonstrated in this project:

Python
Cryptography
Cybersecurity
Security Testing
Network Security
Authentication
MITM Detection
⭐ GitHub Repository

https://github.com/devapriya-cyber/encrypted-chat.git

If this project helped you understand practical cryptography and secure communication, consider giving the repository a ⭐.

📜 Disclaimer

This project is intended for educational purposes and authorized security testing only.

Do not use the attack simulation components against systems, networks, accounts, or users without explicit permission.