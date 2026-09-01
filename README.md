\# 🔐 Secure Encrypted Chat Application



A Python-based secure chat application demonstrating \*\*hybrid encryption, authenticated communication, message integrity, public-key fingerprint verification, trusted-key protection, replay-attack detection, and simulated MITM/public-key substitution attacks\*\*.



> \*\*Educational security project — not intended for production use.\*\*



\## 🛡️ Security Features



\* 🔑 \*\*RSA-3072\*\* public/private key pairs

\* 🔒 \*\*AES-256-GCM\*\* authenticated message encryption

\* 🔐 \*\*RSA-OAEP with SHA-256\*\* for protecting AES session keys

\* ✍️ \*\*RSA-PSS with SHA-256\*\* digital signatures

\* 🪪 \*\*SHA-256 public-key fingerprints\*\*

\* 🤝 \*\*Trusted public-key verification\*\*

\* 🛡️ \*\*Message signature verification\*\*

\* 🔁 \*\*Replay-attack detection using message IDs\*\*

\* 🔑 \*\*Challenge-response authentication\*\*

\* 🌐 \*\*WebSocket-based communication\*\*

\* 🚨 \*\*Public-key substitution / MITM attack simulation\*\*

\* ⛔ \*\*Blocking of untrusted public keys\*\*



\## 🏗️ Architecture



```text

&#x20;            ┌──────────────────────┐

&#x20;            │    WebSocket Server  │

&#x20;            │                      │

&#x20;            │  Authentication      │

&#x20;            │  Message Routing     │

&#x20;            │  Public Key Exchange │

&#x20;            └──────────┬───────────┘

&#x20;                       │

&#x20;             ┌─────────┴─────────┐

&#x20;             │                   │

&#x20;       ┌─────▼─────┐       ┌─────▼─────┐

&#x20;       │   Alice   │       │    Bob    │

&#x20;       │  Client   │       │  Client   │

&#x20;       └───────────┘       └───────────┘

&#x20;             │                   │

&#x20;             └── Encrypted ──────┘

&#x20;                 Messages

```



The server routes messages between clients, while the message contents are protected using hybrid encryption.



\## 🔒 How Message Encryption Works



The application uses \*\*hybrid encryption\*\*, combining RSA and AES.



1\. A random \*\*AES-256 session key\*\* is generated.

2\. The message is encrypted using \*\*AES-256-GCM\*\*.

3\. The AES session key is encrypted using the recipient's \*\*RSA public key\*\* with RSA-OAEP.

4\. The encrypted AES key, nonce, and ciphertext are sent through the WebSocket server.

5\. The recipient uses their RSA private key to recover the AES session key.

6\. AES-GCM decrypts and authenticates the message.



\### Message Integrity



Messages are also digitally signed using \*\*RSA-PSS\*\*.



The signature covers:



```text

message\_id

\+ encrypted AES key

\+ nonce

\+ ciphertext

```



The recipient verifies the signature before accepting and decrypting the message.



\## 🔑 Authentication



When a client connects:



1\. The client sends its username and public key.

2\. The server generates a random authentication challenge.

3\. The client signs the challenge using its RSA private key.

4\. The server verifies the signature using the submitted public key.

5\. The connection is accepted only after successful verification.



This demonstrates \*\*challenge-response authentication\*\* and prevents a client from authenticating without possessing the corresponding private key.



\## 🪪 Public-Key Fingerprint Verification



Before communicating with another user, the client can request their public key.



The public key is converted into a SHA-256 fingerprint.



Example:



```text

fdc4:89e4:03f0:39e3:00c3:3b4e:d50a:1038:...

```



The received fingerprint is compared against the previously trusted fingerprint.



\### Trusted Key



```text

✓ Trusted public key verified.

```



\### Untrusted Key



```text

🚨 SECURITY WARNING 🚨



Public key mismatch!

MESSAGE BLOCKED.

```



This provides protection against a public-key substitution attack when the legitimate fingerprint has already been trusted.



\## 🔁 Replay Attack Protection



Each encrypted message contains a unique `message\_id`.



The client maintains a set of previously accepted message IDs.



If the same message is received again:



```text

Replay attack detected!

Message blocked.

```



The message is therefore not processed a second time during the current client session.



\## 🚨 MITM / Public-Key Substitution Attack Simulation



The project includes a dedicated attack simulation.



During the test, an attacker-controlled public key is substituted for Bob's legitimate public key.



Alice receives the attacker's key and calculates its fingerprint.



The fingerprint does not match Bob's trusted fingerprint:



```text

🚨 SECURITY WARNING 🚨

Public key mismatch!

MESSAGE BLOCKED.

```



This demonstrates how \*\*public-key fingerprint verification can detect a public-key substitution attack\*\*.



The project also includes an authentication attack test where an attacker attempts to impersonate Bob.



The server rejects the attack:



```text

AUTH\_FAILED|Public key does not match registered key

```



\## 🧪 Security Tests



The project contains tests covering:



\* RSA encryption/decryption

\* RSA-PSS signatures

\* AES-256-GCM encryption

\* Hybrid RSA + AES encryption

\* Public-key fingerprints

\* Trusted-key storage

\* Message signatures

\* Replay protection

\* Public-key substitution / MITM detection

\* Authentication impersonation testing



\## 📁 Project Structure



```text

encrypted\_chat/

│

├── client/

│   ├── client.py

│   ├── crypto.py

│   ├── fingerprint.py

│   ├── key\_manager.py

│   ├── rsa\_keys.py

│   ├── trusted\_keys.py

│   ├── trusted\_keys.json

│   │

│   └── tests/

│       ├── test\_crypto.py

│       ├── test\_fingerprint.py

│       ├── test\_hybrid.py

│       ├── test\_keys.py

│       ├── test\_key\_exchange.py

│       ├── test\_message\_signature.py

│       ├── test\_replay\_protection.py

│       ├── test\_rsa.py

│       ├── test\_signature.py

│       └── test\_trusted\_keys.py

│

├── server/

│   ├── server.py

│   └── server\_attack\_test.py

│

├── requirements.txt

├── README.md

└── .gitignore

```



> Private RSA keys, attack artifacts, local trusted-key data, and backup files are excluded from Git using `.gitignore`.



\## ⚙️ Technologies



\* \*\*Python\*\*

\* \*\*WebSockets\*\*

\* \*\*Cryptography\*\*

\* \*\*RSA\*\*

\* \*\*AES-256-GCM\*\*

\* \*\*RSA-OAEP\*\*

\* \*\*RSA-PSS\*\*

\* \*\*SHA-256\*\*

\* \*\*JSON\*\*

\* \*\*PowerShell\*\*



\## 💻 Installation



\### 1. Clone the repository



```powershell

git clone https://github.com/devapriya-cyber/encrypted-chat.git

cd encrypted-chat

```



\### 2. Create a virtual environment



```powershell

python -m venv venv

```



\### 3. Activate the virtual environment



```powershell

.\\venv\\Scripts\\Activate.ps1

```



\### 4. Install dependencies



```powershell

pip install -r requirements.txt

```



\## ▶️ Running the Application



\### Start the normal server



Open Terminal 1:



```powershell

python server\\server.py

```



\### Start the clients



Open separate terminals:



```powershell

python client\\client.py

```



Run one client as Alice and another as Bob.



\### Request Bob's public key



Inside the client:



```text

/key bob

```



\### Send a message



```text

bob|Hello Bob

```



\## 🚨 Running the Attack Simulation



Start the attack-test server:



```powershell

python server\\server\_attack\_test.py

```



The attack-test client can be started with:



```powershell

python client\\client.py --attack-test

```



The attack simulation demonstrates:



1\. Attacker impersonation attempt

2\. Server authentication rejection

3\. Public-key substitution

4\. Fingerprint mismatch detection

5\. Communication blocking



\## 🔬 Security Design



| Security Mechanism   | Purpose                                      |

| -------------------- | -------------------------------------------- |

| RSA-3072             | Public-key cryptography                      |

| RSA-OAEP             | Protect AES session keys                     |

| AES-256-GCM          | Confidentiality and authenticated encryption |

| RSA-PSS              | Digital signatures                           |

| SHA-256              | Fingerprints and cryptographic hashing       |

| Challenge-response   | Client authentication                        |

| Trusted fingerprints | Public-key verification                      |

| Message IDs          | Replay detection                             |

| WebSockets           | Client-server communication                  |



\## ⚠️ Security Limitations



This is an \*\*educational security prototype\*\*, not a production messaging application.



Current limitations include:



\* No forward secrecy such as an ephemeral Diffie-Hellman protocol

\* Replay state is maintained in memory and is not persistent across restarts

\* Private keys are stored locally without password-based encryption

\* Key provisioning/trust establishment is simplified for demonstration

\* The application is configured for local WebSocket communication

\* It does not implement the complete key-management architecture used by modern secure messaging systems



These limitations are intentional or simplified to keep the project suitable for learning and security demonstration.



\## 🎯 Project Goal



The goal of this project is to demonstrate how multiple cryptographic security mechanisms can work together to protect a messaging system against common threats such as:



\* Eavesdropping

\* Message tampering

\* Replay attacks

\* Unauthorized authentication

\* Public-key substitution

\* Man-in-the-middle attacks



\## 👩‍💻 Author



\*\*Devapriya\*\*



Cybersecurity Student | Python | Network Security | Cryptography



