\# Secure Encrypted Chat Application



A Python-based secure chat application demonstrating authenticated communication, hybrid encryption, public-key fingerprint verification, and detection of public-key substitution attacks.



\## Features



\- RSA-3072 public/private key pairs

\- RSA-PSS authentication

\- AES-256-GCM message encryption

\- RSA-OAEP protection of AES session keys

\- WebSocket client-server communication

\- Public-key fingerprint verification

\- Trusted public-key storage

\- Simulated public-key substitution / MITM attack

\- Detection and blocking of an untrusted public key



\## How It Works



The application uses hybrid encryption.



1\. A random AES-256 session key is generated.

2\. The message is encrypted using AES-256-GCM.

3\. The AES session key is encrypted using the recipient's RSA public key.

4\. The encrypted data is sent through the WebSocket server.

5\. The recipient uses their RSA private key to recover the AES key.

6\. The message is decrypted using AES-256-GCM.



\## Authentication



When a client connects:



1\. The client sends its username and public key.

2\. The server generates a random challenge.

3\. The client signs the challenge using its RSA private key.

4\. The server verifies the signature using the client's public key.

5\. The connection is accepted only after successful authentication.



\## Public-Key Verification



Before communicating with another user, the client can request their public key.



The received key is converted into a fingerprint and compared with the previously trusted fingerprint.



If the fingerprints match:



&#x20;   Trusted public key verified.



If they do not match:



&#x20;   SECURITY WARNING

&#x20;   Public key mismatch!

&#x20;   MESSAGE BLOCKED.



\## MITM Attack Simulation



The project includes a simulated public-key substitution attack.



During the test, the attacker-controlled public key is provided instead of Bob's legitimate public key.



Alice detects that the received key has a different fingerprint and blocks the communication.



Test result:



&#x20;   Public key mismatch!

&#x20;   MESSAGE BLOCKED.



This demonstrates how fingerprint verification can detect a public-key substitution attack.



\## Technologies



\- Python

\- WebSockets

\- RSA

\- AES-256-GCM

\- Python Cryptography library

\- JSON

\- PowerShell



\## Project Structure



&#x20;   encrypted\_chat/

&#x20;   |

&#x20;   +-- client/

&#x20;   |   +-- client.py

&#x20;   |   +-- crypto.py

&#x20;   |   +-- fingerprint.py

&#x20;   |   +-- key\_manager.py

&#x20;   |   +-- rsa\_keys.py

&#x20;   |   +-- trusted\_keys.py

&#x20;   |   +-- keys/

&#x20;   |

&#x20;   +-- server/

&#x20;   |   +-- server.py

&#x20;   |

&#x20;   +-- requirements.txt



\## Installation



Create a virtual environment:



&#x20;   python -m venv venv



Activate it:



&#x20;   .\\venv\\Scripts\\Activate.ps1



Install dependencies:



&#x20;   pip install -r requirements.txt



\## Running the Application



Start the server:



&#x20;   python server\\server.py



In separate terminals, start the clients:



&#x20;   cd client

&#x20;   python client.py



Run one client as Alice and another as Bob.



Request Bob's public key:



&#x20;   /key bob



Send a message:



&#x20;   bob|Hello Bob



\## Security Testing



The application was tested for:



\- RSA authentication

\- AES message encryption

\- Public-key fingerprint verification

\- Trusted-key verification

\- Public-key substitution attack detection

\- Normal encrypted communication after the security test



\## Limitations



This is an educational security prototype and is not intended to replace production messaging systems.



It does not implement the complete security architecture of modern production messaging applications, including mature key-management infrastructure and forward secrecy protocols.



\## Author



Devapriya

