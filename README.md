# WhisperLink: A Secure, Serverless, Peer-to-Peer Chat Application

WhisperLink is a lightweight, serverless, peer-to-peer chat application designed for secure, encrypted communication between two peers. The app ensures privacy and security by encrypting all messages, while allowing optional file sharing between connected peers.

## Features

- **Serverless Architecture**: WhisperLink operates entirely without a centralized server. Peers connect directly to each other without relying on any third-party infrastructure.
  
- **Peer-to-Peer Communication**: The application facilitates secure communication between two peers at a time, establishing a direct link for chat.
  
- **Encrypted Messages**: All messages between peers are encrypted using AES-256 symmetric encryption, ensuring that communication remains private and secure.
  
- **Optional File Sharing**: WhisperLink offers the ability to share files securely between connected peers as an optional feature.
  
- **Simple Key Exchange**: The application uses RSA public-key encryption to securely exchange the AES key used for encrypting messages.

## Peer Discovery Mechanism

WhisperLink employs a peer discovery mechanism to establish connections between two instances (peers):

### Instance A - Instance B

```plaintext
Instance A                             Instance B
   |                                        |
   | <----> (UDP Broadcasts Presence) <-----|  
   |       (Sending UDP broadcasts)         |  
   | <----> (Listening for Broadcasts) <----|  
   |          (Receives B's Broadcast)      |
   |                                        |
   |--- Initiates TCP Connection to B ----->|
   |                                        |
   |<--------- TCP Chat Communication ----->|
