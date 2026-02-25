# vpn-lite

A lightweight VPN implementation in Go featuring encrypted peer-to-peer communication over TCP.

The end goal is to route all client network traffic through an encrypted tunnel to the server. Currently in the early stages, establishing the cryptographic foundation with interactive encrypted messaging between client and server.

## Status

Work in progress.

## Features

- **ECDH Key Exchange** — Client and server generate P-256 key pairs and perform an Elliptic Curve Diffie-Hellman handshake to derive a shared secret.
- **AES-GCM Encryption** — All messages are encrypted and authenticated using AES-GCM with randomly generated nonces.
- **TOFU Server Verification** — The client uses a trust-on-first-use model to verify the server's identity by saving a SHA-256 fingerprint of the server's public key on first connection and comparing it on subsequent connections.
- **Interactive Messaging** — The client runs an interactive loop where the user can send encrypted messages to the server and receive encrypted responses.

## Project Structure

```
vpn-lite/
├── cmd/
│   ├── client/main.go    # VPN client
│   └── server/main.go    # VPN server
└── internal/
    └── crypto/
        ├── keys.go        # ECDH key pair generation and shared secret derivation
        ├── cipher.go      # AES-GCM encryption and decryption
        └── fingerprint.go # SHA-256 public key fingerprinting
```

## Building

```
go build ./cmd/server
go build ./cmd/client
```

## Usage

Start the server:
```
./server
```

Connect with the client:
```
./client
```

The client will perform an ECDH handshake with the server, verify the server's fingerprint, and then prompt for messages to send over the encrypted tunnel.

## License

MIT
