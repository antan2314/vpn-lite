// Package main implements the VPN server.
// TODO: This implementation is incomplete.
package main

import (
	"crypto/ecdh"
	"fmt"
	"log"
	"net"
	"vpn-lite/internal/crypto"
)

func main() {
	// Generate ECDH key pair for the server
	serverKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Server is starting.... \nKey pair generated: %x\n", serverKeyPair.Public.Bytes())

	// Start listening for incoming connections on port 8080
	serverListener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Server is accepting connections on port 8080\n")

	// Accept a single client connection
	serverConn, err := serverListener.Accept()
	if err != nil {
		log.Fatal(err)
	}

	// Read the client's public key (P-256 public keys are 65 bytes uncompressed)
	buffer := make([]byte, 65)
	n, err := serverConn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}

	// Parse the client's public key
	clientPublicKey, err := ecdh.P256().NewPublicKey(buffer[:n])
	if err != nil {
		log.Fatal(err)
	}

	// Send the server's public key back to the client
	_, err = serverConn.Write(serverKeyPair.Public.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	// Derive the shared secret using ECDH
	serverClientSharedSecret, err := crypto.DerivedSharedSecret(serverKeyPair.Private, clientPublicKey)
	if err != nil {
		log.Fatal(err)
	}
	// Use shared secret to establish encrypted tunnel
	incomingEncryptedMessageBuffer := make([]byte, 1024)
	n, err = serverConn.Read(incomingEncryptedMessageBuffer)
	if err != nil {
		log.Fatal(err)
	}
	incomingEncryptedMessage, err := crypto.Decrypt(serverClientSharedSecret, incomingEncryptedMessageBuffer[:n])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(incomingEncryptedMessage)) //test to show decryption works

	// TODO: Handle multiple client connections
	// TODO: Forward traffic through the VPN
}
