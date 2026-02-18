// Package main implements the VPN client.
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
	// Generate ECDH key pair for the client
	clientKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Client is starting.... \nKey pair generated: %x\n", clientKeyPair.Public.Bytes())

	// Connect to the VPN server
	clientDial, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		log.Fatal(err)
	}

	// Send the client's public key to the server for key exchange
	clientDial.Write(clientKeyPair.Public.Bytes())

	// Receive server's public key
	buffer := make([]byte, 65)
	n, err := clientDial.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	// Parse the server's public key
	serverPublicKey, err := ecdh.P256().NewPublicKey(buffer[:n])
	if err != nil {
		log.Fatal(err)
	}

	// Derive shared secret using ECDH
	clientServerSharedSecret, err := crypto.DerivedSharedSecret(clientKeyPair.Private, serverPublicKey)

	if err != nil {
		log.Fatal(err)
	}
	// Establish encrypted tunnel
	message := []byte("hello world") //test message to make sure encryption and decryption function
	encryptedMessage, err := crypto.Encrypt(clientServerSharedSecret, message)
	if err != nil {
		log.Fatal(err)
	}
	clientDial.Write(encryptedMessage)

}
