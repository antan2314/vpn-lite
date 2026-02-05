// Package main implements the VPN client.
// TODO: This implementation is incomplete.
package main

import (
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

	// TODO: Receive server's public key
	// TODO: Derive shared secret using ECDH
	// TODO: Establish encrypted tunnel
}
