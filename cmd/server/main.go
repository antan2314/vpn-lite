// Package main implements the VPN server.
// TODO: This implementation is incomplete.
package main

import (
	"crypto/ecdh"
	"fmt"
	"io"
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

	for {
		// Accept a single client connection
		serverConn, err := serverListener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		// Read the client's public key (P-256 public keys are 65 bytes uncompressed)
		buffer := make([]byte, 65)
		n, err := serverConn.Read(buffer)
		if err != nil {
			log.Println(err)
			_ = serverConn.Close()
			continue
		}

		// Parse the client's public key
		clientPublicKey, err := ecdh.P256().NewPublicKey(buffer[:n])
		if err != nil {
			log.Println(err)
			_ = serverConn.Close()
			continue
		}
		// Send the server's public key back to the client
		_, err = serverConn.Write(serverKeyPair.Public.Bytes())
		if err != nil {
			log.Println(err)
			_ = serverConn.Close()
			continue
		}
		// Derive the shared secret using ECDH
		serverClientSharedSecret, err := crypto.DerivedSharedSecret(serverKeyPair.Private, clientPublicKey)
		if err != nil {
			log.Println(err)
			_ = serverConn.Close()
			continue
		}
		for {
			// Use shared secret to establish encrypted tunnel
			incomingEncryptedMessageBuffer := make([]byte, 1024)
			n, err = serverConn.Read(incomingEncryptedMessageBuffer)
			if err == io.EOF {
				fmt.Println("Connection closed by client")
				break
			} else if err != nil {
				log.Println("Read error:", err)
				break
			}

			incomingEncryptedMessage, err := crypto.Decrypt(serverClientSharedSecret, incomingEncryptedMessageBuffer[:n])
			if err != nil {
				log.Println("Decrypt error:", err)
				break
			}
			fmt.Println(string(incomingEncryptedMessage)) //test to show decryption works
		}
		_ = serverConn.Close()
		// TODO: Handle multiple client connections
		// TODO: Forward traffic through the VPN
	}
}
