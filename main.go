package main

// TODO: Remove test code below before production release.

import (
	"fmt"
	"log"
	"vpn-lite/internal/crypto"
)

// main contains temporary test code to verify ECDH key exchange.
// This will be replaced with actual VPN functionality.
func main() {
	//tests for keys.go
	clientKeys, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	serverKeys, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	clientSecret, err := crypto.DerivedSharedSecret(clientKeys.Private, serverKeys.Public)
	if err != nil {
		log.Fatal(err)
	}
	serverSecret, err := crypto.DerivedSharedSecret(serverKeys.Private, clientKeys.Public)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Client Secret: %x\n", clientSecret)
	fmt.Printf("Server Secret: %x\n", serverSecret)

	//tests for cipher.go
	outgoingMessage := []byte("Hello World")
	encryptedMessage, err := crypto.Encrypt(clientSecret, outgoingMessage)
	if err != nil {
		log.Fatal(err)
	}
	decryptedMessage, err := crypto.Decrypt(serverSecret, encryptedMessage)

	fmt.Printf("Decrypted Message: %s\n", decryptedMessage)
}
