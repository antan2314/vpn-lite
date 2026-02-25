// Package main implements the VPN client.
// TODO: This implementation is incomplete.
package main

import (
	"bufio"
	"crypto/ecdh"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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
	// Interactive encrypted message loop — reads user input, encrypts and sends it,
	// then waits for the server's encrypted response and decrypts it.
	userInput := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Please enter message to the server: ")
		// ReadString includes the trailing '\n' in the returned message
		message, err := userInput.ReadString('\n')
		//message = strings.TrimSpace(message)
		if err != nil {
			log.Fatal(err)
		}
		byteMessage := []byte(message) //test message to make sure encryption and decryption function
		encryptedMessage, err := crypto.Encrypt(clientServerSharedSecret, byteMessage)
		if err != nil {
			log.Fatal(err)
		}
		clientDial.Write(encryptedMessage)

		// Read the server's encrypted response
		// TODO: Fixed 1024-byte buffer — responses larger than this will be truncated and decryption will fail
		incomingEncryptedMessageBuffer := make([]byte, 1024)
		n, err = clientDial.Read(incomingEncryptedMessageBuffer)
		if err == io.EOF {
			fmt.Println("Connection closed by server")
			break
		} else if err != nil {
			log.Println("Read error:", err)
			break
		}

		// Decrypt the server's response using the shared secret
		incomingEncryptedMessage, err := crypto.Decrypt(clientServerSharedSecret, incomingEncryptedMessageBuffer[:n])
		if err != nil {
			log.Println("Decrypt error:", err)
			break
		}
		fmt.Println("Incoming server message: " + string(incomingEncryptedMessage)) //test to show decryption works

	}
}
