// Package crypto provides cryptographic utilities for secure VPN communication.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// KeyPair holds an ECDH key pair used for secure key exchange between VPN peers.
type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// GenerateKeyPair creates a new ECDH key pair using the P-256 curve.
// The public key can be shared with peers to establish a shared secret,
// while the private key must be kept secure.
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private key: %v\n", err)
		return nil, err
	}
	publicKey := privateKey.PublicKey()

	fmt.Println("ECDH Key Pair Generated Successfully!")

	return &KeyPair{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}
