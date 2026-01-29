package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private key: %v\n", err)
		return nil, err
	}
	publicKey := privateKey.PublicKey()

	fmt.Println("ECDH Key Pair Generated Successfully!")
	// For demonstration only: Avoid printing sensitive private key material in production.
	fmt.Printf("Public Key : %x\n", publicKey.Bytes())
	fmt.Printf("Private Key : %x\n", privateKey.Bytes())

	return &KeyPair{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}
