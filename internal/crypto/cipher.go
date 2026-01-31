package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Encrypt encrypts plaintext using AES-GCM with the provided key.
// Returns the ciphertext with the nonce prepended.
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	encryptKey, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encryptKeyGCM, err := cipher.NewGCM(encryptKey)
	if err != nil {
		return nil, err
	}
	encryptNonce := make([]byte, encryptKeyGCM.NonceSize())
	_, err = rand.Read(encryptNonce)
	if err != nil {
		return nil, err
	}
	encryptCipherText := encryptKeyGCM.Seal(encryptNonce, encryptNonce, plaintext, nil)
	return encryptCipherText, nil
}

// Decrypt decrypts ciphertext using AES-GCM with the provided key.
// Expects the nonce to be prepended to the ciphertext (as produced by Encrypt).
// Returns the original plaintext or an error if decryption fails.
func Decrypt(key []byte, cipherText []byte) ([]byte, error) {
	decryptKey, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decryptKeyGCM, err := cipher.NewGCM(decryptKey)
	if err != nil {
		return nil, err
	}

	decryptCipherTextNonce := cipherText[:decryptKeyGCM.NonceSize()]
	decryptCipherTextPostNonce := cipherText[decryptKeyGCM.NonceSize():]

	decryptedData, err := decryptKeyGCM.Open(nil, decryptCipherTextNonce, decryptCipherTextPostNonce, nil)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil

}
