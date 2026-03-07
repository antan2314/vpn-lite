// kdf.go provides password-based key derivation for encrypting stored credentials.
// It uses scrypt for key derivation and cryptographic random salt generation.
package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/scrypt"
)

// DeriveKeyFromPassword derives a 32-byte encryption key from a password and salt
// using scrypt (N=32768, r=8, p=1) for use in encrypting stored credentials.
func DeriveKeyFromPassword(password string, salt []byte) ([]byte, error) {
	encryptedPassword, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	return encryptedPassword, err
}

// GenerateSalt generates a 32-byte cryptographically random salt for use with DeriveKeyFromPassword.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
