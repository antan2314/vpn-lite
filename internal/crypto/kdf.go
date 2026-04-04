package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/scrypt"
)

func DeriveKeyFromPassword(password string, salt []byte) ([]byte, error) {
	encryptedPassword, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	return encryptedPassword, err
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
