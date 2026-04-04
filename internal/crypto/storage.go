package crypto

import (
	"os"
)

func SaveServerKeys(serverKeyPair *KeyPair, password string, filepath string) error {
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	encryptionKey, err := DeriveKeyFromPassword(password, salt)
	if err != nil {
		return err
	}

	privateKeyBytes := serverKeyPair.Private.Bytes()
	encryptedPrivateKeyBytes, err := Encrypt(encryptionKey, privateKeyBytes)
	if err != nil {
		return err
	}

	publicKeyBytes := serverKeyPair.Public.Bytes()
	combined := append(salt, publicKeyBytes...)
	combined = append(combined, encryptedPrivateKeyBytes...)

	err = os.WriteFile(filepath, combined, 0600)
	if err != nil {
		return err
	}
	return nil

}
