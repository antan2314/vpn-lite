package crypto

import (
	"crypto/sha256"
	"fmt"
)

func Fingerprint(publicKeyBytes []byte) string {
	publicKey := sha256.New()
	publicKey.Write([]byte(publicKeyBytes))
	return fmt.Sprintf("%x", publicKey.Sum(nil))
}
