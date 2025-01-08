package tools

import (
	"crypto/rsa"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
)

func CheckSignature(pub tpm2.Public, attestData []byte, signature []byte) error {
	pubKey, err := pub.Key()
	if err != nil {
		return err
	}

	key, ok := pubKey.(*rsa.PublicKey)
	if ok {
		fmt.Println("\n>>>É uma chave Publica RSA...")
	}

	sigScheme := pub.RSAParameters.Sign
	hash, err := sigScheme.Hash.Hash()

	if err != nil {
		return err
	}

	h := hash.New()
	h.Write(attestData)
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(key, hash, hashed, signature)
}
