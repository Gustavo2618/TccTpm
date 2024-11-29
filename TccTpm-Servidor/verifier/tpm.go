package verifier

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func GenerateHere(ak *tpm2.HashValue, pub crypto.PublicKey, symBlockSize int, secret []byte) ([]byte, []byte, error) {
	rsaPub, _ := pub.(*rsa.PublicKey)
	return generateRSA(ak, rsaPub, symBlockSize, secret, rand.Reader)

}

func generateRSA(ak *tpm2.HashValue, pub *rsa.PublicKey, symBlockSize int, secret []byte, rnd io.Reader) ([]byte, []byte, error) {
	cryptohash, err := ak.Alg.Hash()
	if err != nil {
		return nil, nil, err
	}

	seed := make([]byte, symBlockSize)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, fmt.Errorf("\n>>>Erro gerando semente  %v", err)
	}

	label := append([]byte(labelIdentity), 0)
	encSecret, err := rsa.EncryptOAEP(cryptohash.New(), rnd, pub, seed, label)
	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Erro gerando encriptação da semenete %v", err)
	}

	akNameEncoded, err := ak.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Error encodando nome da ak : %v", err)
	}
	symmetricKey, err := tpm2.KDFa(ak.Alg, seed, labelStorage, akNameEncoded, nil, len(seed)*8)
	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Error gerando a chave simetrica: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Error configurando o cipher simetrico: %v", err)
	}
	cv, err := tpmutil.Pack(tpmutil.U16Bytes(secret))
	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Error gerando o cv (TPM2B_Digest): %v", err)
	}
	encIdentity := make([]byte, len(cv))
	cipher.NewCFBEncrypter(c, make([]byte, len(symmetricKey))).XORKeyStream(encIdentity, cv)

	mackey, err := tpm2.KDFa(ak.Alg, seed, labelIntegrity, nil, nil, cryptohash.Size()*8)
	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Error gerando hmac key: %v", err)
	}

	mac := hmac.New(cryptohash.New, mackey)
	mac.Write(encIdentity)
	mac.Write(akNameEncoded)
	integrityHMAC := mac.Sum(nil)
	idObject := &tpm2.IDObject{
		IntegrityHMAC: integrityHMAC,
		EncIdentity:   encIdentity,
	}

	id, err := tpmutil.Pack(idObject)

	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Error encodando IDObject: %v", err)
	}

	packedID, err := tpmutil.Pack(tpmutil.U16Bytes(id))

	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Error enpacotando o id: %v", err)
	}

	packedEncSecret, err := tpmutil.Pack(tpmutil.U16Bytes(encSecret))
	if err != nil {
		return nil, nil, fmt.Errorf("\n>>>Error no secret encriptado: %v", err)
	}

	return packedID, packedEncSecret, nil

}
