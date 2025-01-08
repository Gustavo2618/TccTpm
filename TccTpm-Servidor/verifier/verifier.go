package verifier

import (
	"TccTpm/structs"
	"TccTpm/tools"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	symBlockSize   = 16
	labelIdentity  = "IDENTITY"
	labelStorage   = "STORAGE"
	labelIntegrity = "INTEGRITY"
)

func VerifyCertify(ek crypto.PublicKey, ak tpm2.Public, certifydata []byte, certifySignature []byte) (nonce []byte, ec structs.ChallengeResponse, err error) {

	certify, err := tpm2.DecodeAttestationData(certifydata)
	if err != nil {
		fmt.Println(">>>Error decodando Certify", err)
		return nil, structs.ChallengeResponse{}, err
	}

	if certify.AttestedCertifyInfo == nil {
		return nil, structs.ChallengeResponse{}, fmt.Errorf("\n>>>Erro certify info")
	}
	if certify.AttestedCertifyInfo.Name.Digest == nil {
		return nil, structs.ChallengeResponse{}, fmt.Errorf("\n>>>Erro certify info name")
	}
	if _, err := certify.AttestedCertifyInfo.Name.MatchesPublic(ak); err != nil {
		return nil, structs.ChallengeResponse{}, fmt.Errorf("\n>>>Erro certify de uma AK diferente")
	}
	if err := tools.CheckSignature(ak, certifydata, certifySignature); err != nil {
		return nil, structs.ChallengeResponse{}, fmt.Errorf("\n>>>Erro ao verificar assinatura do certify")
	}
	fmt.Println("\n>>>Assinatura verificada...")

	hash := sha256.New()
	rnd := rand.Reader
	nonce = make([]byte, hash.Size())

	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return nil, structs.ChallengeResponse{}, err
	}

	credential, encryptedSecret, err := GenerateHere(certify.AttestedCertifyInfo.Name.Digest, ek, symBlockSize, nonce)

	if err != nil {
		return nil, structs.ChallengeResponse{}, nil
	}
	return nonce, structs.ChallengeResponse{
		Credential:      credential,
		EncryptedSecret: encryptedSecret,
	}, nil
}

func VerifyAkProps(ak tpm2.Public) error {
	fmt.Println("\n\n>>>Verificando propriedades da AK...")
	props := ak.Attributes
	if props&tpm2.FlagFixedTPM == 0 {
		return fmt.Errorf("\n>>>A chave tem que ser fixada ao tpm")
	}
	fmt.Println("\n>>>Flag FixedTPM ok.")
	if props&tpm2.FlagRestricted == 0 {
		return fmt.Errorf("\n>>>A chave tem que ser restrita")
	}
	fmt.Println("\n>>>Flag Restricted ok.")
	if props&tpm2.FlagSign == 0 {
		return fmt.Errorf("\n>>>A chave te que ser de assinatura")
	}
	fmt.Printf("\n>>>Flag de Assinatura ok.\n")

	return nil
}
