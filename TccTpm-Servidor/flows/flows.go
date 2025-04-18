package flows

import (
	"TccTpm/structs"
	"TccTpm/verifier"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

var DatafromTpm structs.DataFromTpm

func InitialChallenge(data structs.RequestData) (ec structs.ChallengeResponse, err error) {

	//loading EK
	ekBytes := data.EkPublic
	ek, err := tpm2.DecodePublic(ekBytes)
	if err != nil {
		fmt.Println(">>>Error decoding public Ek", err)
		return structs.ChallengeResponse{}, err
	}

	DatafromTpm.EK, _ = ek.Key()
	fmt.Printf("\n>>>EK: %x", DatafromTpm.EK)
	//loading AK
	akBytes := data.AkPublic
	ak, err := tpm2.DecodePublic(akBytes)
	DatafromTpm.AKPublicArea = ak
	DatafromTpm.AK, _ = ak.Key()
	fmt.Printf("\n\n>>>AK: %x", DatafromTpm.AK)
	if err != nil {
		fmt.Println(">>>Error decoding public Ak", err)
		return structs.ChallengeResponse{}, err
	}
	if err = verifier.VerifyAkProps(ak); err != nil {
		fmt.Println(">>>Error lak propriedades: ", err)
		return structs.ChallengeResponse{}, err
	}

	//iniciando a geração do challenger
	certifyBytes := data.Certify
	certifySignatureBytes := data.CertifySignature
	fmt.Printf("\n>>>Bytes de certificacao: %x\n", certifyBytes)
	fmt.Printf("\n>>>Bytes de assinatura da certificacao: %x\n", certifySignatureBytes)

	nonce, ec, err := verifier.VerifyCertify(DatafromTpm.EK, ak, certifyBytes, certifySignatureBytes)
	if err != nil {
		fmt.Println("\n>>>Erro gerando o challenge: ", err)
		return structs.ChallengeResponse{}, err
	}
	DatafromTpm.Secret = nonce
	fmt.Printf("\n>>>Credenciais: %x\n", ec.Credential)
	fmt.Printf("\n>>>Segredo: %x\n", ec.EncryptedSecret)
	fmt.Printf("\n>>>Nonce para realizar o challenge do cliente: %x\n\n", nonce)

	return ec, err
}

// verificação do secret enviado pelo cliente
func SecretCheck(nonce []byte) bool {
	return bytes.Equal(nonce, DatafromTpm.Secret)
}
func NonceCheck(nonce []byte) bool {
	return bytes.Equal(nonce, DatafromTpm.FreshNonceForQuote)
}

// criando nonce para atestação com quote
func Attestation() (response structs.Attest, err error) {
	newNonce := make([]byte, 20)
	rnd := rand.Reader
	io.ReadFull(rnd, newNonce)
	response.NonceForAttestation = newNonce
	DatafromTpm.FreshNonceForQuote = newNonce
	return response, nil
}

