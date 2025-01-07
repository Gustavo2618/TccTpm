package structs

import (
	"crypto"

	"github.com/google/go-tpm/legacy/tpm2"
)

type ProofOfPossetion struct {
	Data RequestData `json:"ProofOfPossetion"`
}
type RequestData struct {
	AkPublic         []byte `json:"akPublic"`
	EkPublic         []byte `json:"ekPublic"`
	Certify          []byte `json:"certify"`
	CertifySignature []byte `json:"certifySignature"`
}

type ChallengeResponse struct {
	Credential      []byte `json:"credential"`
	EncryptedSecret []byte `json:"encryptedSecret"`
}
type CheckSecret struct {
	Secret []byte `json:"Client Secret"`
}

type DataFromTpm struct {
	Secret             []byte
	EK                 crypto.PublicKey
	AK                 crypto.PublicKey
	FreshNonceForQuote []byte
	AKPublicArea       tpm2.Public
}

type Attest struct {
	NonceForAttestation []byte   `json:"nonce"`
	PcrsToMakeQuote     []uint32 `json:"PCRS"`
}

type QuoteFromClient struct {
	Quote          []byte `json:"Quote"`
	PcrsFromClient []byte `json:"PCRS"`
	QuoteSignature []byte `json:"QuoteSignature"`
}
