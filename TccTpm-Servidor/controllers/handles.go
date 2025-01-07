package controllers

import (
	"TccTpm/flows"
	"TccTpm/structs"
	"TccTpm/tools"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-tpm/legacy/tpm2"
)

func InitialCommunication(w http.ResponseWriter, r *http.Request) {
	var requestData structs.ProofOfPossetion

	err := json.NewDecoder(r.Body).Decode(&requestData)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------")
	fmt.Println(requestData)

	fmt.Println()
	fmt.Println(">>>Keys recieved from client")

	ec, err := flows.InitialChallenge(requestData.Data)
	if err != nil {
		fmt.Println(">>>Error ao tentar fazer o provisioning..")
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ec)
}

func SecretCheckForAttestation(w http.ResponseWriter, r *http.Request) {
	var secret structs.CheckSecret
	var result structs.Attest

	if err := json.NewDecoder(r.Body).Decode(&secret); err != nil {
		http.Error(w, "Erro ao decodificar JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf(">>>Segredo enviado pelo cliente: %x", secret)

	if !flows.SecretCheck(secret.Secret) {
		http.Error(w, "\n>>>Falha ao verificar o segredo", http.StatusUnauthorized)
		return
	}
	fmt.Println("\n>>>Sucesso ao comparar o secret.")
	result, err := flows.Attestation()
	result.PcrsToMakeQuote = []uint32{0, 1, 2, 3, 4, 5, 7, 9}
	if err != nil {
		http.Error(w, "\n>>>Erro ao enviar dados da atestação: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf(">>>Fresh Nonce para atestação: %x\n", result.NonceForAttestation)
	fmt.Println(">>>PCR's para atestação: ", result.PcrsToMakeQuote)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "\n>>>Erro ao codificar resposta JSON: "+err.Error(), http.StatusInternalServerError)
	}

}
func VerifyingQuote(w http.ResponseWriter, r *http.Request) {
	var quote structs.QuoteFromClient

	if err := json.NewDecoder(r.Body).Decode(&quote); err != nil {
		http.Error(w, "\n>>>Erro ao decodar o quote: "+err.Error(), http.StatusBadRequest)
		return
	}
	// fmt.Println(">>> teste: ", quote)
	fmt.Printf(">>>Quote enviado pelo cliente : %x\n\n", quote.Quote)
	fmt.Printf(">>>Assinatura do quote : %x\n\n", quote.QuoteSignature)
	fmt.Printf(">>>Pcrs enviados pelo cliente : %x\n\n", quote.PcrsFromClient)
	//devolvendo o quote
	attestationData, _ := tpm2.DecodeAttestationData(quote.Quote)
	//verificar Nonce
	if !flows.NonceCheck(attestationData.ExtraData) {
		http.Error(w, "\n>>>Falha ao verificar o freshNonce do quote.", http.StatusUnauthorized)
		return
	}

	//verificar os pcrs
	Hashed := sha256.New()
	Hashed.Write(quote.PcrsFromClient)
	HashedDigest := Hashed.Sum(nil)
	fmt.Printf(">>>Hashed digest:%x \n\n", HashedDigest)
	if !bytes.Equal(HashedDigest, attestationData.AttestedQuoteInfo.PCRDigest) {
		http.Error(w, "\n>>>Falha ao verificar o digest dos Pcr's", http.StatusUnauthorized)
		return
	}

	//verificar a assinatura do quote
	if err := tools.CheckSignature(flows.DatafromTpm.AKPublicArea, quote.Quote, quote.QuoteSignature); err != nil {
		http.Error(w, "\n>>>Falha ao verificar a Assinatura do quote", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Deu bom!")
}
