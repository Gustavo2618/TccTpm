package routes

import (
	"TccTpm/controllers"

	// "github.com/google/go-tpm/legacy/tpm2"
	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router) {

	router.HandleFunc("/InitialCommunication", controllers.InitialCommunication).Methods("POST")
	router.HandleFunc("/secretCheckForAttestation", controllers.SecretCheckForAttestation).Methods("POST")
	router.HandleFunc("/resultAttestation", controllers.VerifyingQuote).Methods("POST")
}
