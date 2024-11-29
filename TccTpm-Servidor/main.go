package main

import (
	"TccTpm/routes"
	"log"
	"net/http"

	//"github.com/google/go-tpm/legacy/tpm2"
	"github.com/gorilla/mux"
)

func main() {
	// tpm2.DecodePublic()
	router := mux.NewRouter()
	routes.RegisterRoutes(router)
	log.Println("Server is Running....")
	log.Fatal(http.ListenAndServe(":8080", router))
}
