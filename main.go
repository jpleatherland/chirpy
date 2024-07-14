package main

import (
	"net/http"
	"log"
	"io"
)

func main() {
	serber := http.NewServeMux()

	log.Print("Listening...")
	serber.Handle("/app/*", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	serber.HandleFunc("/healthz", healthCheck)
	http.ListenAndServe(":8080", serber)

}

func healthCheck(rw http.ResponseWriter, req *http.Request){
	rw.WriteHeader(http.StatusOK)
	io.WriteString(rw, "OK")
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
}
