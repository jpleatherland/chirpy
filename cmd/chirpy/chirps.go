package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func writeChirp(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	post := postRequest{}
	err := decoder.Decode(&post)
	if err != nil {
		log.Print(err)
		rw.WriteHeader(http.StatusTeapot)
		io.WriteString(rw, err.Error())
	}
}

func readChirp() {

}
