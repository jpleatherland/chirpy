package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"slices"
)

func validateChirp(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	post := postRequest{}
	err := decoder.Decode(&post)
	if err != nil {
		fmt.Printf("Error decoding post body: %s", err)
		rw.WriteHeader(500)
		errorResponse := postResponse{Response: make(map[string]any)}
		errorResponse.Response["error"] = "Something went wrong"
		resp, err := json.Marshal(errorResponse.Response)
		if err != nil {
			panic(err)
		}
		rw.Write(resp)
		return
	}
	if len(post.Body) > 140 {
		rw.Header().Set("Content-type", "application/json")
		rw.WriteHeader(400)
		errorResponse := postResponse{Response: make(map[string]any)}
		errorResponse.Response["body"] = "Chirp is too large"
		resp, err := json.Marshal(errorResponse.Response)
		if err != nil {
		  panic (err)
		}
		rw.Write(resp)
		return
	}
	cleanedInput := cleanInput(post.Body)
	rw.Header().Set("Content-type", "application/json")
	rw.WriteHeader(200)
	validResponse := postResponse{Response: make(map[string]any)}
	validResponse.Response["cleaned_body"] = cleanedInput
	resp, err := json.Marshal(validResponse.Response)
	if err != nil {
		panic (err)
	}
	rw.Write(resp)
}

type postRequest struct {
	Body string `json:"body"` 
}

type postResponse struct {
	Response map[string]any
}

func cleanInput(s string) string {
	fmt.Println(s)
	disallowed_words := []string{"kerfuffle", "sharbert", "fornax"}
	splitInput := strings.Split(s, " ")
	for string := range splitInput{
		lowerString := strings.ToLower(splitInput[string])
		if slices.Contains(disallowed_words, lowerString) {
			splitInput[string] = "****"
		}
	}
	fmt.Println(strings.Join(splitInput, " "))
	return strings.Join(splitInput, " ")
}
