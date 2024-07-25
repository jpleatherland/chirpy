package database

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
)

func (db *DB) CreateChirp(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	payload := chirpSubmission{}
	err := decoder.Decode(&payload)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error reading request body: %v", err), http.StatusUnprocessableEntity)
		return
	}
	if len(payload.Body) > 140 {
		http.Error(rw, "chirp is too large", http.StatusBadRequest)
		return
	}
	cleanedInput := cleanInput(payload.Body)
	token, err := getTokenFromHeader(req.Header, db.jwtSecret)

	if err != nil {
		http.Error(rw, "invalid token", http.StatusUnauthorized)
		return
	}

	userId, err := token.Claims.GetSubject()
	if err != nil {
		http.Error(rw, "unable to read token", http.StatusInternalServerError)
		return
	}

	userIdInt, err := strconv.Atoi(userId)
	if err != nil {
		http.Error(rw, "unable to get user id", http.StatusInternalServerError)
		return
	}
	chirp, err := db.writeChirpToDB(cleanedInput, userIdInt)
	if err != nil {
		http.Error(rw, fmt.Sprintf("failed to write to db: %v", err), http.StatusInternalServerError)
	}
	rw.WriteHeader(http.StatusCreated)
	responseChirp, err := json.Marshal(chirp)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error writing response: %v", err), http.StatusInternalServerError)
		return
	}
	rw.Write(responseChirp)
}

func (db *DB) ReadChirps(rw http.ResponseWriter, req *http.Request) {
	dbRead, err := db.loadDB()
	if err != nil {
		http.Error(rw, fmt.Sprintf("error reading from database: %v", err), http.StatusInternalServerError)
		return
	}
	chirpId := req.PathValue("id")
	if chirpId != "" {
		chirpInt, err := strconv.Atoi(chirpId)
		if err != nil {
			http.Error(rw, fmt.Sprintf("unable to convert requested chirp id to int: %v", err), http.StatusInternalServerError)
			return
		}
		chirp, exists := dbRead.Chirps[chirpInt]
		if !exists {
			http.Error(rw, "requested chirp does not exist", http.StatusNotFound)
			return
		}
		chirpJSON, err := json.Marshal(chirp)
		if err != nil {
			http.Error(rw, fmt.Sprintf("error creating chirp response: %v", err), http.StatusInternalServerError)
			return
		}
		rw.WriteHeader(http.StatusOK)
		rw.Write(chirpJSON)
		return
	}
	chirps := make([]Chirp, 0, len(dbRead.Chirps))
	for _, chirp := range dbRead.Chirps {
		chirps = append(chirps, chirp)
	}
	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].ID < chirps[j].ID
	})

	chirpsJSON, err := json.Marshal(chirps)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error creating chirp response: %v", err), http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write(chirpsJSON)
}

func (db *DB) DeleteChirps(rw http.ResponseWriter, req *http.Request) {
	dbRead, err := db.loadDB()
	if err != nil {
		http.Error(rw, fmt.Sprintf("error reading from database: %v", err), http.StatusInternalServerError)
		return
	}
	token, err := getTokenFromHeader(req.Header, db.jwtSecret)

	if err != nil {
		http.Error(rw, "invalid token", http.StatusUnauthorized)
		return
	}

	userId, err := token.Claims.GetSubject()
	if err != nil {
		http.Error(rw, "unable to read token", http.StatusInternalServerError)
		return
	}

	userIdInt, err := strconv.Atoi(userId)
	if err != nil {
		http.Error(rw, "unable to get user id", http.StatusInternalServerError)
		return
	}

	chirpIdToDelete, err := strconv.Atoi(req.PathValue("id"))
	if err != nil {
		http.Error(rw, "unable to set chirp id", http.StatusBadRequest)
		return
	}

	chirp, exists := dbRead.Chirps[chirpIdToDelete]
	if !exists {
		http.Error(rw, fmt.Sprintf("unable to find chirp with id: %d", chirpIdToDelete), http.StatusNotFound)
		return
	}

	if chirp.Author_ID != userIdInt {
		http.Error(rw, "unable to delete another users chirp", http.StatusForbidden)
		return
	}

	delete(dbRead.Chirps, chirpIdToDelete)
	err = db.writeDB(dbRead)
	if err != nil {
		http.Error(rw, "something went wrong", http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusNoContent)

}

func cleanInput(s string) string {
	disallowed_words := []string{"kerfuffle", "sharbert", "fornax"}
	splitInput := strings.Split(s, " ")
	for string := range splitInput {
		lowerString := strings.ToLower(splitInput[string])
		if slices.Contains(disallowed_words, lowerString) {
			splitInput[string] = "****"
		}
	}
	return strings.Join(splitInput, " ")
}

type Chirp struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
	Author_ID int `json:"author_id"`
}

type chirpSubmission struct {
	Body string `json:"body"`
}
