package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type polkaSubmission struct {
	Event string         `json:"event"`
	Data  map[string]int `json:"data"`
}

func (cfg *apiConfig) upgradeUser(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	payload := polkaSubmission{}
	err := decoder.Decode(&payload)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error reading request body: %v", err), http.StatusUnprocessableEntity)
		return
	}
	if payload.Event != "user.upgraded" {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	userId, exists := payload.Data["user_id"]
	if !exists {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = cfg.db.UpgradeUser(userId)
	if err != nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}
