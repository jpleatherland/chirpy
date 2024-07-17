package database

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password []byte
}

type UserToJson struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"`
}

type userSubmission struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	ExpireTime int    `json:"expires_in_seconds"`
}

func (db *DB) CreateUser(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	payload := userSubmission{}
	err := decoder.Decode(&payload)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error reading request body: %v", err), http.StatusUnprocessableEntity)
		return
	}
	user, err := db.writeUserToDB(payload)
	if err != nil {
		http.Error(rw, fmt.Sprintf("failed to write to db: %v", err), http.StatusInternalServerError)
	}
	userJSON := UserToJson{ID: user.ID, Email: user.Email}
	responseUser, err := json.Marshal(userJSON)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error writing response: %v", err), http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusCreated)
	rw.Write(responseUser)
}

func (db *DB) Login(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	payload := userSubmission{}
	err := decoder.Decode(&payload)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error reading request body: %v", err), http.StatusUnprocessableEntity)
		return
	}
	dbStructure, err := db.loadDB()
	if err != nil {
		http.Error(rw, fmt.Sprintf("failed to read from db: %v", err), http.StatusInternalServerError)
		return
	}
	user, exists := dbStructure.Users[payload.Email]
	if !exists {
		http.Error(rw, "user does not exist", http.StatusNotFound)
		return
	}
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(payload.Password))
	if err != nil {
		http.Error(rw, "incorrect password", http.StatusUnauthorized)
		return
	}
	expiryTime := 24 * time.Hour 
	if payload.ExpireTime != 0 {
		expiryTime = time.Duration(payload.ExpireTime) * time.Hour
	} 
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: "chirpy",
		IssuedAt: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiryTime)),
		Subject: strconv.Itoa(user.ID),
	})
	signedToken, err := newToken.SignedString([]byte(db.jwtSecret))
	if err != nil {
		http.Error(rw, fmt.Sprintf("unable to sign token: %v", err), http.StatusUnauthorized)
	}
	userJSON := UserToJson{ID: user.ID, Email: user.Email, Token: signedToken}
	responseUser, err := json.Marshal(userJSON)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error writing response: %v", err), http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write(responseUser)
}
