package database

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	ID           int    `json:"id"`
	Email        string `json:"email"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type userSubmission struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
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
		if err.Error() == "user already exists" {
			http.Error(rw, "user already exists", http.StatusConflict)
		} else {
			http.Error(rw, fmt.Sprintf("failed to write to db: %v", err), http.StatusInternalServerError)
		}
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

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiryTime)),
		Subject:   user.Email,
	})
	signedToken, err := newToken.SignedString([]byte(db.jwtSecret))
	if err != nil {
		http.Error(rw, fmt.Sprintf("unable to sign token: %v", err), http.StatusUnauthorized)
	}

	refreshTokenSize := 32
	refreshTokenByte := make([]byte, refreshTokenSize)
	_, err = rand.Read(refreshTokenByte)
	if err != nil {
		http.Error(rw, fmt.Sprintf("unable to generate refresh token: %v", err), http.StatusUnauthorized)
	}
	refreshToken := hex.EncodeToString(refreshTokenByte)

	userJSON := UserToJson{
		ID:           user.ID,
		Email:        user.Email,
		Token:        signedToken,
		RefreshToken: refreshToken,
	}

	tokenCacheEntry := TokenCache{
		UserId:     user.Email,
		ExpiryTime: time.Now().AddDate(0, 0, 60).Unix(),
	}

	dbStructure.RefreshTokens[refreshToken] = tokenCacheEntry

	err = db.writeDB(dbStructure)
	if err != nil {
		http.Error(rw, fmt.Sprintf("unable to update user refresh token: %v", err), http.StatusInternalServerError)
	}

	responseUser, err := json.Marshal(userJSON)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error writing response: %v", err), http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write(responseUser)
}

func (db *DB) UpdateUser(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	payload := userSubmission{}
	err := decoder.Decode(&payload)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error reading request body: %v", err), http.StatusUnprocessableEntity)
		return
	}

	token, err := getTokenFromHeader(req.Header, db.jwtSecret)
	if err != nil {
		http.Error(rw, "invalid token", http.StatusUnauthorized)
		return
	}

	userToUpdate, err := token.Claims.GetSubject()
	if err != nil {
		http.Error(rw, "Unable to read token", http.StatusUnauthorized)
		return
	}

	user, err := db.updateDB(payload, userToUpdate)
	if err != nil {
		http.Error(rw, fmt.Sprintf("failed to write to db: %v", err), http.StatusInternalServerError)
		return
	}

	userJSON := UserToJson{ID: user.ID, Email: user.Email}
	responseUser, err := json.Marshal(userJSON)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error writing response: %v", err), http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write(responseUser)
}

func getTokenFromHeader(header http.Header, secret string) (*jwt.Token, error) {

	tokenString := header.Get("Authorization")

	if !strings.HasPrefix(tokenString, "Bearer ") {
		return &jwt.Token{}, errors.New("invalid token")
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
	)

	if err != nil || !token.Valid {
		return &jwt.Token{}, errors.New("invalid token")
	}
	return token, nil
}
