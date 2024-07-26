package database

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID            int    `json:"id"`
	Email         string `json:"email"`
	Is_Chirpy_Red bool   `json:"is_chirpy_red"`
	Password      []byte
}

type UserToJson struct {
	ID            int    `json:"id"`
	Email         string `json:"email"`
	Token         string `json:"token"`
	RefreshToken  string `json:"refresh_token"`
	Is_Chirpy_Red bool   `json:"is_chirpy_red"`
}

type userSubmission struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	ExpiryTime int32  `json:"expires_in_seconds"`
	Token      string `json:"token"`
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
	userJSON := UserToJson{ID: user.ID, Email: user.Email, Is_Chirpy_Red: false}
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

	user := User{}

	for _, userEntry := range dbStructure.Users {
		if userEntry.Email == payload.Email {
			user = userEntry
			break
		}
	}

	if user.Email == "" {
		http.Error(rw, "user does not exist", http.StatusNotFound)
	}

	err = bcrypt.CompareHashAndPassword(user.Password, []byte(payload.Password))
	if err != nil {
		http.Error(rw, "incorrect password", http.StatusUnauthorized)
		return
	}

	signedToken, err := GenerateToken(strconv.Itoa(user.ID), payload.ExpiryTime, db.jwtSecret)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	userJSON := UserToJson{
		ID:           user.ID,
		Email:        user.Email,
		Token:        signedToken,
		RefreshToken: refreshToken,
		Is_Chirpy_Red: user.Is_Chirpy_Red,
	}

	tokenCacheEntry := TokenCache{
		UserId:     strconv.Itoa(user.ID),
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

	user, err := db.updateDB(payload, userIdInt)
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

func (db *DB) RefreshToken(rw http.ResponseWriter, req *http.Request) {
	rTokenString := req.Header.Get("Authorization")
	if !strings.HasPrefix(rTokenString, "Bearer ") {
		http.Error(rw, "invalid token", http.StatusUnauthorized)
	}

	rTokenString = strings.TrimPrefix(rTokenString, "Bearer ")
	dbStruct, err := db.loadDB()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	tokenCacheEntry, exists := dbStruct.RefreshTokens[rTokenString]
	if !exists {
		http.Error(rw, "invalid token", http.StatusUnauthorized)
		return
	}

	if time.Now().Unix() > tokenCacheEntry.ExpiryTime {
		http.Error(rw, "token expired", http.StatusUnauthorized)
		return
	}

	signedToken, err := GenerateToken(tokenCacheEntry.UserId, 0, db.jwtSecret)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	tokenJson, err := json.Marshal(struct {
		Token string `json:"token"`
	}{Token: signedToken})
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write(tokenJson)
}

func (db *DB) RevokeToken(rw http.ResponseWriter, req *http.Request) {
	rTokenString := req.Header.Get("Authorization")
	if !strings.HasPrefix(rTokenString, "Bearer ") {
		http.Error(rw, "invalid token", http.StatusUnauthorized)
		return
	}

	rTokenString = strings.TrimPrefix(rTokenString, "Bearer ")
	dbStruct, err := db.loadDB()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	_, exists := dbStruct.RefreshTokens[rTokenString]
	if !exists {
		http.Error(rw, "token does not exist", http.StatusNotFound)
		return
	}

	delete(dbStruct.RefreshTokens, rTokenString)

	err = db.writeDB(dbStruct)
	if err != nil {
		http.Error(rw, "unable to update database", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusNoContent)
}

func GenerateToken(userEmail string, tokenExpiryTime int32, jwtSecret string) (string, error) {
	expiryTime := 24 * time.Hour
	if tokenExpiryTime > 0 {
		expiryTime = time.Duration(tokenExpiryTime) * time.Second
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiryTime)),
		Subject:   userEmail,
	})
	signedToken, err := newToken.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func GenerateRefreshToken() (string, error) {
	refreshTokenSize := 32
	refreshTokenByte := make([]byte, refreshTokenSize)
	_, err := rand.Read(refreshTokenByte)
	if err != nil {
		return "", errors.New("unable to generate refresh token")
	}
	refreshToken := hex.EncodeToString(refreshTokenByte)
	return refreshToken, nil
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
