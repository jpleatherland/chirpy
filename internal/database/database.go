package database

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"fmt"
	"os"
	"sync"
	"errors"
)

type DB struct {
	path string
	mux  *sync.RWMutex
	jwtSecret string
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[string]User  `json:"users"`
}

func ConnectToDB(dbPath string, jwt string) (*DB, error) {
	database := DB{
		path: dbPath,
		mux:  new(sync.RWMutex),
		jwtSecret: jwt,
	}
	err := database.ensureDB()
	if err != nil {
		return nil, err
	}
	return &database, nil
}

func (db *DB) loadDB() (DBStructure, error) {
	dbStruct := DBStructure{}
	data, err := os.ReadFile(db.path)
	if err != nil {
		fmt.Println(err)
		return dbStruct, nil
	}
	err = json.Unmarshal(data, &dbStruct)
	if err != nil {
		fmt.Println(err)
		return dbStruct, nil
	}
	return dbStruct, nil
}

func (db *DB) ensureDB() error {
	dbStruct := DBStructure{
		Chirps: make(map[int]Chirp),
		Users:  make(map[string]User),
	}
	existingDB, err := os.Open(db.path)
	if err != nil {
		newDB, err := os.Create(db.path)
		if err != nil {
			return err
		}
		defer newDB.Close()
		initialWrite, err := json.Marshal(dbStruct)
		if err != nil {
			return err
		}
		newDB.Write(initialWrite)
		return nil
	}
	existingDB.Close()
	return nil
}

func (db *DB) writeChirpToDB(data string) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	newID := len(dbStructure.Chirps) + 1
	newChirp := Chirp{
		ID:   newID,
		Body: data,
	}

	dbStructure.Chirps[newID] = newChirp

	err = db.writeDB(dbStructure)
	if err != nil {
		return Chirp{}, err
	}
	return newChirp, err
}

func (db *DB) writeUserToDB(data userSubmission) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	_, exists := dbStructure.Users[data.Email]
	if exists {
		return User{}, errors.New("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.Password), 4)
	if err != nil {
		return User{}, errors.New("unable to securely store password")
	}
	newID := len(dbStructure.Users) + 1
	newUser := User{
		ID:    newID,
		Email: data.Email,
		Password: hashedPassword,
	}

	dbStructure.Users[newUser.Email] = newUser

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}
	return newUser, err
}

func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	file, err := os.Create(db.path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(&dbStructure)
	if err != nil {
		return err
	}

	return nil
}
