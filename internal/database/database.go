package database

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type Chirp struct {
	id   int
	body string
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
}

func (db *DB) LoadDB() (DBStructure, error) {
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

func ConnectToDB(dbPath string) (*DB, error) {
	database := DB{path: dbPath}
	err := database.ensureDB()
	if err != nil {
		return nil, err
	}
	return &database, nil
}

func (db *DB) ensureDB() error {
	dbStruct := DBStructure{}
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

func (db *DB) WriteToDB(data DBStructure) error {
  encodedData, err := json.Marshal(data.Chirps)
  if err != nil {
	return err
  }
  err = os.WriteFile(db.path, encodedData, 0666)
  if err != nil {
	return err
  }
  return nil
}

// come into main, create a db which is ensured to exist at the path and have a basic structure
// then load the structure to get the data to a var
// when need to write pass structure to the db method
