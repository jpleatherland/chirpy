package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

func TestCleanInput(t *testing.T) {
	input := "what a kerFufFle in a forNax sometimes shaRBert"
	want := "what a **** in a **** sometimes ****"
	response := cleanInput(input)
	if response != want {
		t.Errorf("cleanInput(%s) = %s, want %s", input, response, want)
	}
}

func TestCreateChirp(t *testing.T) {
	resources, err := setupTestEnvironment()
	if err != nil {
		t.Fatalf("failed to set up test environment: %v", err)
	}
	defer teardownTestEnvironment(resources)

	// create the payload
	chirp := map[string]string{
		"body": "Hello, Chirpy!",
	}
	payload, err := json.Marshal(chirp)
	if err != nil {
		t.Fatalf("Failed to marshal chirp: %v", err)
	}

	// Create new http request
	req, err := http.NewRequest(http.MethodPost, resources.Server.URL+"/api/chirps", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("failed to create http request %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// post the payload
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	// inspect result
	if status := resp.StatusCode; status != http.StatusCreated {
		t.Errorf("Handler returned the wrong status code: got %v, want %v", status, http.StatusCreated)
	}

	expected := Chirp{
		ID:   1,
		Body: "Hello, Chirpy!",
	}

	var result Chirp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result != expected {
		t.Errorf("Handler returned unexpected body: got %v want %v", result, expected)
	}
}

func TestCreateUser(t *testing.T) {
	resources, err := setupTestEnvironment()
	if err != nil {
		t.Fatalf("failed to set up test environment: %v", err)
	}
	defer teardownTestEnvironment(resources)

	// create the input payload
	user := userSubmission{
		Email:    "test@test.com",
		Password: "12345",
	}

	resp, err := createUser(user, resources)
	if err != nil {
		t.Fatalf("unable to create user %v", err)
	}
	defer resp.Body.Close()

	// inspect result
	if status := resp.StatusCode; status != http.StatusCreated {
		t.Errorf("Handler returned the wrong status code: got %v, want %v", status, http.StatusCreated)
	}

	expectedID := 1
	expectedEmail := "test@test.com"

	var result UserToJson
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Email != expectedEmail {
		t.Errorf("Handler returned unexpected email: got %v want %v", result.Email, expectedEmail)
	}
	if result.ID != expectedID {
		t.Errorf("Handler returned unexpected email: got %v want %v", result.ID, expectedID)
	}
}

func TestCreateExistingUser(t *testing.T) {
	resources, err := setupTestEnvironment()
	if err != nil {
		t.Fatalf("failed to set up test environment: %v", err)
	}
	defer teardownTestEnvironment(resources)

	// create the input payload
	user := userSubmission{
		Email:    "test@test.com",
		Password: "12345",
	}

	resp, err := createUser(user, resources)
	if err != nil {
		t.Fatalf("unable to create user %v", err)
	}
	defer resp.Body.Close()

	resp2, err := createUser(user, resources)

	// inspect result
	if err != nil {
		fmt.Println(err)
	}
	defer resp2.Body.Close()

	body, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("unable to read response: %v", err)
	}

	if !strings.Contains(string(body), "user already exists") {
		t.Errorf("Handler returned unexpected body: got %v want %v", string(body), "user already exists")
	}

	if status := resp2.StatusCode; status != http.StatusConflict {
		t.Errorf("Handler returned the wrong status code: got %v, want %v", status, http.StatusCreated)
	}
}

func TestLoginUser(t *testing.T) {
	resources, err := setupTestEnvironment()
	if err != nil {
		t.Fatalf("failed to set up test environment: %v", err)
	}
	defer teardownTestEnvironment(resources)

	// create the input payload
	user := userSubmission{
		Email:    "test@test.com",
		Password: "12345",
	}

	resp, err := createUser(user, resources)
	if err != nil {
		t.Fatalf("unable to create user %v", err)
	}
	resp.Body.Close()

	resp2, err := loginUser(user, resources)
	if err != nil {
		t.Fatalf("attempt to login failed: %v", err)
	}

	expectedID := 1
	expectedEmail := "test@test.com"

	var result UserToJson
	if err := json.NewDecoder(resp2.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Email != expectedEmail {
		t.Errorf("Handler returned unexpected email: got %v want %v", result.Email, expectedEmail)
	}
	if result.ID != expectedID {
		t.Errorf("Handler returned unexpected email: got %v want %v", result.ID, expectedID)
	}
	if result.Token == "" {
		t.Errorf("Handler returned unexpected token: got %v expected token", result.ID)
	}
}

func TestUpdateUser(t *testing.T) {
	resources, err := setupTestEnvironment()
	if err != nil {
		t.Fatalf("failed to set up test environment: %v", err)
	}
	defer teardownTestEnvironment(resources)

	// create the input payload
	user := userSubmission{
		Email:    "test@test.com",
		Password: "12345",
	}

	resp, err := createUser(user, resources)
	if err != nil {
		t.Fatalf("unable to create user %v", err)
	}
	resp.Body.Close()

	resp2, err := loginUser(user, resources)
	if err != nil {
		t.Fatalf("attempt to login failed: %v", err)
	}

	var result UserToJson
	if err := json.NewDecoder(resp2.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	user2 := userSubmission{
		Email:    "test2@test.com",
		Password: "12345",
		Token:    result.Token,
	}

	resp3, err := updateUser(user2, resources)
	if err != nil {
		t.Fatalf("attempt to update failed: %v", err)
	}

	expectedEmail := user2.Email
	expectedID := 1

	var result3 UserToJson

	if err := json.NewDecoder(resp3.Body).Decode(&result3); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result3.Email != expectedEmail {
		t.Errorf("Handler returned unexpected email: got %v want %v", result.Email, expectedEmail)
	}
	if result.ID != expectedID {
		t.Errorf("Handler returned unexpected email: got %v want %v", result.ID, expectedID)
	}

}

func TestUpdateMissingUser(t *testing.T) {
	resources, err := setupTestEnvironment()
	if err != nil {
		t.Fatalf("failed to set up test environment: %v", err)
	}
	defer teardownTestEnvironment(resources)

	user2 := userSubmission{
		Email:    "test2@test.com",
		Password: "12345",
		Token:    "badtoken",
	}

	resp3, err := updateUser(user2, resources)
	if err != nil {
		t.Fatalf("attempt to update failed: %v", err)
	}

	expectedStatus := http.StatusUnauthorized

	if resp3.StatusCode != expectedStatus {
		t.Errorf("Handler returned unexpected status: got %v want %v", resp3.StatusCode, expectedStatus)
	}
}

type TestResources struct {
	TmpFile *os.File
	Server  *httptest.Server
	JWT     string
	DB      *DB
}

func setupTestEnvironment() (*TestResources, error) {
	// create the file for the database
	tmpFile, tmpFilePath, err := setupFileForDB()
	if err != nil {
		return nil, err
	}

	// load env vars for the jwt
	err = godotenv.Load()
	if err != nil {
		os.Remove(tmpFile.Name())
		return nil, err
	}

	// setup the database and server
	db, err := ConnectToDB(tmpFilePath, os.Getenv("JWT_SECRET_TESTING"))
	if err != nil {
		os.Remove(tmpFile.Name())
		return nil, err
	}

	ts := setupTestServer(db)

	resources := &TestResources{
		TmpFile: tmpFile,
		Server:  ts,
		JWT:     os.Getenv("JWT_SECRET_TESTING"),
		DB:      db,
	}

	return resources, nil
}

func teardownTestEnvironment(resources *TestResources) {
	// Close the test server
	if resources.Server != nil {
		resources.Server.Close()
	}

	// Remove the temporary db file
	if resources.TmpFile != nil {
		os.Remove(resources.TmpFile.Name())
	}
}

func setupFileForDB() (*os.File, string, error) {
	tmpFile, err := os.CreateTemp("", "testdb")
	if err != nil {
		return nil, "", err
	}
	return tmpFile, tmpFile.Name(), nil
}

func setupTestServer(db *DB) *httptest.Server {
	server := http.NewServeMux()

	server.HandleFunc("GET /api/chirps", db.ReadChirps)
	server.HandleFunc("GET /api/chirps/{id}", db.ReadChirps)
	server.HandleFunc("POST /api/chirps", db.CreateChirp)

	server.HandleFunc("POST /api/users", db.CreateUser)
	server.HandleFunc("PUT /api/users", db.UpdateUser)

	server.HandleFunc("POST /api/login", db.Login)

	return httptest.NewServer(server)
}

func createUser(user userSubmission, resources *TestResources) (*http.Response, error) {
	payload, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	// create the http request
	req, err := http.NewRequest(http.MethodPost, resources.Server.URL+"/api/users", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// post the payload
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

func loginUser(user userSubmission, resources *TestResources) (*http.Response, error) {
	payload, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	// create the http request
	req, err := http.NewRequest(http.MethodPost, resources.Server.URL+"/api/login", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// post the payload
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

func updateUser(user userSubmission, resources *TestResources) (*http.Response, error) {
	payload, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	// create the http request
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPut, resources.Server.URL+"/api/users", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+user.Token)

	// post the payload
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}
