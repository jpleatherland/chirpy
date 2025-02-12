package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/jpleatherland/chirpy/internal/database"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	jwt := os.Getenv("JWT_SECRET")
	polka := os.Getenv("POLKA_KEY")
	server := http.NewServeMux()
	db, err := database.ConnectToDB("./database.json", jwt)
	apiConf := apiConfig{
		jwtSecret: jwt,
		polkaKey: polka,
		db:        db,
	}
	if err != nil {
		panic(err)
	}
	log.Print("Listening...")
	server.Handle("/app/*", apiConf.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("./cmd/chirpy/")))))

	server.HandleFunc("GET /api/healthz", healthCheck)
	server.HandleFunc("GET /api/metrics", apiConf.metrics)

	server.HandleFunc("GET /api/chirps", db.ReadChirps)
	server.HandleFunc("GET /api/chirps/{id}", db.ReadChirps)
	server.HandleFunc("POST /api/chirps", db.CreateChirp)
	server.HandleFunc("DELETE /api/chirps/{id}", db.DeleteChirps)

	server.HandleFunc("POST /api/users", db.CreateUser)
	server.HandleFunc("PUT /api/users", db.UpdateUser)

	server.HandleFunc("POST /api/login", db.Login)

	server.HandleFunc("POST /api/refresh", db.RefreshToken)

	server.HandleFunc("POST /api/revoke", db.RevokeToken)

	server.HandleFunc("POST /api/polka/webhooks", apiConf.upgradeUser)

	server.HandleFunc("/api/reset", apiConf.resetMetrics)
	server.HandleFunc("GET /admin/metrics", apiConf.adminMetrics)
	http.ListenAndServe(":8080", server)

}

func healthCheck(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	io.WriteString(rw, "OK")
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
}

type apiConfig struct {
	fileserverHits int
	jwtSecret      string
	polkaKey       string
	db             *database.DB
}

func (apiConf *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Increment the counter
		apiConf.fileserverHits += 1

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func (apiConf *apiConfig) metrics(rw http.ResponseWriter, req *http.Request) {
	io.WriteString(rw, fmt.Sprintf("Hits: %v", apiConf.fileserverHits))
}

func (apiConf *apiConfig) resetMetrics(rw http.ResponseWriter, _ *http.Request) {
	apiConf.fileserverHits = 0
	io.WriteString(rw, "Metrics reset")
}

func (apiConf *apiConfig) adminMetrics(rw http.ResponseWriter, _ *http.Request) {
	var tmplFile = "adminMetrics.templ"
	tmpl, err := template.New(tmplFile).ParseFiles(tmplFile)
	if err != nil {
		panic(err)
	}
	rw.Header().Set("Content-Type", "text/html")
	err = tmpl.Execute(rw, apiConf.fileserverHits)
	if err != nil {
		panic(err)
	}
}
