package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/lib/pq"
	"google.golang.org/api/idtoken"
)

var (
	templates *template.Template
	db        *sql.DB
)

func init() {
	templates = template.Must(template.New("").ParseGlob("static/*.html"))
	template.Must(templates.ParseGlob("static/*.js"))

	var err error
	db, err = sql.Open("postgres", os.Getenv("PGCONN"))
	if err != nil {
		log.Fatal("[ERROR] failed to open database: ", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("[ERROR] failed to connect to database: ", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS rsvps (
			event_id TEXT NOT NULL,
			google_username TEXT NOT NULL,
			num_people INTEGER NOT NULL DEFAULT 0,
			donation DECIMAL(10,2) NOT NULL DEFAULT 0,
			PRIMARY KEY (event_id, google_username)
		)
	`)
	if err != nil {
		log.Fatal("[ERROR] failed to create table: ", err)
	}
}

func main() {
	http.HandleFunc("/", handleStatic)
	http.HandleFunc("/auth/google/callback", handleGoogleCallback)

	log.Println("server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	name := strings.TrimPrefix(path, "/")

	if strings.HasSuffix(name, ".html") || strings.HasSuffix(name, ".js") {
		t := templates.Lookup(name)
		if t == nil {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(name, ".html") {
			w.Header().Set("Content-Type", "text/html")
		} else {
			w.Header().Set("Content-Type", "application/javascript")
		}
		t.Execute(w, templateData())
		return
	}

	http.ServeFile(w, r, filepath.Join("static", name))
}

func templateData() map[string]any {
	return map[string]any{
		"env": envMap(),
	}
}

func envMap() map[string]string {
	m := map[string]string{}
	for _, e := range os.Environ() {
		if parts := strings.SplitN(e, "=", 2); len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	credential := r.FormValue("credential")
	if credential == "" {
		http.Error(w, "missing credential", http.StatusBadRequest)
		return
	}

	payload, err := idtoken.Validate(context.Background(), credential, os.Getenv("GOOGLE_CLIENT_ID"))
	if err != nil {
		log.Println("[ERROR] failed to validate token:", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	profile := map[string]any{
		"email":   payload.Claims["email"],
		"name":    payload.Claims["name"],
		"picture": payload.Claims["picture"],
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}
