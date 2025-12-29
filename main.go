package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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
	http.HandleFunc("/api/rsvp/", handleRSVP)

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

	email := payload.Claims["email"].(string)

	profile := map[string]any{
		"email":   email,
		"name":    payload.Claims["name"],
		"picture": payload.Claims["picture"],
		"token":   signEmail(email),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

func signEmail(email string) string {
	h := hmac.New(sha256.New, []byte(os.Getenv("TOKEN_SECRET")))
	h.Write([]byte(email))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(email)) + "." + sig
}

func verifyToken(token string) (string, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	emailBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	email := string(emailBytes)
	if signEmail(email) != token {
		return "", false
	}
	return email, true
}

func handleRSVP(w http.ResponseWriter, r *http.Request) {
	eventID := strings.TrimPrefix(r.URL.Path, "/api/rsvp/")
	if eventID == "" {
		http.Error(w, "missing event id", http.StatusBadRequest)
		return
	}

	token := r.Header.Get("Authorization")
	email, ok := verifyToken(strings.TrimPrefix(token, "Bearer "))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		var numPeople int
		var totalPeople int
		err := db.QueryRow("SELECT num_people FROM rsvps WHERE event_id = $1 AND google_username = $2", eventID, email).Scan(&numPeople)
		if err == sql.ErrNoRows {
			numPeople = 0
		} else if err != nil {
			log.Println("[ERROR] failed to query rsvp:", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		err = db.QueryRow("SELECT COALESCE(SUM(num_people), 0) FROM rsvps WHERE event_id = $1", eventID).Scan(&totalPeople)
		if err != nil {
			log.Println("[ERROR] failed to query total:", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"numPeople": numPeople, "totalPeople": totalPeople})

	case http.MethodPost:
		var req struct {
			NumPeople int `json:"numPeople"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`
			INSERT INTO rsvps (event_id, google_username, num_people) VALUES ($1, $2, $3)
			ON CONFLICT (event_id, google_username) DO UPDATE SET num_people = $3
		`, eventID, email, req.NumPeople)
		if err != nil {
			log.Println("[ERROR] failed to upsert rsvp:", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		var totalPeople int
		db.QueryRow("SELECT COALESCE(SUM(num_people), 0) FROM rsvps WHERE event_id = $1", eventID).Scan(&totalPeople)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"numPeople": req.NumPeople, "totalPeople": totalPeople})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
