package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/api/idtoken"
)

var templates *template.Template

func init() {
	templates = template.Must(template.ParseGlob("static/*.html"))
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

	if strings.HasSuffix(name, ".html") {
		t := templates.Lookup(name)
		if t == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		t.Execute(w, envMap())
		return
	}

	http.ServeFile(w, r, filepath.Join("static", name))
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

	response := map[string]any{
		"email":   payload.Claims["email"],
		"name":    payload.Claims["name"],
		"picture": payload.Claims["picture"],
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
