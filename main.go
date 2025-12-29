package main

import (
	"context"
	"encoding/base64"
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
	http.HandleFunc("/auth/logout", handleLogout)

	log.Println("server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	name := strings.TrimPrefix(path, "/")

	if name == "index.html" && getProfile(r) != nil {
		http.Redirect(w, r, "/home.html", http.StatusSeeOther)
		return
	}

	if strings.HasSuffix(name, ".html") {
		t := templates.Lookup(name)
		if t == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		t.Execute(w, templateData(r))
		return
	}

	http.ServeFile(w, r, filepath.Join("static", name))
}

func templateData(r *http.Request) map[string]any {
	return map[string]any{
		"env":     envMap(),
		"profile": getProfile(r),
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

func getProfile(r *http.Request) map[string]any {
	cookie, err := r.Cookie("profile")
	if err != nil {
		return nil
	}
	data, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil
	}
	var profile map[string]any
	if json.Unmarshal(data, &profile) != nil {
		return nil
	}
	return profile
}

func setProfile(w http.ResponseWriter, profile map[string]any) {
	data, _ := json.Marshal(profile)
	http.SetCookie(w, &http.Cookie{
		Name:     "profile",
		Value:    base64.RawURLEncoding.EncodeToString(data),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "profile",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

	setProfile(w, profile)
	http.Redirect(w, r, "/home.html", http.StatusSeeOther)
}
