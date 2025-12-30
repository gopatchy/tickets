package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/lib/pq"
	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/checkout/session"
	"github.com/stripe/stripe-go/v76/webhook"
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
		log.Fatal("[ERROR] failed to create rsvps table: ", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS rsvp_payments (
			stripe_session_id TEXT PRIMARY KEY,
			event_id TEXT NOT NULL,
			google_username TEXT NOT NULL,
			amount DECIMAL(10,2) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		log.Fatal("[ERROR] failed to create rsvp_payments table: ", err)
	}
}

func main() {
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

	http.HandleFunc("/", handleStatic)
	http.HandleFunc("POST /auth/google/callback", handleGoogleCallback)
	http.HandleFunc("GET /api/rsvp/{eventID}", handleRSVPGet)
	http.HandleFunc("POST /api/rsvp/{eventID}", handleRSVPPost)
	http.HandleFunc("GET /api/donate/success/{eventID}", handleDonateSuccess)
	http.HandleFunc("POST /api/stripe/webhook", handleStripeWebhook)

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

	if !strings.Contains(name, ".") {
		t := templates.Lookup(name + ".html")
		if t != nil {
			w.Header().Set("Content-Type", "text/html")
			t.Execute(w, templateData())
			return
		}
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

func authorize(r *http.Request) (string, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
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

func handleRSVPGet(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("eventID")
	email, ok := authorize(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var numPeople int
	var donation float64
	err := db.QueryRow("SELECT num_people, donation FROM rsvps WHERE event_id = $1 AND google_username = $2", eventID, email).Scan(&numPeople, &donation)
	if err == sql.ErrNoRows {
		numPeople = 0
		donation = 0
	} else if err != nil {
		log.Println("[ERROR] failed to query rsvp:", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"numPeople": numPeople, "donation": donation})
}

func handleRSVPPost(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("eventID")
	email, ok := authorize(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		NumPeople     *int  `json:"numPeople"`
		DonationCents int64 `json:"donationCents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.NumPeople != nil {
		_, err := db.Exec(`
			INSERT INTO rsvps (event_id, google_username, num_people) VALUES ($1, $2, $3)
			ON CONFLICT (event_id, google_username) DO UPDATE SET num_people = $3
		`, eventID, email, *req.NumPeople)
		if err != nil {
			log.Println("[ERROR] failed to upsert rsvp:", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
	}

	var numPeople int
	var donation float64
	err := db.QueryRow("SELECT num_people, donation FROM rsvps WHERE event_id = $1 AND google_username = $2", eventID, email).Scan(&numPeople, &donation)
	if err != nil && err != sql.ErrNoRows {
		log.Println("[ERROR] failed to query rsvp:", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{"numPeople": numPeople, "donation": donation}

	if req.DonationCents > 0 {
		stripeURL, err := createCheckoutSession(eventID, email, req.DonationCents)
		if err != nil {
			log.Println("[ERROR] failed to create checkout session:", err)
			http.Error(w, "failed to create checkout session", http.StatusInternalServerError)
			return
		}
		resp["url"] = stripeURL
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func createCheckoutSession(eventID, email string, amountCents int64) (string, error) {
	baseURL := os.Getenv("BASE_URL")
	params := &stripe.CheckoutSessionParams{
		CustomerEmail: stripe.String(email),
		Mode:          stripe.String(string(stripe.CheckoutSessionModePayment)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency: stripe.String("usd"),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name: stripe.String("Donation - Applause for a Cause"),
					},
					UnitAmount: stripe.Int64(amountCents),
				},
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL: stripe.String(fmt.Sprintf("%s/api/donate/success/%s?session_id={CHECKOUT_SESSION_ID}", baseURL, eventID)),
		CancelURL:  stripe.String(fmt.Sprintf("%s/%s", baseURL, eventID)),
		Metadata: map[string]string{
			"event_id": eventID,
			"email":    email,
		},
	}

	s, err := session.New(params)
	if err != nil {
		return "", err
	}
	return s.URL, nil
}

func processPayment(sess *stripe.CheckoutSession) error {
	if sess.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid {
		return nil
	}

	eventID := sess.Metadata["event_id"]
	email := sess.Metadata["email"]
	amount := float64(sess.AmountTotal) / 100

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists bool
	err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM rsvp_payments WHERE stripe_session_id = $1)", sess.ID).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	_, err = tx.Exec(`
		INSERT INTO rsvp_payments (stripe_session_id, event_id, google_username, amount)
		VALUES ($1, $2, $3, $4)
	`, sess.ID, eventID, email, amount)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO rsvps (event_id, google_username, num_people, donation)
		VALUES ($1, $2, 0, (SELECT COALESCE(SUM(amount), 0) FROM rsvp_payments WHERE event_id = $1 AND google_username = $2))
		ON CONFLICT (event_id, google_username) DO UPDATE SET
		donation = (SELECT COALESCE(SUM(amount), 0) FROM rsvp_payments WHERE event_id = $1 AND google_username = $2)
	`, eventID, email)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	log.Printf("recorded donation of $%.2f from %s for %s", amount, email, eventID)
	return nil
}

func handleDonateSuccess(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("eventID")

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Redirect(w, r, fmt.Sprintf("/%s", eventID), http.StatusSeeOther)
		return
	}

	sess, err := session.Get(sessionID, nil)
	if err != nil {
		log.Println("[ERROR] failed to get checkout session:", err)
		http.Redirect(w, r, fmt.Sprintf("/%s", eventID), http.StatusSeeOther)
		return
	}

	if err := processPayment(sess); err != nil {
		log.Println("[ERROR] failed to process payment:", err)
	}

	http.Redirect(w, r, fmt.Sprintf("/%s?donated=1", eventID), http.StatusSeeOther)
}

func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	event, err := webhook.ConstructEventWithOptions(body, r.Header.Get("Stripe-Signature"), os.Getenv("STRIPE_WEBHOOK_SECRET"), webhook.ConstructEventOptions{IgnoreAPIVersionMismatch: true})
	if err != nil {
		log.Println("[ERROR] failed to verify webhook:", err)
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	if event.Type == "checkout.session.completed" {
		var sess stripe.CheckoutSession
		if err := json.Unmarshal(event.Data.Raw, &sess); err != nil {
			log.Println("[ERROR] failed to parse session:", err)
			http.Error(w, "failed to parse session", http.StatusBadRequest)
			return
		}

		if err := processPayment(&sess); err != nil {
			log.Println("[ERROR] failed to process payment:", err)
		}
	}

	w.WriteHeader(http.StatusOK)
}
