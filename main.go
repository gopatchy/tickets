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
	"strconv"
	"strings"

	_ "github.com/lib/pq"
	"github.com/resend/resend-go/v2"
	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/checkout/session"
	"github.com/stripe/stripe-go/v76/webhook"
	"google.golang.org/api/idtoken"
)

type eventInfo struct {
	Name     string
	Date     string
	Location string
	Address  string
}

var events = map[string]eventInfo{
	"afac26": {
		Name:     "Applause for a Cause",
		Date:     "Saturday, February 7, 2026 at 6:30 PM",
		Location: "Helios Gym",
		Address:  "597 Central Avenue, Sunnyvale, CA 94086",
	},
}

type SiteMode string

const (
	SiteModeRSVP SiteMode = "rsvp"
	SiteModeGive SiteMode = "give"
)

var (
	modeTemplates = map[SiteMode]*template.Template{}
	domainModes   = map[string]SiteMode{}
	db            *sql.DB
)

func init() {
	for _, d := range strings.Split(os.Getenv("GIVE_DOMAINS"), ",") {
		d = strings.TrimSpace(d)
		if d != "" {
			domainModes[d] = SiteModeGive
		}
	}

	for _, mode := range []SiteMode{SiteModeRSVP, SiteModeGive} {
		dir := "static/" + string(mode) + "/"
		modeTemplates[mode] = template.Must(template.New("").ParseGlob("static/shared/*.html"))
		template.Must(modeTemplates[mode].ParseGlob(dir + "*.html"))
		template.Must(modeTemplates[mode].ParseGlob(dir + "*.js"))
	}

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
	http.HandleFunc("GET /api/report", handleReport)

	log.Println("server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")

	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	name := strings.TrimPrefix(path, "/")
	mode := getSiteMode(r)
	tmpl := modeTemplates[mode]
	staticDir := filepath.Join("static", string(mode))

	if strings.HasSuffix(name, ".html") || strings.HasSuffix(name, ".js") {
		t := tmpl.Lookup(name)
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
		t := tmpl.Lookup(name + ".html")
		if t != nil {
			w.Header().Set("Content-Type", "text/html")
			t.Execute(w, templateData())
			return
		}
	}

	http.ServeFile(w, r, filepath.Join(staticDir, name))
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

func getSiteMode(r *http.Request) SiteMode {
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if mode, ok := domainModes[host]; ok {
		return mode
	}
	return SiteModeRSVP
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

func getRSVP(eventID, email string) (int, float64, error) {
	var numPeople int
	var donation float64
	err := db.QueryRow("SELECT num_people, donation FROM rsvps WHERE event_id = $1 AND google_username = $2", eventID, email).Scan(&numPeople, &donation)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return numPeople, donation, err
}

func handleRSVPGet(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("eventID")
	email, ok := authorize(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	numPeople, donation, err := getRSVP(eventID, email)
	if err != nil {
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
		if *req.NumPeople > 0 {
			go sendRSVPConfirmation(eventID, email, *req.NumPeople)
		}
	}

	numPeople, donation, err := getRSVP(eventID, email)
	if err != nil {
		log.Println("[ERROR] failed to query rsvp:", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{"numPeople": numPeople, "donation": donation}

	if req.DonationCents > 0 {
		stripeURL, err := createCheckoutSession(eventID, email, req.DonationCents, numPeople)
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

func createCheckoutSession(eventID, email string, amountCents int64, numPeople int) (string, error) {
	baseURL := os.Getenv("BASE_URL")
	params := &stripe.CheckoutSessionParams{
		CustomerEmail: stripe.String(email),
		Mode:          stripe.String(string(stripe.CheckoutSessionModePayment)),
		PaymentIntentData: &stripe.CheckoutSessionPaymentIntentDataParams{
			ReceiptEmail: stripe.String(email),
		},
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
			"event_id":   eventID,
			"email":      email,
			"num_people": fmt.Sprintf("%d", numPeople),
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

func sendRSVPConfirmation(eventID, email string, numPeople int) {
	event, ok := events[eventID]
	if !ok {
		log.Printf("[ERROR] unknown event %s for email confirmation", eventID)
		return
	}

	resendKey := os.Getenv("RESEND_KEY")
	if resendKey == "" {
		log.Println("[ERROR] RESEND_KEY not set, skipping confirmation email")
		return
	}

	client := resend.NewClient(resendKey)

	word := "person"
	if numPeople != 1 {
		word = "people"
	}

	html := fmt.Sprintf(`
<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>Your RSVP is Confirmed!</h2>
  <p>You're all set for <strong>%s</strong>.</p>
  <table style="margin: 20px 0; border-collapse: collapse;">
    <tr><td style="padding: 8px 0; color: #666;">Party Size</td><td style="padding: 8px 0 8px 20px;"><strong>%d %s</strong></td></tr>
    <tr><td style="padding: 8px 0; color: #666;">Date</td><td style="padding: 8px 0 8px 20px;"><strong>%s</strong></td></tr>
    <tr><td style="padding: 8px 0; color: #666;">Location</td><td style="padding: 8px 0 8px 20px;"><strong>%s</strong><br>%s</td></tr>
  </table>
  <p>See you there!</p>
  <p style="color: #666; font-size: 14px; margin-top: 30px;">— HCA Events</p>
</div>
`, event.Name, numPeople, word, event.Date, event.Location, event.Address)

	params := &resend.SendEmailRequest{
		From:    "HCA Events <events@hca.run>",
		To:      []string{email},
		Subject: fmt.Sprintf("Thank you for RSVPing to %s", event.Name),
		Html:    html,
	}

	_, err := client.Emails.Send(params)
	if err != nil {
		log.Printf("[ERROR] failed to send confirmation email to %s: %v", email, err)
		return
	}
	log.Printf("sent confirmation email to %s for %s", email, eventID)
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

	amount := float64(sess.AmountTotal) / 100
	redirectURL := fmt.Sprintf("/%s?donated=%.2f", eventID, amount)
	if numPeopleStr := sess.Metadata["num_people"]; numPeopleStr != "" {
		if numPeople, err := strconv.Atoi(numPeopleStr); err == nil && numPeople > 0 {
			redirectURL += fmt.Sprintf("&num_people=%d", numPeople)
		}
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
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

func handleReport(w http.ResponseWriter, r *http.Request) {
	type rsvpRow struct {
		EventID   string  `json:"eventId"`
		Email     string  `json:"email"`
		NumPeople int     `json:"numPeople"`
		Donation  float64 `json:"donation"`
	}

	type eventSummary struct {
		EventID      string    `json:"eventId"`
		Name         string    `json:"name"`
		TotalPeople  int       `json:"totalPeople"`
		TotalDonated float64   `json:"totalDonated"`
		RSVPs        []rsvpRow `json:"rsvps"`
	}

	rows, err := db.Query("SELECT event_id, google_username, num_people, donation FROM rsvps WHERE num_people > 0 ORDER BY event_id, google_username")
	if err != nil {
		log.Println("[ERROR] failed to query rsvps for report:", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	eventMap := map[string]*eventSummary{}
	for rows.Next() {
		var r rsvpRow
		if err := rows.Scan(&r.EventID, &r.Email, &r.NumPeople, &r.Donation); err != nil {
			log.Println("[ERROR] failed to scan rsvp row:", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		summary, ok := eventMap[r.EventID]
		if !ok {
			name := r.EventID
			if e, ok := events[r.EventID]; ok {
				name = e.Name
			}
			summary = &eventSummary{EventID: r.EventID, Name: name, RSVPs: []rsvpRow{}}
			eventMap[r.EventID] = summary
		}
		summary.TotalPeople += r.NumPeople
		summary.TotalDonated += r.Donation
		summary.RSVPs = append(summary.RSVPs, r)
	}

	result := []eventSummary{}
	for _, s := range eventMap {
		result = append(result, *s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
