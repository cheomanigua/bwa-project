package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/stripe/stripe-go/v84"
	portalsession "github.com/stripe/stripe-go/v84/billingportal/session"
	checkoutsession "github.com/stripe/stripe-go/v84/checkout/session"
	"github.com/stripe/stripe-go/v84/price"
	"github.com/stripe/stripe-go/v84/subscription"
	"github.com/stripe/stripe-go/v84/webhook"
	"google.golang.org/api/option"
)

// --- Domain Models ---

type AuthUser struct {
	UID          string
	Email        string
	Plan         string
	Name         string
	RegisteredAt time.Time
	NextRenewal  time.Time
	StripeID     string
}

type App struct {
	auth         *auth.Client
	firestore    *firestore.Client
	storage      *storage.Client
	projectID    string
	bucket       string
	domain       string
	emulatorHost string
}

func main() {
	ctx := context.Background()

	// 1. Config Loading
	projectID := getEnv("PROJECT_ID", "my-test-project")
	bucketName := getEnv("GCS_BUCKET", "content")
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

	// 2. Client Initialization
	app, err := initializeApp(ctx, projectID, bucketName)
	if err != nil {
		log.Fatalf("Failed to initialize app: %v", err)
	}
	defer app.firestore.Close()
	defer app.storage.Close()

	// 3. Routing
	mux := http.NewServeMux()

	// Auth & Sessions
	mux.HandleFunc("/api/sessionLogin", app.handleSessionLogin)
	mux.HandleFunc("/api/sessionLogout", app.handleSessionLogout)
	mux.HandleFunc("/api/session", app.handleSession)
	mux.HandleFunc("/api/reset-password", app.handleResetPassword)
	mux.HandleFunc("/api/change-password", app.handleChangePassword)
	mux.HandleFunc("/api/delete-account", app.handleDeleteAccount)

	// Stripe Integration
	mux.HandleFunc("/api/stripe-webhook", app.handleStripeWebhook)
	mux.HandleFunc("/api/create-checkout-session", app.handleCreateCheckoutSession)
	mux.HandleFunc("/api/create-customer-portal-session", app.handleCreateCustomerPortalSession)
	mux.HandleFunc("/dashboard/", app.handleCheckoutSuccess)

	// Content & Support
	mux.HandleFunc("/api/contact-support", app.handleContactSupport)
	mux.HandleFunc("/posts/", app.handleContentGuard)

	port := getEnv("PORT", "8081")
	log.Printf("Server starting on port %s for project %s", port, projectID)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// --- Initialization Logic ---

func initializeApp(ctx context.Context, projectID, bucket string) (*App, error) {
	log.Printf("Initializing app for project: %s", projectID)

	fbApp, err := firebase.NewApp(ctx, &firebase.Config{ProjectID: projectID})
	if err != nil {
		return nil, fmt.Errorf("error initializing firebase app: %w", err)
	}

	authClient, err := fbApp.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting firebase auth client: %w", err)
	}

	var firestoreClient *firestore.Client
	if host := os.Getenv("FIRESTORE_EMULATOR_HOST"); host != "" {
		log.Printf("Using Firestore Emulator at: %s", host)
		firestoreClient, err = firestore.NewClient(ctx, projectID, option.WithoutAuthentication())
	} else {
		firestoreClient, err = fbApp.Firestore(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("error getting firestore client: %w", err)
	}

	var storageClient *storage.Client
	emulatorHost := os.Getenv("STORAGE_EMULATOR_HOST")
	if emulatorHost == "" {
		emulatorHost = os.Getenv("GCS_EMULATOR_HOST")
	}

	if emulatorHost != "" {
		endpoint := fmt.Sprintf("%s/storage/v1/", strings.TrimSuffix(emulatorHost, "/"))
		if !strings.HasPrefix(endpoint, "http") {
			endpoint = "http://" + endpoint
		}
		log.Printf("Configuring GCS Client for emulator at: %s", endpoint)

		currentProject := os.Getenv("GOOGLE_CLOUD_PROJECT")
		os.Unsetenv("GOOGLE_CLOUD_PROJECT")
		storageClient, err = storage.NewClient(ctx, option.WithEndpoint(endpoint), option.WithoutAuthentication())
		if currentProject != "" {
			os.Setenv("GOOGLE_CLOUD_PROJECT", currentProject)
		}
	} else {
		log.Println("Using production GCS client")
		storageClient, err = storage.NewClient(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("error getting storage client: %w", err)
	}

	return &App{
		auth:         authClient,
		firestore:    firestoreClient,
		storage:      storageClient,
		projectID:    projectID,
		bucket:       bucket,
		domain:       getEnv("DOMAIN", "http://localhost:5000"),
		emulatorHost: emulatorHost,
	}, nil
}

// --- Stripe Webhook ---

func (a *App) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading webhook body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sig := r.Header.Get("Stripe-Signature")
	event, err := webhook.ConstructEventWithOptions(payload, sig, os.Getenv("STRIPE_WEBHOOK_SECRET"), webhook.ConstructEventOptions{IgnoreAPIVersionMismatch: true})
	if err != nil {
		log.Printf("Error verifying webhook signature: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Prints all Webhook events like crazy
	//log.Printf("Webhook received: %s [ID: %s]", event.Type, event.ID)

	ctx := r.Context()
	if event.Type == "checkout.session.completed" || event.Type == "customer.subscription.updated" {
		var subID, customerID, customerEmail, customerName string

		if event.Type == "checkout.session.completed" {
			var session stripe.CheckoutSession
			json.Unmarshal(event.Data.Raw, &session)
			subID = session.Subscription.ID
			customerID = session.Customer.ID
			customerEmail = session.CustomerDetails.Email
			customerName = session.CustomerDetails.Name
			log.Printf("Processing Checkout for: %s", customerEmail)
		} else {
			var sub stripe.Subscription
			json.Unmarshal(event.Data.Raw, &sub)
			subID = sub.ID
			customerID = sub.Customer.ID
			log.Printf("Processing Subscription Update for Customer: %s", customerID)
		}

		params := &stripe.SubscriptionParams{}
		params.AddExpand("items.data.price")
		fullSub, err := subscription.Get(subID, params)
		if err != nil {
			log.Printf("Error retrieving subscription details from Stripe: %v", err)
			w.WriteHeader(http.StatusOK)
			return
		}

		regPlan := "basic"
		if len(fullSub.Items.Data) > 0 {
			lookupKey := fullSub.Items.Data[0].Price.LookupKey
			log.Printf("Stripe Price Lookup Key: %s", lookupKey)
			switch lookupKey {
			case "pro_plan":
				regPlan = "pro"
			case "elite_plan":
				regPlan = "elite"
			}
		}

		var uid string
		if event.Type == "checkout.session.completed" {
			userRecord, err := a.auth.GetUserByEmail(ctx, customerEmail)
			if err != nil {
				log.Printf("Creating new account for: %s", customerEmail)
				temp, _ := generateTempPassword()
				newUser, err := a.auth.CreateUser(ctx, (&auth.UserToCreate{}).Email(customerEmail).Password(temp).DisplayName(customerName).EmailVerified(true))
				if err != nil {
					log.Printf("Error creating firebase user: %v", err)
				} else {
					uid = newUser.UID
					link, _ := a.auth.PasswordResetLink(ctx, customerEmail)
					log.Printf("[EMAIL SIMULATION] To: %s | Subject: Welcome! Set your password | Link: %s", customerEmail, link)
				}
			} else {
				uid = userRecord.UID
			}
		} else {
			// Portal fix: Find by stripeID
			iter := a.firestore.Collection("users").Where("stripeID", "==", customerID).Limit(1).Documents(ctx)
			doc, err := iter.Next()
			if err == nil {
				uid = doc.Ref.ID
				log.Printf("Found user %s via StripeID: %s", uid, customerID)
			} else {
				log.Printf("Could not find user with stripeID: %s", customerID)
			}
		}

		if uid != "" {
			update := map[string]any{
				"plan":     regPlan,
				"stripeID": customerID,
			}
			if customerName != "" {
				update["name"] = customerName
			}
			if event.Type == "checkout.session.completed" {
				update["registeredAt"] = time.Now()
			}

			_, err := a.firestore.Collection("users").Doc(uid).Set(ctx, update, firestore.MergeAll)
			if err != nil {
				log.Printf("Error updating firestore for user %s: %v", uid, err)
			} else {
				log.Printf("Firestore updated: User %s is now on %s plan", uid, regPlan)
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}

// --- Content Guard ---

func (a *App) handleContentGuard(w http.ResponseWriter, r *http.Request) {
	log.Printf("--- Access Request: %s ---", r.URL.Path)
	ctx := r.Context()

	// Authentication Start: The handler resolves the identity of the requester.
	user := a.getAuthenticatedUserFromCookie(r)
	userPlan := "visitor"
	if user != nil {
		userPlan = user.Plan
		log.Printf("Authenticated User: %s [Plan: %s]", user.Email, userPlan)
	}

	objectPath := strings.TrimPrefix(r.URL.Path, "/")
	if !strings.Contains(path.Base(objectPath), ".") {
		objectPath = path.Join(objectPath, "index.html")
	}

	// Metadata Fetch: The handler requests attributes from the GCS Emulator (:9000).
	attrs, err := a.storage.Bucket(a.bucket).Object(objectPath).Attrs(ctx)
	if err != nil {
		log.Printf("GCS Metadata error for %s: %v", objectPath, err)
		http.Error(w, "Content not found", http.StatusNotFound)
		return
	}

	// Requirements Retrieval: The GCS Emulator returns the object’s custom metadata.
	meta := attrs.Metadata["required-plans"]
	var required []string
	if meta != "" {
		for p := range strings.SplitSeq(meta, ",") {
			required = append(required, strings.TrimSpace(p))
		}
	}

	// Authorization Logic: The handler compares the user’s plan level against the requirements.
	if !isAuthorized(userPlan, required) {
		log.Printf("ACCESS DENIED: User plan '%s' does not meet requirements: %v", userPlan, required)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "<html><body><h1>Access Denied</h1><p>This content requires a %v plan. Your current plan is: %s</p></body></html>", required, userPlan)
		return
	}

	log.Printf("ACCESS GRANTED: Serving %s", objectPath)

	encoded := url.PathEscape(objectPath)
	host := strings.TrimPrefix(strings.TrimPrefix(a.emulatorHost, "http://"), "https://")
	emulatorURL := fmt.Sprintf("http://%s/storage/v1/b/%s/o/%s?alt=media", host, a.bucket, encoded)

	// Media Request: The backend initiates an http.Get request with alt=media
	resp, err := http.Get(emulatorURL)
	if err != nil {
		log.Printf("Error fetching media from emulator: %v", err)
		http.Error(w, "Storage unreachable", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Emulator returned non-200 for media: %d", resp.StatusCode)
		http.Error(w, "Content not found", http.StatusNotFound)
		return
	}

	// Data Reception: The backend sets the headers for the incoming stream.
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	// Direct Stream to Client: The backend pipes the data directly to the user’s browser.
	io.Copy(w, resp.Body)
}

// --- Auth & Account Handlers ---

func (a *App) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="red">Please enter your email address.</span>`)
		return
	}
	log.Printf("Password reset requested for: %s", email)
	link, err := a.auth.PasswordResetLink(r.Context(), email)
	if err != nil {
		log.Printf("Error generating reset link: %v", err)
	} else {
		log.Printf("[EMAIL SIMULATION] To: %s | Subject: Password Reset | Link: %s", email, link)
	}

	// ALWAYS show the same neutral success message
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<div class="pa3 bg-washed-green br2">
			<p class="dark-green b mb1">Check your email!</p>
			<p class="f6">If an account exists with that email, we've sent a password reset link.</p>
			<p class="f7 gray i">This window will close in 5 seconds...</p>
		</div>
	`)
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Identify user
	user := a.getAuthenticatedUserFromCookie(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="red">Error: Session expired.</span>`)
		return
	}

	// 2. Validate password
	newPassword := r.FormValue("newPassword")
	if len(newPassword) < 6 {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="red">Password must be at least 6 characters.</span>`)
		return
	}

	// 3. Update password in Firebase
	// This action revokes all active session tokens on the Firebase side
	log.Printf("Changing password for user: %s", user.UID)
	_, err := a.auth.UpdateUser(r.Context(), user.UID, (&auth.UserToUpdate{}).Password(newPassword))
	if err != nil {
		log.Printf("Error updating password: %v", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="red">Failed to update password.</span>`)
		return
	}

	// 4. LOGOUT: Clear the local __session cookie
	// We do this so the browser doesn't try to use an invalidated cookie
	http.SetCookie(w, &http.Cookie{Name: "__session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})

	// 5. Return the HTML message + Redirect Script
	// This will be injected into #password-feedback via HTMX
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<div class="pa3 bg-washed-green br2 mt3">
			<p class="dark-green b mb1">Success!</p>
			<p class="f6 mb2">To log in again, use your new password.</p>
			<p class="f7 gray i">Redirecting to login in 5 seconds...</p>
		</div>
		<script>
			setTimeout(function() {
				window.location.href = "/login";
			}, 5000);
		</script>
	`)
}

func (a *App) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := a.getAuthenticatedUserFromCookie(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Printf("DELETING ACCOUNT: %s", user.UID)
	ctx := r.Context()

	// 1. Cancel Stripe Subscription if StripeID exists
	if user.StripeID != "" {
		log.Printf("Canceling Stripe subscriptions for Stripe customer: %s", user.StripeID)
		i := subscription.List(&stripe.SubscriptionListParams{Customer: stripe.String(user.StripeID), Status: stripe.String("active")})
		for i.Next() {
			subscription.Cancel(i.Subscription().ID, nil)
		}
	}

	// 2. Delete User Data from Firestore
	a.firestore.Collection("users").Doc(user.UID).Delete(ctx)

	// 3. Delete User from Firebase Auth
	err := a.auth.DeleteUser(ctx, user.UID)
	if err != nil {
		log.Printf("Failed to delete auth user: %v", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="red">Error deleting account. Please contact support.</span>`)
		return
	}

	// 4. LOGOUT: Clear the session cookie
	http.SetCookie(w, &http.Cookie{Name: "__session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})

	log.Printf("DELETED ACCOUNT:  %s, Email: %s", user.UID, user.Email)

	// 5. Return the Success Message + Redirect to Home
	// This will be injected into the modal via HTMX
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<div class="pa3 bg-washed-red br2 mt3">
			<p class="dark-red b mb1">Account Deleted</p>
			<p class="f6 mb2">Your subscription has been cancelled and your account has been deleted.</p>
			<p class="f7 gray i">Redirecting to home in 5 seconds...</p>
		</div>
		<script>
			setTimeout(function() {
				window.location.href = "/";
			}, 5000);
		</script>
	`)
}

func (a *App) handleContactSupport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := a.getAuthenticatedUserFromCookie(r)
	email := "anonymous"
	if user != nil {
		email = user.Email
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	subject := r.FormValue("subject")
	message := r.FormValue("message")
	log.Printf("SUPPORT TICKET | From: %s | Subject: %s | Message: %s", email, subject, message)
	fmt.Fprintf(w, "<span>Your message has been sent!</span>")
}

// --- Session Logic ---

func (a *App) getAuthenticatedUserFromCookie(r *http.Request) *AuthUser {
	cookie, err := r.Cookie("__session")
	if err != nil {
		return nil
	}

	// SDK Invocation: The helper calls the Firebase SDK to verify the cookie.
	token, err := a.auth.VerifySessionCookie(r.Context(), cookie.Value)
	if err != nil {
		log.Printf("Session verification failed: %v", err)
		return nil
	}

	userPlan, userName, stripeID := "basic", "", ""
	var registeredAt time.Time

	// Database Request: The helper initiates a Firestore lookup.
	dsnap, err := a.firestore.Collection("users").Doc(token.UID).Get(r.Context())
	if err == nil {
		data := dsnap.Data()
		userPlan, _ = data["plan"].(string)
		userName, _ = data["name"].(string)
		stripeID, _ = data["stripeID"].(string)
		registeredAt, _ = data["registeredAt"].(time.Time)
	}

	var nextRenewal time.Time
	if stripeID != "" {
		i := subscription.List(&stripe.SubscriptionListParams{
			Customer: stripe.String(stripeID),
			Status:   stripe.String("active"),
			Expand:   []*string{stripe.String("data.items")},
		})
		if i.Next() {
			s := i.Subscription()
			if len(s.Items.Data) > 0 {
				nextRenewal = time.Unix(s.Items.Data[0].CurrentPeriodEnd, 0)
			}
		}
	}

	// Return User Profile: The helper returns the full AuthUser struct.
	return &AuthUser{
		UID:          token.UID,
		Email:        token.Claims["email"].(string),
		Plan:         userPlan,
		Name:         userName,
		RegisteredAt: registeredAt,
		NextRenewal:  nextRenewal,
		StripeID:     stripeID,
	}
}

func (a *App) handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDToken string `json:"idToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Login decode error: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	cookie, err := a.auth.SessionCookie(r.Context(), req.IDToken, 24*5*time.Hour)
	if err != nil {
		log.Printf("Error creating session cookie: %v", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__session", Value: cookie, MaxAge: 60 * 60 * 24 * 5, HttpOnly: true, Path: "/"})
	w.WriteHeader(http.StatusOK)
}

func (a *App) handleSessionLogout(w http.ResponseWriter, r *http.Request) {
	log.Println("User logging out")
	http.SetCookie(w, &http.Cookie{Name: "__session", Value: "", MaxAge: -1, Path: "/"})
	w.WriteHeader(http.StatusOK)
}

func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUserFromCookie(r)
	if user != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"loggedIn":     true,
			"plan":         user.Plan,
			"email":        user.Email,
			"name":         user.Name,
			"registeredAt": user.RegisteredAt.Format("Jan 2, 2006"),
			"nextRenewal":  user.NextRenewal.Format("Jan 2, 2006"),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"loggedIn": false, "plan": "visitor"})
}

// --- Stripe Logic ---

func (a *App) handleCreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanName string `json:"planName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	priceParams := &stripe.PriceListParams{}
	priceParams.LookupKeys = []*string{stripe.String(req.PlanName)}
	i := price.List(priceParams)
	var targetPrice *stripe.Price
	if i.Next() {
		targetPrice = i.Price()
	}

	if targetPrice == nil {
		log.Printf("Could not find Stripe price for lookup key: %s", req.PlanName)
		http.Error(w, "Invalid plan", 400)
		return
	}

	log.Printf("Creating checkout session for plan: %s", req.PlanName)
	params := &stripe.CheckoutSessionParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems:  []*stripe.CheckoutSessionLineItemParams{{Price: stripe.String(targetPrice.ID), Quantity: stripe.Int64(1)}},
		SuccessURL: stripe.String(a.domain + "/dashboard?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(a.domain + "/"),
	}
	s, err := checkoutsession.New(params)
	if err != nil {
		log.Printf("Error creating Stripe session: %v", err)
		http.Error(w, "Internal error", 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"sessionId": s.ID})
}

func (a *App) handleCreateCustomerPortalSession(w http.ResponseWriter, r *http.Request) {
	user := a.getAuthenticatedUserFromCookie(r)
	if user == nil || user.StripeID == "" {
		http.Error(w, "No subscription found", 400)
		return
	}
	log.Printf("Creating portal session for customer: %s", user.StripeID)
	params := &stripe.BillingPortalSessionParams{Customer: stripe.String(user.StripeID), ReturnURL: stripe.String(a.domain + "/dashboard")}
	s, err := portalsession.New(params)
	if err != nil {
		log.Printf("Portal session error: %v", err)
		http.Error(w, "Internal error", 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"url": s.URL})
}

func (a *App) handleCheckoutSuccess(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.ServeFile(w, r, filepath.Join(getEnv("STATIC_ROOT", "public"), "dashboard", "index.html"))
		return
	}
	log.Printf("Checkout success, processing session: %s", sessionID)
	s, _ := checkoutsession.Get(sessionID, nil)
	userRecord, _ := a.auth.GetUserByEmail(r.Context(), s.CustomerDetails.Email)
	token, _ := a.auth.CustomToken(r.Context(), userRecord.UID)
	cookie, _ := a.auth.SessionCookie(r.Context(), token, 24*5*time.Hour)
	http.SetCookie(w, &http.Cookie{Name: "__session", Value: cookie, MaxAge: 60 * 60 * 24 * 5, HttpOnly: true, Path: "/"})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// --- Helpers ---

func isAuthorized(userPlan string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	hierarchy := map[string]int{"visitor": 0, "basic": 1, "pro": 2, "elite": 3}
	for _, r := range required {
		if hierarchy[userPlan] >= hierarchy[r] {
			return true
		}
	}
	return false
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func generateTempPassword() (string, error) {
	const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	res := make([]byte, 12)
	for i := range res {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(c))))
		res[i] = c[n.Int64()]
	}
	return string(res), nil
}
