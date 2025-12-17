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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/stripe/stripe-go/v84"

	// Use alias for Checkout Session to avoid conflict (FIXED)
	checkoutsession "github.com/stripe/stripe-go/v84/checkout/session"
	// Use alias for Billing Portal Session to avoid conflict (FIXED)
	portalsession "github.com/stripe/stripe-go/v84/billingportal/session"

	"github.com/stripe/stripe-go/v84/customer"
	"github.com/stripe/stripe-go/v84/paymentintent"
	"github.com/stripe/stripe-go/v84/price"
	"github.com/stripe/stripe-go/v84/setupintent"
	"github.com/stripe/stripe-go/v84/subscription"
	"github.com/stripe/stripe-go/v84/webhook"
	"google.golang.org/api/option"
)

// --- Configuration ---
var (
	StaticRoot          = getEnv("STATIC_ROOT", "public")
	ContentRoot         = getEnv("CONTENT_ROOT", "../frontend/content/posts")
	GCSBucket           = getEnv("GCS_BUCKET", "content")
	GCSAccessID         = getEnv("GCS_ACCESS_ID", "localhost")
	StripeSecretKey     = getEnv("STRIPE_SECRET_KEY", "sk_test_...")             // Load from environment
	StripeWebhookSecret = getEnv("STRIPE_WEBHOOK_SECRET", "whsec_...")           // Load from environment
	ResetEmailSender    = getEnv("RESET_EMAIL_SENDER", "noreply@yourdomain.com") // Sender for setup emails
)

// --- Domain Models ---

type UserRegistration struct {
	IDToken string `json:"idToken"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Plan    string `json:"plan"`
}

type AuthUser struct {
	UID          string
	Email        string
	Plan         string
	Name         string
	RegisteredAt time.Time
	NextRenewal  time.Time
	StripeID     string // Used for the Stripe Customer Portal
}

// --- Content Guard ---
type ContentGuard struct {
	permissions map[string][]string
	mu          sync.RWMutex
}

var contentGuard = ContentGuard{permissions: make(map[string][]string)}

var reFrontMatter = regexp.MustCompile(`(?s)^(?:---|\+\+\+)\s*[\r\n](.*?)[\r\n](?:---|\+\+\+)`)
var reCategories = regexp.MustCompile(`categories\s*[:=]\s*\[([^\]]+)]`)

func (cg *ContentGuard) Init() error {
	log.Println("Initializing Content Guard...")
	return filepath.Walk(ContentRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".md") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		fmMatch := reFrontMatter.FindSubmatch(content)
		if len(fmMatch) < 2 {
			return nil
		}

		catMatch := reCategories.FindStringSubmatch(string(fmMatch[1]))
		if len(catMatch) < 2 {
			return nil
		}

		rawPlans := strings.Split(catMatch[1], ",")
		var requiredPlans []string
		for _, p := range rawPlans {
			plan := strings.TrimSpace(strings.Trim(p, `'"`))
			if plan != "" {
				requiredPlans = append(requiredPlans, plan)
			}
		}

		if len(requiredPlans) > 0 {
			urlPath := strings.TrimPrefix(path, ContentRoot)
			urlPath = strings.TrimSuffix(urlPath, ".md")
			urlPath = strings.ReplaceAll(urlPath, string(filepath.Separator), "/")
			finalURLPath := "/posts" + urlPath
			finalURLPath = strings.TrimSuffix(finalURLPath, "/")
			finalURLPath = strings.TrimSuffix(finalURLPath, "/index")

			cg.mu.Lock()
			cg.permissions[finalURLPath] = requiredPlans
			cg.mu.Unlock()
			log.Printf("ContentGuard: %s requires plans: %v", finalURLPath, requiredPlans)
		}
		return nil
	})
}

func (cg *ContentGuard) IsAuthorized(path string, userPlan string) bool {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	requiredPlans, ok := cg.permissions[path]
	if !ok || len(requiredPlans) == 0 {
		return true
	}
	if userPlan == "visitor" {
		return false
	}
	return slices.Contains(requiredPlans, userPlan)
}

// --- Global Clients ---
var (
	authClient      *auth.Client
	firestoreClient *firestore.Client
	gcsClient       *storage.Client
)

func generateSignedURL(objectName string) (string, error) {
	isEmulator := os.Getenv("GCS_EMULATOR_HOST") != ""
	if !isEmulator {
		// Production path — keep your real signing logic
		opts := &storage.SignedURLOptions{
			Method:         "GET",
			Expires:        time.Now().Add(30 * time.Second),
			Scheme:         storage.SigningSchemeV4,
			GoogleAccessID: GCSAccessID,
		}
		return gcsClient.Bucket(GCSBucket).SignedURL(objectName, opts)
	}

	// EMULATOR MODE: fake-gcs-server IGNORES signature → just build URL manually
	base := "http://caddy-server:5000"
	path := fmt.Sprintf("/gcs-content/%s/%s", GCSBucket, objectName)
	fakeExpireLocalLinux := time.Now().Add(5 * time.Second).Unix()

	url := fmt.Sprintf("%s%s?X-Goog-Algorithm=GOOG4-RSA-SHA256"+
		"&X-Goog-Credential=%s%%2F%s%%2Fauto%%2Fstorage%%2Fgoog4_request"+
		"&X-Goog-Date=%s"+
		"&X-Goog-Expires=%d"+
		"&X-Goog-SignedHeaders=host",
		base, path,
		GCSAccessID,
		time.Now().Format("20060102"),
		time.Now().Format("20060102T150405Z"),
		int(fakeExpireLocalLinux-time.Now().Unix()),
	)

	log.Printf("Emulator mode: fake signed URL generated: %s", url)
	return url, nil
}

// --- Utility Functions ---

// generateTempPassword creates a strong, temporary password for Firebase Auth.
func generateTempPassword() (string, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234456789!@#$%^&*"
	const length = 16
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		result[i] = chars[num.Int64()]
	}
	return string(result), nil
}

// sendPasswordSetupEmail is a placeholder that MUST be replaced with a SendGrid integration.
func sendPasswordSetupEmail(email, link string) error {
	log.Printf("SIMULATING SENDGRID: To %s, Setup Link: %s", email, link)
	// *** TODO: REPLACE THIS WITH YOUR REAL SENDGRID IMPLEMENTATION ***
	return nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- HTTP Handlers ---

// handleContentGuard remains unchanged
func handleContentGuard(w http.ResponseWriter, r *http.Request) {
	user := getAuthenticatedUserFromCookie(r)
	userPlan := "visitor"
	if user != nil {
		userPlan = user.Plan
	}

	requestPath := r.URL.Path
	requestPath = strings.TrimSuffix(requestPath, "/")
	requestPath = strings.TrimSuffix(requestPath, "/index.html")
	requestPath = strings.TrimSuffix(requestPath, "/index")

	// 1. Authorization Check
	if !contentGuard.IsAuthorized(requestPath, userPlan) {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<!DOCTYPE html>
			<html><head><title>Access Denied</title></head>
			<body><h1>Access Denied</h1><p>You need a higher plan to view this content.</p></body>
			</html>
		`)
		return
	}

	// 2. Object Path Construction

	objectPath := strings.TrimPrefix(requestPath, "/")
	objectPath = filepath.Join(objectPath, "index.html")

	log.Printf("User authorized. Generating Signed URL for object: %s", objectPath)

	// 3. Generate Signed URL (Short-lived, server-side only)
	signedURL, err := generateSignedURL(objectPath)
	if err != nil {
		log.Printf("Failed to generate signed URL: %v", err)
		http.Error(w, "Failed to generate secure link", http.StatusInternalServerError)
		return
	}

	// 4. PROXY THE CONTENT from GCS
	resp, err := http.Get(signedURL)
	if err != nil {
		log.Printf("Failed to fetch content from GCS: %v", err)
		http.Error(w, "Content fetch error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("GCS responded with status: %d for object: %s", resp.StatusCode, objectPath)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// 5. Set Response Headers
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")

	// 6. Copy the Content to the Client
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying content to client: %v", err)
	}
}

// handleCreateCheckoutSession initiates the subscription process.
func handleCreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PriceID string `json:"priceId"` // e.g., 'price_1O3uB0...', passed from frontend selection
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.PriceID == "" {
		http.Error(w, "Missing priceId", http.StatusBadRequest)
		return
	}

	// 1. Verify Price Details
	_, err := price.Get(req.PriceID, nil)
	if err != nil {
		log.Printf("Invalid Stripe Price ID: %v", err)
		http.Error(w, "Invalid plan selected.", http.StatusBadRequest)
		return
	}

	// 2. Create Stripe Checkout Session
	params := &stripe.CheckoutSessionParams{
		// MODE: Correctly set to Subscription
		Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(req.PriceID),
				Quantity: stripe.Int64(1),
			},
		},

		// Explicitly expand the intents for the webhook to reliably get the PM ID
		Expand: []*string{
			stripe.String("payment_intent"),
			stripe.String("setup_intent"),
		},

		BillingAddressCollection: stripe.String(string(stripe.CheckoutSessionBillingAddressCollectionRequired)),

		SuccessURL: stripe.String("http://localhost:5000/dashboard?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String("http://localhost:5000/"),
	}

	// Use the aliased package name 'checkoutsession' (FIXED)
	s, err := checkoutsession.New(params)
	if err != nil {
		log.Printf("Failed to create Stripe Checkout Session: %v", err)
		http.Error(w, "Could not initiate checkout.", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"sessionId": s.ID})
}

// handleStripeWebhook securely creates the Firebase user and Firestore profile after successful payment.
// It also sets the successful payment method as the default for the customer in Stripe.
func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	// 1. Verify and Read Webhook Payload
	const MaxBodyBytes = int64(65536)
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusServiceUnavailable)
		return
	}

	signature := r.Header.Get("Stripe-Signature")
	options := webhook.ConstructEventOptions{
		IgnoreAPIVersionMismatch: true,
	}

	event, err := webhook.ConstructEventWithOptions(
		payload,
		signature,
		StripeWebhookSecret,
		options,
	)

	if err != nil {
		log.Printf("Error verifying webhook signature: %v", err)
		http.Error(w, "Invalid signature or payload", http.StatusBadRequest)
		return
	}

	// 2. Process Successful Payment Event
	if event.Type == "checkout.session.completed" {
		var checkoutSession stripe.CheckoutSession
		if err := json.Unmarshal(event.Data.Raw, &checkoutSession); err != nil {
			log.Printf("Error unmarshalling session: %v", err)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Robust Nil Checks
		if checkoutSession.Customer == nil || checkoutSession.Subscription == nil || checkoutSession.CustomerDetails == nil || checkoutSession.CustomerDetails.Email == "" {
			log.Printf("FATAL: Received checkout.session.completed event missing critical data.")
			w.WriteHeader(http.StatusOK)
			return
		}

		stripeCustomerID := checkoutSession.Customer.ID
		subID := checkoutSession.Subscription.ID

		// Safely extract Intent IDs
		var paymentIntentID string
		if checkoutSession.PaymentIntent != nil {
			paymentIntentID = checkoutSession.PaymentIntent.ID
		}
		var setupIntentID string
		if checkoutSession.SetupIntent != nil {
			setupIntentID = checkoutSession.SetupIntent.ID
		}

		ctx := r.Context()

		// A. Get Plan Details (Uses subscription package)
		subParams := &stripe.SubscriptionParams{}
		// Expand Price's Product to get the name if Nickname is missing
		subParams.AddExpand("items.data.price.product")

		sub, err := subscription.Get(subID, subParams)
		if err != nil {
			log.Printf("Error fetching subscription %s: %v", subID, err)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Defensive check
		if len(sub.Items.Data) == 0 || sub.Items.Data[0].Price == nil {
			log.Printf("FATAL: Subscription %s missing price data.", subID)
			w.WriteHeader(http.StatusOK)
			return
		}

		price := sub.Items.Data[0].Price

		// Get plan name (Nickname -> Product Name -> Price ID)
		regPlan := price.Nickname
		if regPlan == "" && price.Product != nil {
			regPlan = price.Product.Name
		}
		if regPlan == "" {
			regPlan = price.ID
			log.Printf("WARNING: Using Price ID %s as plan name.", regPlan)
		}

		// Plan Normalization for Content Guard
		regPlan = strings.ToLower(regPlan)
		regPlan = strings.TrimSuffix(regPlan, " membership")
		regPlan = strings.TrimSpace(regPlan)

		regEmail := checkoutSession.CustomerDetails.Email
		regName := checkoutSession.CustomerDetails.Name

		log.Printf("Checkout session completed for Email: %s, Plan: %s, Customer ID: %s", regEmail, regPlan, stripeCustomerID)

		// B. Set Default Payment Method
		pmID := ""

		// 1. Try to get PM ID from Payment Intent
		if paymentIntentID != "" {
			pi, err := paymentintent.Get(paymentIntentID, nil)
			if err == nil && pi.PaymentMethod != nil {
				pmID = pi.PaymentMethod.ID
			}
			// 2. Try to get PM ID from Setup Intent
		} else if setupIntentID != "" {
			si, err := setupintent.Get(setupIntentID, nil)
			if err == nil && si.PaymentMethod != nil {
				pmID = si.PaymentMethod.ID
			}
		}

		// 3. Fallback to Subscription's Default PM
		if pmID == "" && sub.DefaultPaymentMethod != nil {
			pmID = sub.DefaultPaymentMethod.ID
			log.Printf("Fallback: Retrieved PM ID %s directly from Subscription object.", pmID)
		}

		if pmID != "" {
			log.Printf("Attempting to set default payment method %s for customer %s", pmID, stripeCustomerID)

			// FIX: Correctly use *stripe.CustomerParams for the customer.Update call
			// FIX: Use *stripe.CustomerInvoiceSettingsParams for the nested type (FINAL FIX)
			customerParams := &stripe.CustomerParams{
				InvoiceSettings: &stripe.CustomerInvoiceSettingsParams{
					DefaultPaymentMethod: stripe.String(pmID),
				},
			}

			_, err = customer.Update(stripeCustomerID, customerParams)
			if err != nil {
				log.Printf("Failed to set default payment method for customer %s: %v", stripeCustomerID, err)
			} else {
				log.Printf("Successfully set default payment method for customer %s.", stripeCustomerID)
			}
		}

		// C. Create the Firebase User & Firestore Profile

		userRecord, err := authClient.GetUserByEmail(ctx, regEmail)
		var firebaseUID string
		var isNewUser bool = false

		if err != nil {
			// User does not exist, create them
			tempPass, err := generateTempPassword()
			if err != nil {
				log.Printf("Failed to generate temp password: %v", err)
				w.WriteHeader(http.StatusOK)
				return
			}

			params := (&auth.UserToCreate{}).
				Email(regEmail).
				Password(tempPass).
				DisplayName(regName).
				EmailVerified(true)

			newUserRecord, createErr := authClient.CreateUser(ctx, params)
			if createErr != nil {
				log.Printf("Failed to create Firebase user for %s: %v", regEmail, createErr)
				w.WriteHeader(http.StatusOK)
				return
			}
			firebaseUID = newUserRecord.UID
			isNewUser = true
			log.Printf("Created new Firebase user with UID: %s", firebaseUID)

		} else {
			// User exists
			firebaseUID = userRecord.UID
			log.Printf("Found existing Firebase user with UID: %s. Updating profile.", firebaseUID)
		}

		// D. Create/Update FINAL, PERMANENT Firestore profile
		finalProfile := map[string]any{
			"plan":         regPlan,
			"stripeID":     stripeCustomerID, // Save the Stripe ID for the customer portal
			"name":         regName,
			"email":        regEmail,
			"registeredAt": firestore.ServerTimestamp,
		}

		_, err = firestoreClient.Collection("users").Doc(firebaseUID).Set(ctx, finalProfile, firestore.MergeAll)
		if err != nil {
			log.Printf("Failed to write Firestore profile for UID %s: %v", firebaseUID, err)
		}

		// E. Generate and Send Password Setup Link (Only for newly created users)
		if isNewUser {
			resetLink, err := authClient.PasswordResetLink(ctx, regEmail)
			if err != nil {
				log.Printf("Failed to generate password reset link: %v", err)
			} else {
				if err := sendPasswordSetupEmail(regEmail, resetLink); err != nil {
					log.Printf("Failed to send setup email: %v", err)
				}
			}
		}
	}

	// 3. Handle Other Events (Subscription changes)
	if event.Type == "customer.subscription.deleted" || event.Type == "customer.subscription.updated" {
		log.Printf("Subscription event received: %s. Implement logic to update user plan.", event.Type)
	}

	// Acknowledge the webhook successfully
	w.WriteHeader(http.StatusOK)
}

// handleCreateCustomerPortalSession securely generates a URL for the Stripe Customer Portal.
func handleCreateCustomerPortalSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Authenticate user and get their profile data (including StripeID)
	user := getAuthenticatedUserFromCookie(r)
	if user == nil || user.StripeID == "" {
		log.Printf("Unauthorized or missing Stripe ID for portal request.")
		http.Error(w, "Unauthorized or no active subscription found.", http.StatusForbidden)
		return
	}

	// 2. Create the Billing Portal Session
	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(user.StripeID),
		ReturnURL: stripe.String("http://localhost:5000/dashboard"), // Redirect back to the dashboard when done
	}

	// Use the aliased package name 'portalsession' (FIXED)
	s, err := portalsession.New(params)
	if err != nil {
		log.Printf("Failed to create Stripe Billing Portal session for customer %s: %v", user.StripeID, err)
		http.Error(w, "Could not create customer portal session.", http.StatusInternalServerError)
		return
	}

	// 3. Return the secure URL to the frontend
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"url": s.URL})
}

// handleCheckoutSuccess processes the redirect from Stripe's success URL.
func handleCheckoutSuccess(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")

	// If no session_id, just serve the dashboard page (or redirect to home if not logged in)
	if sessionID == "" {
		http.ServeFile(w, r, filepath.Join(StaticRoot, "dashboard", "index.html"))
		return
	}

	// 1. Retrieve the Checkout Session
	// Use the aliased package name 'checkoutsession' and its Get method (FIXED)
	s, err := checkoutsession.Get(sessionID, nil)
	if err != nil {
		log.Printf("Error fetching Stripe session %s: %v", sessionID, err)
		http.Error(w, "Could not verify payment session.", http.StatusInternalServerError)
		return
	}

	// 2. Check if the session was successful and customer email is present
	if s.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid || s.CustomerDetails.Email == "" {
		log.Printf("Session %s not paid or missing email. Status: %s", sessionID, s.PaymentStatus)
		http.Error(w, "Payment not confirmed or session incomplete.", http.StatusBadRequest)
		return
	}

	regEmail := s.CustomerDetails.Email

	// 3. Find the Firebase User created by the Webhook
	userRecord, err := authClient.GetUserByEmail(r.Context(), regEmail)
	if err != nil {
		log.Printf("Error finding Firebase user for %s (Webhook delay?): %v", regEmail, err)
		http.Error(w, "User not yet provisioned. Try logging in shortly.", http.StatusAccepted)
		return
	}
	firebaseUID := userRecord.UID

	// 4. Create Custom Token and Session Cookie
	customToken, err := authClient.CustomToken(r.Context(), firebaseUID)
	if err != nil {
		log.Printf("Failed to create custom token for %s: %v", regEmail, err)
		http.Error(w, "Could not create login token.", http.StatusInternalServerError)
		return
	}

	cookie, err := authClient.SessionCookie(r.Context(), customToken, 24*5*time.Hour)
	if err != nil {
		log.Printf("Failed to create session cookie: %v", err)
		http.Error(w, "Failed to create session.", http.StatusInternalServerError)
		return
	}

	// 5. Set the Session Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "__session",
		Value:    cookie,
		MaxAge:   60 * 60 * 24 * 5,
		HttpOnly: true,
		Secure:   false, // Keep false for localhost
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	// 6. Redirect to the clean dashboard page (without the session_id query param)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleSessionLogin remains unchanged
func handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDToken string `json:"idToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	cookie, err := authClient.SessionCookie(r.Context(), req.IDToken, 24*5*time.Hour)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "__session",
		Value:    cookie,
		MaxAge:   60 * 60 * 24 * 5,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "logged in"})
}

// handleSessionLogout remains unchanged
func handleSessionLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "__session",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})
	w.WriteHeader(http.StatusOK)
}

// handleSession now includes the NextRenewal date in the API response
func handleSession(w http.ResponseWriter, r *http.Request) {
	user := getAuthenticatedUserFromCookie(r)

	if user != nil {
		registeredAtStr := ""
		if !user.RegisteredAt.IsZero() {
			registeredAtStr = user.RegisteredAt.Format("Jan 2, 2006")
		}

		// MISSING PIECE 1: Format the next renewal date
		nextRenewalStr := ""
		if !user.NextRenewal.IsZero() {
			nextRenewalStr = user.NextRenewal.Format("Jan 2, 2006")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"loggedIn":     true,
			"plan":         user.Plan,
			"email":        user.Email,
			"name":         user.Name,
			"registeredAt": registeredAtStr,
			"nextRenewal":  nextRenewalStr,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"loggedIn": false,
		"plan":     "visitor",
	})
}

// getAuthenticatedUserFromCookie now fetches the StripeID from Firestore.
// getAuthenticatedUserFromCookie now fetches the StripeID from Firestore and the renewal date from Stripe.
func getAuthenticatedUserFromCookie(r *http.Request) *AuthUser {
	// 1. Read the Firebase Session Cookie
	cookie, err := r.Cookie("__session")
	if err != nil {
		return nil
	}

	// 2. Verify the Session Cookie
	token, err := authClient.VerifySessionCookie(r.Context(), cookie.Value)
	if err != nil {
		log.Printf("Session cookie verification failed: %v", err)
		return nil
	}

	// 3. Extract Email from token claims
	userEmail, ok := token.Claims["email"].(string)
	if !ok {
		log.Printf("Warning: Email claim missing from Firebase token for UID: %s", token.UID)
		userEmail = ""
	}

	// 4. Fetch custom plan data and StripeID from Firestore
	userPlan := "basic"
	userName := ""
	var registeredAt time.Time
	var stripeID string

	if firestoreClient != nil {
		dsnap, err := firestoreClient.Collection("users").Doc(token.UID).Get(r.Context())
		if err == nil && dsnap.Exists() {
			data := dsnap.Data()
			if p, found := data["plan"].(string); found {
				userPlan = p
			}
			if n, found := data["name"].(string); found {
				userName = n
			}
			if ts, found := data["registeredAt"].(time.Time); found {
				registeredAt = ts
			}
			if s, found := data["stripeID"].(string); found {
				stripeID = s
			}
		} else if err != nil {
			log.Printf("Warning: Failed to fetch user profile for %s from Firestore: %v", token.UID, err)
		}
	}

	// 5. Fetch Active Subscription Details from Stripe
	var nextRenewal time.Time
	if stripeID != "" {
		subParams := &stripe.SubscriptionListParams{
			Customer: stripe.String(stripeID),
			Status:   stripe.String("active"),
			// FIX: EXPAND the 'items' array to access SubscriptionItem fields
			Expand: []*string{stripe.String("data.items")},
		}

		i := subscription.List(subParams)
		if i.Next() {
			activeSub := i.Subscription()

			// FIX: Access CurrentPeriodEnd from the first SubscriptionItem
			if activeSub.Items != nil && len(activeSub.Items.Data) > 0 {
				// The SubscriptionItem holds the CurrentPeriodEnd
				nextRenewal = time.Unix(activeSub.Items.Data[0].CurrentPeriodEnd, 0)
			} else {
				log.Printf("Warning: Subscription items not available or expanded for subscription %s", activeSub.ID)
			}
		} else if i.Err() != nil {
			log.Printf("Warning: Failed to list active subscriptions for customer %s: %v", stripeID, i.Err())
		}
	}

	// 6. Return the full AuthUser profile
	return &AuthUser{
		UID:          token.UID,
		Email:        userEmail,
		Plan:         userPlan,
		Name:         userName,
		RegisteredAt: registeredAt,
		NextRenewal:  nextRenewal,
		StripeID:     stripeID,
	}
}

// --- Main ---
func main() {
	ctx := context.Background()

	// Initialize Firebase and Auth/Firestore Clients
	app, err := firebase.NewApp(ctx, &firebase.Config{ProjectID: "my-test-project"})
	if err != nil {
		log.Fatal(err)
	}
	authClient, err = app.Auth(ctx)
	if err != nil {
		log.Fatal(err)
	}
	firestoreClient, err = app.Firestore(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize GCS Client (with emulator support)
	var gcsOpts []option.ClientOption
	if host := os.Getenv("GCS_EMULATOR_HOST"); host != "" {
		gcsOpts = append(gcsOpts,
			option.WithEndpoint("http://"+host),
			option.WithoutAuthentication(),
		)
	}
	gcsClient, err = storage.NewClient(ctx, gcsOpts...)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize Stripe Client
	stripe.Key = StripeSecretKey

	if err := contentGuard.Init(); err != nil {
		log.Fatal(err)
	}

	// --- Register Handlers ---
	http.HandleFunc("/posts/", handleContentGuard)

	// NEW: Handlers for Stripe Checkout flow
	http.HandleFunc("/api/create-checkout-session", handleCreateCheckoutSession)
	http.HandleFunc("/api/stripe-webhook", handleStripeWebhook)
	http.HandleFunc("/dashboard/", handleCheckoutSuccess)

	// NEW: Handler for Customer Portal
	http.HandleFunc("/api/create-customer-portal-session", handleCreateCustomerPortalSession)

	// Existing Session/Login Handlers
	http.HandleFunc("/api/sessionLogin", handleSessionLogin)
	http.HandleFunc("/api/sessionLogout", handleSessionLogout)
	http.HandleFunc("/api/session", handleSession)

	port := getEnv("PORT", "8081")
	log.Printf("Starting Go server on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
