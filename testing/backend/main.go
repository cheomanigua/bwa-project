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

	portalsession "github.com/stripe/stripe-go/v84/billingportal/session"
	checkoutsession "github.com/stripe/stripe-go/v84/checkout/session"

	"github.com/stripe/stripe-go/v84/price"
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
	StripeSecretKey     = getEnv("STRIPE_SECRET_KEY", "sk_test_...")
	StripeWebhookSecret = getEnv("STRIPE_WEBHOOK_SECRET", "whsec_...")
	ResetEmailSender    = getEnv("RESET_EMAIL_SENDER", "noreply@yourdomain.com")
	Domain              = getEnv("DOMAIN", "http://localhost:5000")
)

// --- Constants for Lookup Keys ---
// These MUST match the "Lookup key" field you set in the Stripe Dashboard for each Price.
const (
	PlanLookupBasic = "basic_plan"
	PlanLookupPro   = "pro_plan"
	PlanLookupElite = "elite_plan"
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

// --- Utility Functions ---

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

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

func sendPasswordSetupEmail(email, link string) error {
	log.Printf("SIMULATING SENDGRID: To %s, Setup Link: %s", email, link)
	return nil
}

func generateSignedURL(objectName string) (string, error) {
	isEmulator := os.Getenv("GCS_EMULATOR_HOST") != ""
	if !isEmulator {
		opts := &storage.SignedURLOptions{
			Method:         "GET",
			Expires:        time.Now().Add(30 * time.Second),
			Scheme:         storage.SigningSchemeV4,
			GoogleAccessID: GCSAccessID,
		}
		return gcsClient.Bucket(GCSBucket).SignedURL(objectName, opts)
	}

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

// --- Permission Helpers ---

func hasPermission(userPlan, required string) bool {
	hierarchy := map[string]int{"visitor": 0, "basic": 1, "pro": 2, "elite": 3}
	return hierarchy[userPlan] >= hierarchy[required]
}

// --- HTTP Handlers ---

func handleContentGuard(w http.ResponseWriter, r *http.Request) {
	// 1. Authorization Logic
	user := getAuthenticatedUserFromCookie(r)
	userPlan := "visitor"
	if user != nil {
		userPlan = user.Plan
	}

	// Prepare the path for the permission check (aligning with contentGuard map)
	requestPath := r.URL.Path
	permPath := strings.TrimSuffix(requestPath, "/")
	permPath = strings.TrimSuffix(permPath, "/index.html")
	permPath = strings.TrimSuffix(permPath, "/index")

	// Check if the user is authorized
	if !contentGuard.IsAuthorized(permPath, userPlan) {
		log.Printf("Unauthorized access attempt: %s by plan %s", permPath, userPlan)

		// Set headers for HTML error response
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)

		// HTML message matching your attached example
		fmt.Fprintf(w, `
			<!DOCTYPE html>
			<html><head><title>Access Denied</title></head>
			<body>
				<h1>Access Denied</h1>
				<p>You need a higher plan to view this content.</p>
				<a href="posts">Go back to Posts</a>
			</body>
			</html>
		`)
		return
	}

	// 2. Object Path Construction
	objectPath := strings.TrimPrefix(requestPath, "/")
	if !strings.Contains(path.Base(objectPath), ".") {
		objectPath = path.Join(objectPath, "index.html")
	}

	// 3. Construct the Emulator API URL (Direct Mode)
	encodedObject := url.PathEscape(objectPath)
	emulatorURL := fmt.Sprintf("http://gcs-emulator:9000/storage/v1/b/%s/o/%s?alt=media",
		GCSBucket,
		encodedObject,
	)

	log.Printf("User authorized. Streaming object: %s", objectPath)

	// 4. Fetch the file via HTTP GET (Direct Streaming / Version 1)
	resp, err := http.Get(emulatorURL)
	if err != nil {
		log.Printf("Network error reaching GCS emulator: %v", err)
		http.Error(w, "Storage service unreachable", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Emulator returned error %d for: %s", resp.StatusCode, objectPath)
		http.Error(w, "Content not found", http.StatusNotFound)
		return
	}

	// 5. Set Response Headers
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/html" // Default for your blog posts
	}
	w.Header().Set("Content-Type", contentType)

	// Prevent caching to ensure auth is re-checked on every visit
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")

	// 6. Stream the content to the client
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error while streaming file: %v", err)
	}
}

// handleCreateCheckoutSession resolves the human-readable plan name to a Stripe Price ID via Lookup Keys.
func handleCreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PlanName string `json:"planName"` // Frontend sends "basic_plan", "pro_plan", etc.
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 1. Resolve Lookup Key to actual Price ID
	priceParams := &stripe.PriceListParams{}
	priceParams.LookupKeys = []*string{stripe.String(req.PlanName)}
	i := price.List(priceParams)

	var targetPrice *stripe.Price
	for i.Next() {
		targetPrice = i.Price()
	}

	if targetPrice == nil {
		log.Printf("Could not find Price for Lookup Key: %s", req.PlanName)
		http.Error(w, "Invalid plan selected", http.StatusBadRequest)
		return
	}

	// 2. Create Checkout Session using the retrieved ID
	params := &stripe.CheckoutSessionParams{
		Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(targetPrice.ID),
				Quantity: stripe.Int64(1),
			},
		},
		BillingAddressCollection: stripe.String(string(stripe.CheckoutSessionBillingAddressCollectionRequired)),
		SuccessURL:               stripe.String(Domain + "/dashboard?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:                stripe.String(Domain + "/"),
	}

	s, err := checkoutsession.New(params)
	if err != nil {
		log.Printf("Checkout creation failed: %v", err)
		http.Error(w, "Could not initiate checkout.", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"sessionId": s.ID})
}

// handleStripeWebhook updates the database by expanding subscription data to see the Lookup Key.
func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	event, err := webhook.ConstructEventWithOptions(
		payload,
		r.Header.Get("Stripe-Signature"),
		StripeWebhookSecret,
		webhook.ConstructEventOptions{
			IgnoreAPIVersionMismatch: true,
		},
	)
	if err != nil {
		log.Printf("Webhook signature verification failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

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
		} else {
			var sub stripe.Subscription
			json.Unmarshal(event.Data.Raw, &sub)
			subID = sub.ID
			customerID = sub.Customer.ID
		}

		// 1. Fetch Subscription and EXPAND the Price object to see the Lookup Key
		subParams := &stripe.SubscriptionParams{}
		subParams.AddExpand("items.data.price")
		fullSub, err := subscription.Get(subID, subParams)
		if err != nil {
			log.Printf("Error retrieving/expanding subscription: %v", err)
			w.WriteHeader(http.StatusOK)
			return
		}

		// 2. Identify Plan Level from the Lookup Key
		lookupKey := fullSub.Items.Data[0].Price.LookupKey
		regPlan := "basic"
		switch lookupKey {
		case PlanLookupPro:
			regPlan = "pro"
		case PlanLookupElite:
			regPlan = "elite"
		}

		// 3. Sync to Firebase/Firestore
		var uid string
		if event.Type == "checkout.session.completed" {
			userRecord, err := authClient.GetUserByEmail(ctx, customerEmail)
			if err != nil {
				tempPass, _ := generateTempPassword()
				newUser, _ := authClient.CreateUser(ctx, (&auth.UserToCreate{}).
					Email(customerEmail).Password(tempPass).DisplayName(customerName).EmailVerified(true))
				uid = newUser.UID
				link, _ := authClient.PasswordResetLink(ctx, customerEmail)
				sendPasswordSetupEmail(customerEmail, link)
			} else {
				uid = userRecord.UID
			}
		} else {
			iter := firestoreClient.Collection("users").Where("stripeID", "==", customerID).Limit(1).Documents(ctx)
			dsnap, err := iter.Next()
			if err == nil {
				uid = dsnap.Ref.ID
			}
		}

		// 4. Update Firestore with conditional logic to prevent overwriting Name with empty strings
		if uid != "" {
			updateData := map[string]any{
				"plan":     regPlan,
				"stripeID": customerID,
			}

			// Only add name/email to the update if they were actually in the webhook payload
			if customerName != "" {
				updateData["name"] = customerName
			}
			if customerEmail != "" {
				updateData["email"] = customerEmail
			}

			// Add registration date only if it's the first time (checkout.session.completed)
			if event.Type == "checkout.session.completed" {
				updateData["registeredAt"] = time.Now()
			}

			// Use MergeAll to ensure we don't delete existing fields like 'registeredAt' on updates
			_, err := firestoreClient.Collection("users").Doc(uid).Set(ctx, updateData, firestore.MergeAll)
			if err != nil {
				log.Printf("Firestore update failed for user %s: %v", uid, err)
			} else {
				log.Printf("Successfully updated user %s (Event: %s) to plan: %s", uid, event.Type, regPlan)
			}
		}

	}

	w.WriteHeader(http.StatusOK)
}

func handleCreateCustomerPortalSession(w http.ResponseWriter, r *http.Request) {
	user := getAuthenticatedUserFromCookie(r)
	if user == nil || user.StripeID == "" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(user.StripeID),
		ReturnURL: stripe.String(Domain + "/dashboard"),
	}
	s, err := portalsession.New(params)
	if err != nil {
		http.Error(w, "Portal error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"url": s.URL})
}

func handleCheckoutSuccess(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.ServeFile(w, r, filepath.Join(StaticRoot, "dashboard", "index.html"))
		return
	}

	s, err := checkoutsession.Get(sessionID, nil)
	if err != nil || s.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid {
		http.Error(w, "Verification failed", http.StatusBadRequest)
		return
	}

	userRecord, _ := authClient.GetUserByEmail(r.Context(), s.CustomerDetails.Email)
	customToken, _ := authClient.CustomToken(r.Context(), userRecord.UID)
	cookie, _ := authClient.SessionCookie(r.Context(), customToken, 24*5*time.Hour)

	http.SetCookie(w, &http.Cookie{
		Name: "__session", Value: cookie, MaxAge: 60 * 60 * 24 * 5, HttpOnly: true, Path: "/",
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getAuthenticatedUserFromCookie(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 1. Cancel Stripe Subscription if StripeID exists
	if user.StripeID != "" {
		iter := subscription.List(&stripe.SubscriptionListParams{
			Customer: stripe.String(user.StripeID),
			Status:   stripe.String("active"),
		})
		for iter.Next() {
			subscription.Cancel(iter.Subscription().ID, nil)
		}
	}

	// 2. Delete User Data from Firestore
	firestoreClient.Collection("users").Doc(user.UID).Delete(r.Context())

	// 3. Delete User from Firebase Auth
	err := authClient.DeleteUser(r.Context(), user.UID)
	if err != nil {
		log.Printf("Failed to delete auth user: %v", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="red">Error deleting account. Please contact support.</span>`)
		return
	}

	// 4. LOGOUT: Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "__session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

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

func handleResetPassword(w http.ResponseWriter, r *http.Request) {
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

	ctx := r.Context()

	// Always attempt to send — but ignore errors related to user not found
	link, err := authClient.PasswordResetLink(ctx, email)
	if err != nil {
		// Log the error for debugging, but don't expose it to the user
		log.Printf("Password reset link generation failed for %s: %v", email, err)
		// Intentionally fall through to success message
	} else {
		log.Printf("Password reset link generated for: %s → %s", email, link)
		sendPasswordSetupEmail(email, link) // Simulated in dev, real in prod
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

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Identify user
	user := getAuthenticatedUserFromCookie(r)
	if user == nil {
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
	params := (&auth.UserToUpdate{}).Password(newPassword)
	_, err := authClient.UpdateUser(r.Context(), user.UID, params)
	if err != nil {
		log.Printf("Password update error: %v", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="red">Failed to update password.</span>`)
		return
	}

	// 4. LOGOUT: Clear the local __session cookie
	// We do this so the browser doesn't try to use an invalidated cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "__session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Tells browser to delete immediately
		HttpOnly: true,
	})

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

func handleContactSupport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getAuthenticatedUserFromCookie(r)
	if user == nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="red">Error: Session expired.</span>`)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	subject := r.FormValue("subject")
	message := r.FormValue("message")

	// SIMULATION: In production, you would use SendGrid or an email service here.
	log.Printf("SUPPORT TICKET RECEIVED:\nFrom: %s (%s)\nSubject: %s\nMessage: %s",
		user.Name, user.Email, subject, message)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<span class="dark-green">Message sent successfully! Our team will contact you.</span>`)
}

func handleSessionLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "__session", Value: "", MaxAge: -1, Path: "/"})
	w.WriteHeader(http.StatusOK)
}

func handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDToken string `json:"idToken"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	cookie, _ := authClient.SessionCookie(r.Context(), req.IDToken, 24*5*time.Hour)
	http.SetCookie(w, &http.Cookie{Name: "__session", Value: cookie, MaxAge: 60 * 60 * 24 * 5, HttpOnly: true, Path: "/"})
	w.WriteHeader(http.StatusOK)
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	user := getAuthenticatedUserFromCookie(r)
	if user != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"loggedIn": true, "plan": user.Plan, "email": user.Email, "name": user.Name,
			"registeredAt": user.RegisteredAt.Format("Jan 2, 2006"),
			"nextRenewal":  user.NextRenewal.Format("Jan 2, 2006"),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"loggedIn": false, "plan": "visitor"})
}

func getAuthenticatedUserFromCookie(r *http.Request) *AuthUser {
	cookie, err := r.Cookie("__session")
	if err != nil {
		return nil
	}

	token, err := authClient.VerifySessionCookie(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}

	userPlan, userName, stripeID := "basic", "", ""
	var registeredAt time.Time

	dsnap, err := firestoreClient.Collection("users").Doc(token.UID).Get(r.Context())
	if err == nil {
		data := dsnap.Data()
		userPlan, _ = data["plan"].(string)
		userName, _ = data["name"].(string)
		stripeID, _ = data["stripeID"].(string)
		registeredAt, _ = data["registeredAt"].(time.Time)
	}

	var nextRenewal time.Time
	if stripeID != "" {
		i := subscription.List(&stripe.SubscriptionListParams{Customer: stripe.String(stripeID), Status: stripe.String("active"), Expand: []*string{stripe.String("data.items")}})
		if i.Next() {
			s := i.Subscription()
			if len(s.Items.Data) > 0 {
				nextRenewal = time.Unix(s.Items.Data[0].CurrentPeriodEnd, 0)
			}
		}
	}

	return &AuthUser{UID: token.UID, Email: token.Claims["email"].(string), Plan: userPlan, Name: userName, RegisteredAt: registeredAt, NextRenewal: nextRenewal, StripeID: stripeID}
}

func main() {
	ctx := context.Background()
	app, _ := firebase.NewApp(ctx, &firebase.Config{ProjectID: "my-test-project"})
	authClient, _ = app.Auth(ctx)
	firestoreClient, _ = app.Firestore(ctx)

	gcsOpts := []option.ClientOption{}
	if host := os.Getenv("GCS_EMULATOR_HOST"); host != "" {
		gcsOpts = append(gcsOpts, option.WithEndpoint("http://"+host), option.WithoutAuthentication())
	}
	gcsClient, _ = storage.NewClient(ctx, gcsOpts...)

	stripe.Key = StripeSecretKey
	contentGuard.Init()

	http.HandleFunc("/posts/", handleContentGuard)
	http.HandleFunc("/api/create-checkout-session", handleCreateCheckoutSession)
	http.HandleFunc("/api/stripe-webhook", handleStripeWebhook)
	http.HandleFunc("/dashboard/", handleCheckoutSuccess)
	http.HandleFunc("/api/delete-account", handleDeleteAccount)
	http.HandleFunc("/api/reset-password", handleResetPassword)
	http.HandleFunc("/api/change-password", handleChangePassword)
	http.HandleFunc("/api/contact-support", handleContactSupport)
	http.HandleFunc("/api/create-customer-portal-session", handleCreateCustomerPortalSession)
	http.HandleFunc("/api/sessionLogout", handleSessionLogout)
	http.HandleFunc("/api/sessionLogin", handleSessionLogin)
	http.HandleFunc("/api/session", handleSession)

	port := getEnv("PORT", "8081")
	log.Printf("Server starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
